// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	ca "github.com/sassoftware/sas-viya-authorization-model/cas"
	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	fi "github.com/sassoftware/sas-viya-authorization-model/file"
	lo "github.com/sassoftware/sas-viya-authorization-model/log"
	pr "github.com/sassoftware/sas-viya-authorization-model/principal"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// dapRemoveCmd represents the dapRemove command
var dapRemoveCmd = &cobra.Command{
	Use:   "remove [pattern] [caslibs]",
	Short: "Remove DAP",
	Long:  `Remove a Data Access Pattern definition [pattern] from a list of CASLIBs [caslibs].`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		new(lo.Log).New()
		deleteGroups, _ := cmd.Flags().GetBool("delete-groups")
		zap.S().Infow("Removing DAP from CASLIBs", "pattern", args[0], "CASLIBs", args[1], "create-groups", deleteGroups)
		co := new(co.Connection)
		co.Connect()
		fp := new(fi.File)
		fp.Path = args[0]
		fp.Schema = []string{"Pattern", "Principal", "Permissions"}
		fp.Type = "csv"
		fp.Read()
		fc := new(fi.File)
		fc.Path = args[1]
		fc.Schema = []string{"CASLIB", "Type", "Path", "Pattern"}
		fc.Type = "csv"
		fc.Read()
		patterns := make(map[string][][]string)
		principals := make(map[string]*pr.Principal)
		for _, pattern := range fp.Content.([][]string)[1:] {
			patterns[pattern[0]] = append(patterns[pattern[0]], pattern[1:])
		}
		for _, caslib := range fc.Content.([][]string)[1:] {
			cas := new(ca.LIB)
			cas.Connection = co
			cas.Name = caslib[0]
			cas.Description = caslib[0]
			cas.Type = caslib[1]
			cas.Path = caslib[2]
			cas.Scope = "global"
			cas.Validate()
			if cas.Exists {
				if _, exists := patterns[caslib[3]]; exists {
					for _, pattern := range patterns[caslib[3]] {
						var principal string = pattern[0]
						if _, exists := principals[principal]; !exists {
							principals[principal] = new(pr.Principal)
							principals[principal].Name = principal
							principals[principal].Connection = co
							principals[principal].Type = "group"
							if principal == "authenticatedUsers" {
								principals[principal].ID = "*"
								principals[principal].Exists = true
							} else {
								principals[principal].ID = principal
								principals[principal].Validate()
							}
						}
						if deleteGroups && principals[principal].Exists {
							principals[principal].Delete()
						}
						var ac ca.AC = ca.AC{
							Type:        "grant",
							Principal:   principals[principal],
							Permissions: strings.Split(pattern[1], ","),
						}
						cas.ACL = append(cas.ACL, ac)
					}
					cas.Remove()
				} else {
					zap.S().Errorw("Pattern is not defined", "CASLIB", caslib[0], "pattern", caslib[3])
				}
			} else {
				zap.S().Errorw("CASLIB does not exist", "CASLIB", caslib[0])
			}
		}
		co.Disconnect()
	},
}

func init() {
	dapCmd.AddCommand(dapRemoveCmd)
	dapRemoveCmd.Flags().BoolP("delete-groups", "g", false, "delete listed custom groups")
}
