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

// dapApplyCmd represents the dapApply command
var dapApplyCmd = &cobra.Command{
	Use:   "apply [pattern] [caslibs]",
	Short: "Apply DAP",
	Long:  `Apply a Data Access Pattern definition [pattern] to a list of CASLIBs [caslibs].`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		new(lo.Log).New()
		createGroups, _ := cmd.Flags().GetBool("create-groups")
		zap.S().Infow("Applying DAP to CASLIBs", "pattern", args[0], "CASLIBs", args[1], "create-groups", createGroups)
		co := new(co.Connection)
		co.Connect()
		fp := new(fi.File)
		fp.Path = args[0]
		fp.Schema = []string{"Pattern", "Principal", "Permissions"}
		fp.Type = "csv"
		fp.Read()
		fc := new(fi.File)
		fc.Path = args[1]
		fc.Schema = []string{"CASLIB", "Pattern"}
		fc.Type = "csv"
		fc.Read()
		patterns := make(map[string][][]string)
		principals := make(map[string]*pr.Principal)
		for _, pattern := range fp.Content.([][]string)[1:] {
			patterns[pattern[0]] = append(patterns[pattern[0]], pattern[1:])
		}
		for _, caslib := range fc.Content.([][]string)[1:] {
			cas := new(ca.CASLIB)
			cas.Connection = co
			cas.Name = caslib[0]
			cas.Validate()
			if cas.Exists {
				if _, exists := patterns[caslib[1]]; exists {
					for _, pattern := range patterns[caslib[1]] {
						var principal string = pattern[0]
						if _, exists := principals[principal]; !exists {
							principals[principal] = new(pr.Principal)
							principals[principal].ID = principal
							principals[principal].Name = principal
							principals[principal].Type = "group"
							principals[principal].Connection = co
							principals[principal].Validate()
						}
						if createGroups && !principals[principal].Exists {
							principals[principal].Create()
						}
						var ac ca.AC = ca.AC{
							Type:        "grant",
							Principal:   principals[principal],
							Permissions: strings.Split(pattern[1], ","),
						}
						cas.ACL = append(cas.ACL, ac)
					}
					cas.Apply()
				} else {
					zap.S().Errorw("Pattern is not defined", "CASLIB", caslib[0], "pattern", caslib[1])
				}
			} else {
				zap.S().Errorw("CASLIB does not exist", "CASLIB", caslib[0])
			}
		}
		co.Disconnect()
	},
}

func init() {
	dapCmd.AddCommand(dapApplyCmd)
	dapApplyCmd.Flags().BoolP("create-groups", "g", false, "create missing custom groups")
}
