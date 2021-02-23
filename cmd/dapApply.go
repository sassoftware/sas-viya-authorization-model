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
		createCASLIBs, _ := cmd.Flags().GetBool("create-caslibs")
		zap.S().Infow("Applying DAP to CASLIBs", "pattern", args[0], "CASLIBs", args[1], "create-groups", createGroups, "create-caslibs", createCASLIBs)
		co := new(co.Connection)
		co.Connect()
		fp := new(fi.File)
		fp.Path = args[0]
		fp.Schema = []string{"Pattern", "Principal", "Permissions"}
		fp.Type = "csv"
		fp.Read()
		fc := new(fi.File)
		fc.Path = args[1]
		fc.Schema = []string{"CASLIB", "Description", "Type", "Path", "Pattern"}
		fc.Type = "csv"
		fc.Read()
		patterns := make(map[string][][]string)
		principals := make(map[string]*pr.Principal)
		caslibs := make(map[string]*ca.LIB)
		for _, pattern := range fp.Content.([][]string)[1:] {
			patterns[pattern[0]] = append(patterns[pattern[0]], pattern[1:])
		}
		for _, caslib := range fc.Content.([][]string)[1:] {
			if _, exists := caslibs[caslib[0]]; !exists {
				caslibs[caslib[0]] = new(ca.LIB)
				caslibs[caslib[0]].Connection = co
				caslibs[caslib[0]].Name = caslib[0]
				caslibs[caslib[0]].Description = caslib[1]
				caslibs[caslib[0]].Type = caslib[2]
				caslibs[caslib[0]].Path = caslib[3]
				caslibs[caslib[0]].Scope = "global"
				caslibs[caslib[0]].Validate()
			}
			if !caslibs[caslib[0]].Exists && createCASLIBs {
				caslibs[caslib[0]].Create()
				caslibs[caslib[0]].Validate()
			}
			if !caslibs[caslib[0]].Exists {
				zap.S().Errorw("CASLIB does not exist", "CASLIB", caslib[0])
			} else {
				if _, exists := patterns[caslib[4]]; exists {
					for _, pattern := range patterns[caslib[4]] {
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
						if createGroups && !principals[principal].Exists {
							principals[principal].Create()
						}
						var ac ca.AC = ca.AC{
							Type:        "grant",
							Principal:   principals[principal],
							Permissions: strings.Split(pattern[1], ","),
						}
						caslibs[caslib[0]].ACL = append(caslibs[caslib[0]].ACL, ac)
					}
					caslibs[caslib[0]].Apply()
				} else {
					zap.S().Errorw("Pattern is not defined", "CASLIB", caslib[0], "pattern", caslib[4])
				}
			}
		}
		co.Disconnect()
	},
}

func init() {
	dapCmd.AddCommand(dapApplyCmd)
	dapApplyCmd.Flags().BoolP("create-groups", "g", false, "create missing custom groups")
	dapApplyCmd.Flags().BoolP("create-caslibs", "c", false, "create missing CASLIBs")
}
