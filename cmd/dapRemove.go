// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	"github.com/sassoftware/sas-viya-authorization-model/utils"
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
		utils.StartLogging()
		utils.ManageSession("create")
		var pattern, caslibs string
		var deleteGroups bool
		var patternFile, caslibsFile, join []map[string]string
		type Settings struct {
			Principal   string
			Permissions []string
		}
		backlog := make(map[string][]Settings)
		deleteGroups, _ = cmd.Flags().GetBool("delete-groups")
		pattern = args[0]
		caslibs = args[1]
		zap.S().Infow("Removing DAP from CASLIBs", "pattern", pattern, "caslibs", caslibs, "delete-groups", deleteGroups)
		patternFile = utils.ReadCSVFile(pattern, []string{"Pattern", "Principal", "GrantType", "Permissions"})
		caslibsFile = utils.ReadCSVFile(caslibs, []string{"CASLIB", "Pattern"})
		join = utils.JoinMaps(caslibsFile, patternFile, "Pattern", "inner")
		for _, item := range join {
			if item["GrantType"] == "caslib" {
				backlog[item["CASLIB"]] = append(backlog[item["CASLIB"]], Settings{
					item["Principal"],
					strings.Split(item["Permissions"], ","),
				})
			}
		}
		for caslib, settings := range backlog {
			if utils.ManageCASLIB("validate", caslib) {
				for _, setting := range settings {
					var group string = setting.Principal
					if deleteGroups {
						utils.ManageGroup("delete", group, group, "")
					}
				}
				acs := utils.AccessControl{
					CASLIB: caslib,
					Action: "removeAll",
				}
				utils.AssertCASPermissions(acs)
			} else {
				zap.S().Errorw("CASLIB does not exist", "caslib", caslib)
			}
		}
		utils.ManageSession("destroy")
	},
}

func init() {
	dapCmd.AddCommand(dapRemoveCmd)
	dapRemoveCmd.Flags().BoolP("delete-groups", "g", false, "delete listed custom groups")
}
