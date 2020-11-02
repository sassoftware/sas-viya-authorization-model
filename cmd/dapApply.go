// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	"github.com/sassoftware/sas-viya-authorization-model/utils"
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
		utils.StartLogging()
		utils.ManageSession("create")
		var pattern, caslibs string
		var createGroups bool
		var patternFile, caslibsFile, join []map[string]string
		type Settings struct {
			Principal   string
			Permissions []string
		}
		backlog := make(map[string][]Settings)
		createGroups, _ = cmd.Flags().GetBool("create-groups")
		pattern = args[0]
		caslibs = args[1]
		zap.S().Infow("Applying DAP to CASLIBs", "pattern", pattern, "caslibs", caslibs, "create-groups", createGroups)
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
				acl := []utils.CASACL{}
				for _, setting := range settings {
					var group string = setting.Principal
					if createGroups {
						utils.ManageGroup("create", group, group, "")
					}
					for _, permission := range setting.Permissions {
						acl = append(acl, utils.CASACL{
							Identity:     group,
							IdentityType: "group",
							Type:         "grant",
							Permission:   permission,
						})
					}
				}
				acs := utils.AccessControl{
					CASLIB:      caslib,
					Description: "Automatically created by goViyaAuth",
					CASACL:      acl,
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
	dapCmd.AddCommand(dapApplyCmd)
	dapApplyCmd.Flags().BoolP("create-groups", "g", false, "create missing custom groups")
}
