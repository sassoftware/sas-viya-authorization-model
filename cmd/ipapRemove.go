// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// ipapRemoveCmd represents the ipapRemove command
var ipapRemoveCmd = &cobra.Command{
	Use:   "remove [pattern] [folders]",
	Short: "Remove IPAP",
	Long:  `Remove an Information Product Access Pattern definition [pattern] from a list of SAS Viya content folders [folders].`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		utils.ManageSession("create")
		var pattern, folders string
		var deleteGroups, deleteFolders bool
		var patternFile, foldersFile, backlog, backlogReverse []map[string]string
		deleteGroups, _ = cmd.Flags().GetBool("delete-groups")
		deleteFolders, _ = cmd.Flags().GetBool("delete-folders")
		pattern = args[0]
		folders = args[1]
		zap.S().Infow("Removing IPAP from SAS Viya content folders", "pattern", pattern, "folders", folders, "delete-groups", deleteGroups, "delete-folders", deleteFolders)
		patternFile = utils.ReadCSVFile(pattern, []string{"Pattern", "Principal", "GrantType", "Permissions"})
		foldersFile = utils.ReadCSVFile(folders, []string{"Directory", "Pattern"})
		backlog = utils.JoinMaps(foldersFile, patternFile, "Pattern", "inner")
		backlogReverse = utils.ReverseMap(backlog)
		for _, item := range backlogReverse {
			var group, uri string
			group = item["Principal"]
			if deleteGroups {
				utils.ManageGroup("delete", group, group, "")
			}
			if deleteFolders {
				uri = utils.ManageFolder("delete", item["Directory"])
			} else {
				uri = utils.ManageFolder("validate", item["Directory"])
			}
			if uri != "" {
				rule := utils.AuthorizationRule{
					Principal:     group,
					PrincipalType: "group",
					Type:          "grant",
					Enabled:       "false",
					Permissions:   strings.Split(item["Permissions"], ","),
					Description:   "Automatically disabled by goViyaAuth",
				}
				if item["GrantType"] == "object" {
					rule.ObjectURI = uri + "/**"
				} else if item["GrantType"] == "conveyed" {
					rule.ContainerURI = uri
				}
				utils.AssertViyaPermissions(rule)
			}
		}
		utils.ManageSession("destroy")
	},
}

func init() {
	ipapCmd.AddCommand(ipapRemoveCmd)
	ipapRemoveCmd.Flags().BoolP("delete-groups", "g", false, "delete listed custom groups")
	ipapRemoveCmd.Flags().BoolP("delete-folders", "f", false, "delete listed SAS Viya content folders if empty")
}
