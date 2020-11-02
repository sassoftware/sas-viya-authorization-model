// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// ipapApplyCmd represents the ipapApply command
var ipapApplyCmd = &cobra.Command{
	Use:   "apply [pattern] [folders]",
	Short: "Apply IPAP",
	Long:  `Apply an Information Product Access Pattern definition [pattern] to a list of SAS Viya content folders [folders].`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		utils.ManageSession("create")
		var pattern, folders string
		var createGroups, createFolders bool
		var patternFile, foldersFile, backlog []map[string]string
		createGroups, _ = cmd.Flags().GetBool("create-groups")
		createFolders, _ = cmd.Flags().GetBool("create-folders")
		pattern = args[0]
		folders = args[1]
		zap.S().Infow("Applying IPAP to SAS Viya content folders", "pattern", pattern, "folders", folders, "create-groups", createGroups, "create-folders", createFolders)
		patternFile = utils.ReadCSVFile(pattern, []string{"Pattern", "Principal", "GrantType", "Permissions"})
		foldersFile = utils.ReadCSVFile(folders, []string{"Directory", "Pattern"})
		backlog = utils.JoinMaps(foldersFile, patternFile, "Pattern", "inner")
		for _, item := range backlog {
			var group, uri string
			group = item["Principal"]
			if createGroups {
				utils.ManageGroup("create", group, group, "")
			}
			if createFolders {
				uri = utils.ManageFolder("create", item["Directory"])
			} else {
				uri = utils.ManageFolder("validate", item["Directory"])
			}
			if uri != "" {
				rule := utils.AuthorizationRule{
					Principal:     group,
					PrincipalType: "group",
					Type:          "grant",
					Enabled:       "true",
					Permissions:   strings.Split(item["Permissions"], ","),
					Description:   "Automatically enabled by goViyaAuth",
				}
				if item["GrantType"] == "object" {
					rule.ObjectURI = uri + "/**"
				} else if item["GrantType"] == "conveyed" {
					rule.ContainerURI = uri
				}
				utils.AssertViyaPermissions(rule)
			} else {
				zap.S().Errorw("Folder does not exist and should not be created")
			}
		}
		utils.ManageSession("destroy")
	},
}

func init() {
	ipapCmd.AddCommand(ipapApplyCmd)
	ipapApplyCmd.Flags().BoolP("create-groups", "g", false, "create missing custom groups")
	ipapApplyCmd.Flags().BoolP("create-folders", "f", false, "create missing SAS Viya content folders")
}
