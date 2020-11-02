// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// matrixRemoveCmd represents the matrixRemove command
var matrixRemoveCmd = &cobra.Command{
	Use:   "remove [matrix]",
	Short: "Remove Matrix",
	Long:  `Remove a SAS Viya Platform Capability Matrix [matrix].`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		utils.ManageSession("create")
		var matrix string
		var deleteGroups bool
		var matrixFile []map[string]string
		deleteGroups, _ = cmd.Flags().GetBool("delete-groups")
		matrix = args[0]
		zap.S().Infow("Removing a SAS Viya Platform Capability Matrix", "matrix", matrix, "delete-groups", deleteGroups)
		matrixFile = utils.ReadCSVFile(matrix, []string{"URI", "Principal", "Permissions"})
		for _, item := range matrixFile {
			var group, uri string
			group = item["Principal"]
			uri = item["URI"]
			if deleteGroups {
				utils.ManageGroup("delete", group, group, "")
			}
			if uri != "" {
				rule := utils.AuthorizationRule{
					Principal:     group,
					PrincipalType: "group",
					Type:          "grant",
					Enabled:       "false",
					Permissions:   strings.Split(item["Permissions"], ","),
					Description:   "Automatically disabled by goViyaAuth",
					ObjectURI:     uri,
				}
				utils.AssertViyaPermissions(rule)
			}
		}
		utils.ManageSession("destroy")
	},
}

func init() {
	matrixCmd.AddCommand(matrixRemoveCmd)
	matrixRemoveCmd.Flags().BoolP("delete-groups", "g", false, "delete listed custom groups")
}
