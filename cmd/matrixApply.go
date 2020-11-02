// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// matrixApplyCmd represents the matrixApply command
var matrixApplyCmd = &cobra.Command{
	Use:   "apply [matrix]",
	Short: "Apply Matrix",
	Long:  `Apply a SAS Viya Platform Capability Matrix [matrix].`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		utils.ManageSession("create")
		var matrix string
		var createGroups bool
		var matrixFile []map[string]string
		createGroups, _ = cmd.Flags().GetBool("create-groups")
		matrix = args[0]
		zap.S().Infow("Applying a SAS Viya Platform Capability Matrix", "matrix", matrix, "create-groups", createGroups)
		matrixFile = utils.ReadCSVFile(matrix, []string{"URI", "Principal", "Permissions"})
		for _, item := range matrixFile {
			var group, uri string
			group = item["Principal"]
			uri = item["URI"]
			if createGroups {
				utils.ManageGroup("create", group, group, "")
			}
			if uri != "" {
				rule := utils.AuthorizationRule{
					Principal:     group,
					PrincipalType: "group",
					Type:          "grant",
					Enabled:       "true",
					Permissions:   strings.Split(item["Permissions"], ","),
					Description:   "Automatically enabled by goViyaAuth",
					ObjectURI:     uri,
				}
				utils.AssertViyaPermissions(rule)
			}
		}
		utils.ManageSession("destroy")
	},
}

func init() {
	matrixCmd.AddCommand(matrixApplyCmd)
	matrixApplyCmd.Flags().BoolP("create-groups", "g", false, "create missing custom groups")
}
