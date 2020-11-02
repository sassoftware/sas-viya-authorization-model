// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// groupsApplyCmd represents the groupsApply command
var groupsApplyCmd = &cobra.Command{
	Use:   "apply [groups]",
	Short: "Apply Custom Groups",
	Long:  `Apply a SAS Viya Custom Groups structure [groups].`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		utils.ManageSession("create")
		var groups string
		var groupsFile []map[string]string
		groups = args[0]
		zap.S().Infow("Applying a SAS Viya Custom Groups structure", "groups", groups)
		groupsFile = utils.ReadCSVFile(groups, []string{"ParentGroupID", "GroupID", "GroupName", "UserID"})
		for _, item := range groupsFile {
			var parentID, groupID, groupName, userID string
			parentID = item["ParentGroupID"]
			groupID = item["GroupID"]
			groupName = item["GroupName"]
			userID = item["UserID"]
			if groupID != "" {
				if groupName == "" {
					groupName = groupID
				}
				utils.ManageGroup("create", groupID, groupName, parentID)
				if userID != "" {
					zap.S().Infow("Nesting user", "groupID", groupID, "userID", userID)
					call := utils.APICall{
						Verb: "PUT",
						Path: "/identities/groups/" + groupID + "/userMembers/" + userID,
					}
					utils.CallViya(call)
				}
			}
		}
		utils.ManageSession("destroy")
	},
}

func init() {
	groupsCmd.AddCommand(groupsApplyCmd)
}
