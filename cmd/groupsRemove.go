// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// groupsRemoveCmd represents the groupsRemove command
var groupsRemoveCmd = &cobra.Command{
	Use:   "remove [groups]",
	Short: "Remove Custom Groups",
	Long:  `Remove a SAS Viya Custom Groups structure [groups].`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		utils.ManageSession("create")
		var groups string
		var groupsFile []map[string]string
		var membersOnly bool
		membersOnly, _ = cmd.Flags().GetBool("members")
		groups = args[0]
		groupsFile = utils.ReadCSVFile(groups, []string{"ParentGroupID", "GroupID", "GroupName", "UserID"})
		if membersOnly {
			zap.S().Infow("Removing members from a SAS Viya Custom Groups structure", "groups", groups)
		} else {
			zap.S().Infow("Removing a SAS Viya Custom Groups structure entirely", "groups", groups)
		}
		for _, item := range groupsFile {
			var groupID, groupName string
			groupID = item["GroupID"]
			groupName = item["GroupName"]
			if groupID != "" {
				if membersOnly {
					utils.ManageGroup("deleteMembers", groupID, groupName, "")
				} else {
					utils.ManageGroup("delete", groupID, groupName, "")
				}
			}
		}
		utils.ManageSession("destroy")
	},
}

func init() {
	groupsCmd.AddCommand(groupsRemoveCmd)
	groupsRemoveCmd.Flags().BoolP("members", "m", false, "remove only the members of each group")
}
