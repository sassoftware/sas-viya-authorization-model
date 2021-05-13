// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	fi "github.com/sassoftware/sas-viya-authorization-model/file"
	lo "github.com/sassoftware/sas-viya-authorization-model/log"
	pr "github.com/sassoftware/sas-viya-authorization-model/principal"
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
		new(lo.Log).New()
		membersOnly, _ := cmd.Flags().GetBool("members")
		if membersOnly {
			zap.S().Infow("Removing members from a SAS Viya Custom Groups structure", "groups", args[0])
		} else {
			zap.S().Infow("Removing a SAS Viya Custom Groups structure", "groups", args[0])
		}
		co := new(co.Connection)
		co.Connect()
		fi := new(fi.File)
		fi.Path = args[0]
		fi.Schema = []string{"ParentGroupID", "GroupID", "GroupName", "UserID"}
		fi.Type = "csv"
		fi.Read()
		groups := make(map[string]*pr.Principal)
		for _, item := range fi.Content.([][]string)[1:] {
			var group string = item[1]
			if group != "" {
				if _, exists := groups[group]; !exists {
					groups[group] = new(pr.Principal)
					groups[group].ID = group
					groups[group].Name = item[2]
					groups[group].Description = item[2]
					groups[group].Type = "group"
					groups[group].Connection = co
					groups[group].Validate()
				}
				if groups[group].Exists {
					if membersOnly {
						groups[group].GetMembers()
						groups[group].DeleteMembers()
					} else {
						groups[group].Delete()
					}
				}
			} else {
				zap.S().Errorw("The GroupID always needs to be provided")
			}
		}
		co.Disconnect()
	},
}

func init() {
	groupsCmd.AddCommand(groupsRemoveCmd)
	groupsRemoveCmd.Flags().BoolP("members", "m", false, "remove only the members of each group")
}
