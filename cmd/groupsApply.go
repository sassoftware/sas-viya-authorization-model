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

// groupsApplyCmd represents the groupsApply command
var groupsApplyCmd = &cobra.Command{
	Use:   "apply [groups]",
	Short: "Apply Custom Groups",
	Long:  `Apply a SAS Viya Custom Groups structure [groups].`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		new(lo.Log).New()
		zap.S().Infow("Applying a SAS Viya Custom Groups structure", "groups", args[0])
		co := new(co.Connection)
		co.Connect()
		fi := new(fi.File)
		fi.Path = args[0]
		fi.Schema = []string{"ParentGroupID", "GroupID", "GroupName", "UserID"}
		fi.Type = "csv"
		fi.Read()
		groups := make(map[string]*pr.Principal)
		users := make(map[string]*pr.Principal)
		for _, item := range fi.Content.([][]string)[1:] {
			var parent string = item[0]
			var group string = item[1]
			var member string = item[3]
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
				if parent != "" {
					if _, exists := groups[parent]; !exists {
						groups[parent] = new(pr.Principal)
						groups[parent].ID = parent
						groups[parent].Name = parent
						groups[parent].Type = "group"
						groups[parent].Connection = co
						groups[parent].Validate()
					}
					if groups[parent].Exists {
						groups[group].Parents = append(groups[group].Parents, groups[parent])
						groups[group].Nest()
					} else {
						zap.S().Errorw("The ParentGroupID does not exist")
					}
				}
				if !groups[group].Exists {
					groups[group].Create()
				}
				if member != "" {
					if _, exists := users[member]; !exists {
						users[member] = new(pr.Principal)
						users[member].ID = member
						users[member].Type = "user"
						users[member].Connection = co
					}
					users[member].Parents = append(users[member].Parents, groups[group])
					groups[group].Members = append(groups[group].Members, users[member])
					users[member].Nest()
				}
			} else {
				zap.S().Errorw("The GroupID always needs to be provided")
			}
		}
		co.Disconnect()
	},
}

func init() {
	groupsCmd.AddCommand(groupsApplyCmd)
}
