// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	fi "github.com/sassoftware/sas-viya-authorization-model/file"
	lo "github.com/sassoftware/sas-viya-authorization-model/log"
	pr "github.com/sassoftware/sas-viya-authorization-model/principal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// groupsSyncCmd represents the groupsSync command
var groupsSyncCmd = &cobra.Command{
	Use:   "sync [groups]",
	Short: "Sync Custom Groups (apply and/or remove automatically)",
	Long:  `Synchronize a SAS Viya Custom Groups structure [groups].`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		new(lo.Log).New()
		zap.S().Infow("Synchronizing a SAS Viya Custom Groups structure (applying and/or removing automatically)", "groups", args[0])
		co := new(co.Connection)
		co.Connect()
		fi := new(fi.File)
		fi.Path = args[0]
		fi.Schema = []string{"ParentGroupID", "GroupID", "GroupName", "UserID"}
		fi.Type = "csv"
		fi.Read()
		groupsTarget := make(map[string]*pr.Principal)
		usersTarget := make(map[string]*pr.Principal)
		groupsCurrent := make(map[string]*pr.Principal)
		usersCurrent := make(map[string]*pr.Principal)
		deleteGroups, _ := cmd.Flags().GetBool("delete-groups")
		for _, item := range fi.Content.([][]string)[1:] {
			var parent string = item[0]
			var group string = item[1]
			var member string = item[3]
			if group != "" {
				if _, exists := groupsTarget[group]; !exists {
					groupsTarget[group] = new(pr.Principal)
					groupsTarget[group].ID = group
					groupsTarget[group].Name = item[2]
					groupsTarget[group].Description = item[2]
					groupsTarget[group].Type = "group"
					groupsTarget[group].Connection = co
				}
				if parent != "" {
					if _, exists := groupsTarget[parent]; !exists {
						groupsTarget[parent] = new(pr.Principal)
						groupsTarget[parent].ID = parent
						groupsTarget[parent].Name = parent
						groupsTarget[parent].Type = "group"
						groupsTarget[parent].Connection = co
					}
					groupsTarget[group].Parents = append(groupsTarget[group].Parents, groupsTarget[parent])
					groupsTarget[parent].Members = append(groupsTarget[parent].Members, groupsTarget[group])
				}
				if member != "" {
					if _, exists := usersTarget[member]; !exists {
						usersTarget[member] = new(pr.Principal)
						usersTarget[member].ID = member
						usersTarget[member].Type = "user"
						usersTarget[member].Connection = co
					}
					usersTarget[member].Parents = append(usersTarget[member].Parents, groupsTarget[group])
					groupsTarget[group].Members = append(groupsTarget[group].Members, usersTarget[member])
				}
			} else {
				zap.S().Errorw("The GroupID always needs to be provided")
			}
		}
		resp, _ := co.Call("GET", "/identities/groups", "", "", [][]string{
			0: {
				"providerId",
				"local",
			},
			1: {
				"limit",
				viper.GetString("responselimit"),
			},
		}, nil)
		if resp.(map[string]interface{})["count"] == "0" {
			zap.S().Debugw("No custom groups exist")
			groupsCurrent = nil
		} else {
			for _, item := range resp.(map[string]interface{})["items"].([]interface{}) {
				group := item.(map[string]interface{})["id"].(string)
				if _, exists := groupsCurrent[group]; !exists {
					groupsCurrent[group] = new(pr.Principal)
					groupsCurrent[group].ID = group
					groupsCurrent[group].Name = item.(map[string]interface{})["name"].(string)
					groupsCurrent[group].Description = item.(map[string]interface{})["name"].(string)
					groupsCurrent[group].Type = "group"
					groupsCurrent[group].Exists = true
					groupsCurrent[group].Connection = co
				}
				resp2, _ := co.Call("GET", "/identities/groups/"+group+"/members", "", "", [][]string{
					0: {
						"limit",
						viper.GetString("responselimit"),
					},
				}, nil)
				if resp2.(map[string]interface{})["count"] == "0" {
					zap.S().Debugw("No members in group", "group", group)
					groupsCurrent[group].Members = nil
				} else {
					for _, item2 := range resp2.(map[string]interface{})["items"].([]interface{}) {
						if item2.(map[string]interface{})["type"].(string) == "group" {
							groupMember := item2.(map[string]interface{})["id"].(string)
							if _, exists := groupsCurrent[groupMember]; !exists {
								groupsCurrent[groupMember] = new(pr.Principal)
								groupsCurrent[groupMember].ID = groupMember
								groupsCurrent[groupMember].Name = item2.(map[string]interface{})["name"].(string)
								groupsCurrent[groupMember].Description = item2.(map[string]interface{})["name"].(string)
								groupsCurrent[groupMember].Type = "group"
								groupsCurrent[groupMember].Exists = true
								groupsCurrent[groupMember].Connection = co
							}
							groupsCurrent[groupMember].Parents = append(groupsCurrent[groupMember].Parents, groupsCurrent[group])
							groupsCurrent[group].Members = append(groupsCurrent[group].Members, groupsCurrent[groupMember])
						} else {
							userMember := item2.(map[string]interface{})["id"].(string)
							if _, exists := usersCurrent[userMember]; !exists {
								usersCurrent[userMember] = new(pr.Principal)
								usersCurrent[userMember].ID = userMember
								usersCurrent[userMember].Type = "user"
								usersCurrent[userMember].Exists = true
								usersCurrent[userMember].Connection = co
							}
							usersCurrent[userMember].Parents = append(usersCurrent[userMember].Parents, groupsCurrent[group])
							groupsCurrent[group].Members = append(groupsCurrent[group].Members, usersCurrent[userMember])
						}
					}
				}
			}
		}
		for _, group := range groupsCurrent {
			if _, exists := groupsTarget[group.ID]; !exists {
				if deleteGroups {
					group.Delete()
				} else {
					zap.S().Infow("The group no longer exists in the desired target state", "group", group.ID)
				}
			} else {
				for _, memberCurrent := range groupsCurrent[group.ID].Members {
					var found bool = false
					for _, memberTarget := range groupsTarget[group.ID].Members {
						if memberCurrent.ID == memberTarget.ID {
							found = true
						}
					}
					if !found {
						group.DeleteMember("user", memberCurrent.ID)
					}
				}
			}
		}
		for _, group := range groupsTarget {
			if _, exists := groupsCurrent[group.ID]; !exists {
				group.Create()
			} else {
				for _, memberTarget := range groupsTarget[group.ID].Members {
					var found bool = false
					for _, memberCurrent := range groupsCurrent[group.ID].Members {
						if memberCurrent.ID == memberTarget.ID {
							found = true
						}
					}
					if !found {
						memberTarget.Nest()
					}
				}
			}
		}
		co.Disconnect()
	},
}

func init() {
	groupsCmd.AddCommand(groupsSyncCmd)
	groupsSyncCmd.Flags().BoolP("delete-groups", "g", false, "delete superfluous custom groups")
}
