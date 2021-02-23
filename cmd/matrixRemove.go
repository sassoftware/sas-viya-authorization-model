// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	au "github.com/sassoftware/sas-viya-authorization-model/authorization"
	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	fi "github.com/sassoftware/sas-viya-authorization-model/file"
	lo "github.com/sassoftware/sas-viya-authorization-model/log"
	pr "github.com/sassoftware/sas-viya-authorization-model/principal"
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
		new(lo.Log).New()
		deleteGroups, _ := cmd.Flags().GetBool("delete-groups")
		zap.S().Infow("Removing a SAS Viya Platform Capability Matrix", "matrix", args[0], "delete-groups", deleteGroups)
		co := new(co.Connection)
		co.Connect()
		fi := new(fi.File)
		fi.Path = args[0]
		fi.Schema = []string{"URI", "Principal", "Permissions"}
		fi.Type = "csv"
		fi.Read()
		principals := make(map[string]*pr.Principal)
		for _, item := range fi.Content.([][]string)[1:] {
			zap.S().Infow("Removing SAS Viya Platform Capability", "item", item)
			var principal string = item[1]
			if _, exists := principals[principal]; !exists {
				principals[principal] = new(pr.Principal)
				principals[principal].ID = principal
				principals[principal].Name = principal
				principals[principal].Connection = co
				if principal == "authenticatedUsers" {
					principals[principal].Type = principal
					principals[principal].Exists = true
				} else {
					principals[principal].Type = "group"
					principals[principal].Validate()
				}
			}
			if deleteGroups && principals[principal].Exists {
				principals[principal].Delete()
			}
			if item[0] != "" {
				au := new(au.Authorization)
				au.Principal = principals[principal]
				au.Type = "grant"
				au.ObjectURI = item[0]
				au.Validate()
				if au.IDs != nil {
					au.Delete()
				}
			}
		}
		co.Disconnect()
	},
}

func init() {
	matrixCmd.AddCommand(matrixRemoveCmd)
	matrixRemoveCmd.Flags().BoolP("delete-groups", "g", false, "delete listed custom groups")
}
