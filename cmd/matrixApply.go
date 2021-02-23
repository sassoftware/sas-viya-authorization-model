// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	au "github.com/sassoftware/sas-viya-authorization-model/authorization"
	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	fi "github.com/sassoftware/sas-viya-authorization-model/file"
	lo "github.com/sassoftware/sas-viya-authorization-model/log"
	pr "github.com/sassoftware/sas-viya-authorization-model/principal"
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
		new(lo.Log).New()
		createGroups, _ := cmd.Flags().GetBool("create-groups")
		zap.S().Infow("Applying a SAS Viya Platform Capability Matrix", "matrix", args[0], "create-groups", createGroups)
		co := new(co.Connection)
		co.Connect()
		fi := new(fi.File)
		fi.Path = args[0]
		fi.Schema = []string{"URI", "Principal", "Permissions"}
		fi.Type = "csv"
		fi.Read()
		principals := make(map[string]*pr.Principal)
		for _, item := range fi.Content.([][]string)[1:] {
			zap.S().Infow("Granting SAS Viya Platform Capability", "item", item)
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
			if createGroups && !principals[principal].Exists {
				principals[principal].Create()
			}
			if item[0] != "" {
				au := new(au.Authorization)
				au.Principal = principals[principal]
				au.Type = "grant"
				au.Enabled = "true"
				au.Permissions = strings.Split(item[2], ",")
				au.Description = "Automatically enabled by goViyaAuth"
				au.ObjectURI = item[0]
				au.Validate()
				if au.IDs == nil {
					au.Enable()
				}
			}
		}
		co.Disconnect()
	},
}

func init() {
	matrixCmd.AddCommand(matrixApplyCmd)
	matrixApplyCmd.Flags().BoolP("create-groups", "g", false, "create missing custom groups")
}
