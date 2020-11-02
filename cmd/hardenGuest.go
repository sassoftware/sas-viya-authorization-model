// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// hardenGuestCmd represents the hardenGuest command
var hardenGuestCmd = &cobra.Command{
	Use:   "guest",
	Short: "Remove all permissions for \"guest\"",
	Long:  `Remove all permissions for "guest".`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		utils.ManageSession("create")
		zap.S().Infow("Removing all SAS Viya permissions for \"guest\"")
		rule := utils.AuthorizationRule{
			Principal:     "guest",
			PrincipalType: "guest",
			Enabled:       "false",
			Description:   "Automatically removed by goViyaAuth",
			EveryURI:      true,
		}
		utils.AssertViyaPermissions(rule)
		zap.S().Infow("Removing all CAS access controls for \"guest\"")
		caslibs := []string{
			"AppData",
			"Formats",
			"ModelPerformanceData",
			"Models",
			"ModelStore",
			"ProductData",
			"Public",
			"ReferenceData",
			"SystemData",
			"VAModels",
		}
		for _, caslib := range caslibs {
			acs := utils.AccessControl{
				CASLIB: caslib,
				Action: "remove",
				CASACL: []utils.CASACL{
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "readInfo",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "select",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "limitedPromote",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "promote",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "createTable",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "dropTable",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "deleteSource",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "insert",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "update",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "delete",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "alterTable",
					},
					{
						Type:         "grant",
						IdentityType: "guest",
						Identity:     "guest",
						Permission:   "manageAccess",
					},
				},
			}
			utils.AssertCASPermissions(acs)
		}
	},
}

func init() {
	hardenCmd.AddCommand(hardenGuestCmd)
}
