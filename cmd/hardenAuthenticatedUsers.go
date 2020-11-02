// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// hardenAuthenticatedUsersCmd represents the hardenAuthenticatedUsers command
var hardenAuthenticatedUsersCmd = &cobra.Command{
	Use:   "au",
	Short: "Restrict permissions for \"authenticatedUsers\"",
	Long:  `Restrict permissions for "authenticatedUsers".`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		utils.ManageSession("create")
		capabilities := []string{
			"/SASDrive/**",
			"/SASDrive/rest/userLinks/**",
			"/SASDrive_capabilities/allowUpload",
			"/SASDrive_capabilities/allowDownload",
			"/SASDrive_capabilities/allowSASVideo",
			"/SASDrive_capabilities/allowSASVideoLinks",
			"/SASDrive_capabilities/allowWelcomeTour",
			"/SASDrive_capabilities/allowWelcomeTourMenu",
			"/SASEnvironmentManager/",
			"/SASEnvironmentManager/dashboard",
			"/SASEnvironmentManager/data",
			"/SASEnvironmentManager/content",
			"/SASEnvironmentManager/jobs",
			"/SASEnvironmentManager/credentials",
			"/SASEnvironmentManager/identities",
			"/SASEnvironmentManager/contexts",
			"/SASEnvironmentManager/udf",
			"/SASEnvironmentManager/logs",
			"/SASEnvironmentManager/destinations",
			"/SASEnvironmentManager/servers",
			"/SASEnvironmentManager/migration",
			"/SASDataExplorer/**",
			"/SASDataStudio/**",
			"/SASGraphBuilder/**",
			"/SASLineage/**",
			"/ModelStudio/**",
			"/SASStudioV/**",
			"/SASThemeDesigner/**",
			"/SASWorkflowManager/**",
			"/jobExecution/jobRequests/*",
			"/jobExecution/jobRequests/*/",
			"/scheduler/jobs/**",
			"/jobExecution/jobs/**",
			"/maps/providers",
			"/maps/providers/*",
			"/maps/providers/*/centroids/state",
			"/webDataAccess/esri/user/token",
			"/SASVisualAnalytics/**",
			"/SASVisualAnalytics_capabilities/edit",
			"/casManagement_capabilities/importData",
			"/webDataAccess_capabilities/facebookImport",
			"/webDataAccess_capabilities/googledriveImport",
			"/webDataAccess_capabilities/googleanalyticsImport",
			"/webDataAccess_capabilities/youtubeImport",
			"/webDataAccess_capabilities/twitterImport",
			"/casManagement/servers/*/caslibs/*/tables",
			"/reportRenderer/reports/**",
			"/reportData_capabilities/exportData",
			"/reportData_capabilities/exportDetailData",
			"/SASVisualAnalyticsCommon_capabilities/exportImage",
			"/dataPreparation_capabilities/exportTable",
			"/SASVisualAnalyticsCommon_capabilities/shareReport",
			"/reportImages/jobs/**",
			"/SASVisualAnalytics_capabilities/buildAnalyticalModel",
			"/reports/reports/*/states",
			"/SASVisualAnalytics_capabilities/shareDataView",
			"/reportAlerts/**",
			"/reportImages/textTemplateOutput",
			"/comments/**",
			"/reportAlerts/evaluator/**",
			"/reportDistribution/distributionRequests/**",
			"/reportDistribution/distributions/**",
			"/folders/folders?parentFolderUri=/folders/folders/*",
		}
		folders := []string{
			"/Model Repositories",
			"/Projects",
			"/Public",
		}
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
		zap.S().Infow("Deleting SAS Viya capability authorization rules for \"authenticatedUsers\". Note: Ensure you have explicitly granted these capabilities to nominated principals")
		for _, uri := range capabilities {
			rule := utils.AuthorizationRule{
				Principal:     "authenticatedUsers",
				PrincipalType: "authenticatedUsers",
				Enabled:       "false",
				Description:   "Automatically removed by goViyaAuth",
				ObjectURI:     uri,
			}
			utils.AssertViyaPermissions(rule)
		}
		zap.S().Infow("Reducing default CAS access controls for \"authenticatedUsers\" to a maximum of read-only or less. Note: Use DAP removal for non-standard \"authenticatedUsers\" access controls")
		for _, caslib := range caslibs {
			acs := utils.AccessControl{
				CASLIB: caslib,
				Action: "remove",
				CASACL: []utils.CASACL{
					{
						Type:         "grant",
						IdentityType: "group",
						Identity:     "*",
						Permission:   "promote",
					},
					{
						Type:         "grant",
						IdentityType: "group",
						Identity:     "*",
						Permission:   "createTable",
					},
					{
						Type:         "grant",
						IdentityType: "group",
						Identity:     "*",
						Permission:   "dropTable",
					},
					{
						Type:         "grant",
						IdentityType: "group",
						Identity:     "*",
						Permission:   "deleteSource",
					},
					{
						Type:         "grant",
						IdentityType: "group",
						Identity:     "*",
						Permission:   "insert",
					},
					{
						Type:         "grant",
						IdentityType: "group",
						Identity:     "*",
						Permission:   "update",
					},
					{
						Type:         "grant",
						IdentityType: "group",
						Identity:     "*",
						Permission:   "delete",
					},
					{
						Type:         "grant",
						IdentityType: "group",
						Identity:     "*",
						Permission:   "alterTable",
					},
					{
						Type:         "grant",
						IdentityType: "group",
						Identity:     "*",
						Permission:   "manageAccess",
					},
				},
			}
			utils.AssertCASPermissions(acs)
		}
		zap.S().Infow("Removing default SAS Viya content folder permissions for \"authenticatedUsers\". Note: Use IPAP removal for non-standard \"authenticatedUsers\" permissions")
		for _, folder := range folders {
			var uri string = utils.ManageFolder("validate", folder)
			if uri != "" {
				rule := utils.AuthorizationRule{
					Principal:     "authenticatedUsers",
					PrincipalType: "authenticatedUsers",
					Enabled:       "false",
					Description:   "Automatically removed by goViyaAuth",
					ContainerURI:  uri,
				}
				utils.AssertViyaPermissions(rule)
			}
		}
		utils.ManageSession("destroy")
	},
}

func init() {
	hardenCmd.AddCommand(hardenAuthenticatedUsersCmd)
}
