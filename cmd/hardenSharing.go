// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// hardenSharingCmd represents the hardenSharing command
var hardenSharingCmd = &cobra.Command{
	Use:   "sharing",
	Short: "Disable sharing and resharing",
	Long:  `Disable sharing and resharing.`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		utils.ManageSession("create")
		zap.S().Infow("Disabling sharing and resharing")
		call1 := utils.APICall{
			Verb: "GET",
			Path: "/configuration/configurations",
			Query: []utils.KV{
				{K: "definitionName", V: "sas.authorization"},
				{K: "limit", V: viper.GetString("responselimit")},
			},
			Body: nil,
		}
		search, _ := utils.CallViya(call1)
		var count string = utils.AssertString(search.(map[string]interface{})["count"])
		if count == "0" {
			zap.S().Debugw("Sharing and resharing setting not found")
		} else {
			zap.S().Debugw("Sharing or resharing setting found", "count", count)
			if items, ok := search.(map[string]interface{})["items"].([]interface{}); ok {
				for _, item := range items {
					var id string = utils.AssertString(item.(map[string]interface{})["id"])
					zap.S().Infow("Changing configuration setting", "id", id)
					call2 := utils.APICall{
						Verb:  "PUT",
						Path:  "/configuration/configurations/" + id,
						Query: nil,
						Body: utils.ConvertKV([]utils.KV{
							{K: "share.reshare.enabled", V: false},
							{K: "share.enabled", V: false},
						}),
						AcceptType:  "application/vnd.sas.configuration.config.sas.authorization+json;version=3",
						ContentType: "application/vnd.sas.configuration.config.sas.authorization+json;version=3",
					}
					utils.CallViya(call2)
				}
			} else {
				zap.S().Errorw("No items returned")
			}
		}
		utils.ManageSession("destroy")
	},
}

func init() {
	hardenCmd.AddCommand(hardenSharingCmd)
}
