// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	au "github.com/sassoftware/sas-viya-authorization-model/authorization"
	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	fi "github.com/sassoftware/sas-viya-authorization-model/file"
	fo "github.com/sassoftware/sas-viya-authorization-model/folder"
	lo "github.com/sassoftware/sas-viya-authorization-model/log"
	pr "github.com/sassoftware/sas-viya-authorization-model/principal"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// ipapRemoveCmd represents the ipapRemove command
var ipapRemoveCmd = &cobra.Command{
	Use:   "remove [pattern] [folders]",
	Short: "Remove IPAP",
	Long:  `Remove an Information Product Access Pattern definition [pattern] from a list of SAS Viya content folders [folders].`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		new(lo.Log).New()
		deleteGroups, _ := cmd.Flags().GetBool("delete-groups")
		deleteFolders, _ := cmd.Flags().GetBool("delete-folders")
		zap.S().Infow("Removing IPAP from SAS Viya content folders", "pattern", args[0], "folders", args[1], "delete-groups", deleteGroups, "delete-folders", deleteFolders)
		co := new(co.Connection)
		co.Connect()
		fp := new(fi.File)
		fp.Path = args[0]
		fp.Schema = []string{"Pattern", "Principal", "GrantType", "Permissions"}
		fp.Type = "csv"
		fp.Read()
		ff := new(fi.File)
		ff.Path = args[1]
		ff.Schema = []string{"Directory", "Pattern"}
		ff.Type = "csv"
		ff.Read()
		patterns := make(map[string][][]string)
		principals := make(map[string]*pr.Principal)
		folders := make(map[string]*fo.Folder)
		for _, pattern := range fp.Content.([][]string)[1:] {
			patterns[pattern[0]] = append(patterns[pattern[0]], pattern[1:])
		}
		for _, folder := range ff.Content.([][]string)[1:] {
			var pathElements []string = strings.Split(folder[0], "/")
			if _, exists := folders[folder[0]]; !exists {
				folders[folder[0]] = new(fo.Folder)
				folders[folder[0]].Path = folder[0]
				folders[folder[0]].Connection = co
				folders[folder[0]].Validate()
			}
			if (folders[folder[0]].Parent == nil) && len(pathElements) >= 3 {
				var parentPath string
				for i := 1; i <= len(pathElements)-2; i++ {
					parentPath = parentPath + "/" + pathElements[i]
				}
				if _, exists := folders[parentPath]; exists {
					folders[folder[0]].Parent = folders[parentPath]
				}
			}
			if deleteFolders && folders[folder[0]].Exists {
				folders[folder[0]].DeleteRecursive()
			}
			if _, exists := patterns[folder[1]]; exists {
				for _, item := range patterns[folder[1]] {
					var principal string = item[0]
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
					if folders[folder[0]].URI != "" {
						au := new(au.Authorization)
						au.Principal = principals[principal]
						au.Type = "grant"
						au.Enabled = "true"
						au.Permissions = strings.Split(item[2], ",")
						au.Description = "Automatically enabled by goViyaAuth"
						if item[1] == "object" {
							au.ObjectURI = folders[folder[0]].URI + "/**"
						} else if item[1] == "conveyed" {
							au.ContainerURI = folders[folder[0]].URI
						}
						au.Validate()
						if au.IDs != nil {
							au.Delete()
						}
					}
				}
			}
		}
		co.Disconnect()
	},
}

func init() {
	ipapCmd.AddCommand(ipapRemoveCmd)
	ipapRemoveCmd.Flags().BoolP("delete-groups", "g", false, "delete listed custom groups")
	ipapRemoveCmd.Flags().BoolP("delete-folders", "f", false, "delete listed SAS Viya content folders recursively. WARNING: Also deletes non-empty folders!")
}
