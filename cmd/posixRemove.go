// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// posixRemoveCmd represents the posixRemove command
var posixRemoveCmd = &cobra.Command{
	Use:   "remove [folders]",
	Short: "Remove POSIX",
	Long:  `Remove all POSIX Permissions Pattern definitions from a list of POSIX folders [folders].`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		zap.S().Warnw("DEPRECATED: All POSIX-related functionality will be dropped with the next release in preparation for SAS Viya 2021")
		var folders string
		var deleteFolders bool
		var foldersFile, foldersReverse []map[string]string
		deleteFolders, _ = cmd.Flags().GetBool("delete-folders")
		folders = args[0]
		zap.S().Infow("Remove all POSIX Permissions Pattern definitions", "folders", folders, "delete-folders", deleteFolders)
		foldersFile = utils.ReadCSVFile(folders, []string{"Directory", "Pattern"})
		foldersReverse = utils.ReverseMap(foldersFile)
		for _, item := range foldersReverse {
			permissions := utils.POSIX{
				UID: 1000,
				GID: []int64{1000},
			}
			if deleteFolders {
				utils.ManagePOSIXFolders("delete", item["Directory"], permissions)
			} else {
				utils.ManagePOSIXPermissions(item["Directory"], permissions)
			}
		}
	},
}

func init() {
	posixCmd.AddCommand(posixRemoveCmd)
	posixRemoveCmd.Flags().BoolP("delete-folders", "f", false, "delete listed POSIX folders if empty")
}
