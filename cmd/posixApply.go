// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strconv"
	"strings"

	"github.com/sassoftware/sas-viya-authorization-model/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// posixApplyCmd represents the posixApply command
var posixApplyCmd = &cobra.Command{
	Use:   "apply [pattern] [folders]",
	Short: "Apply POSIX",
	Long:  `Apply a POSIX Permissions Pattern definition [pattern] to a list of POSIX folders [folders].`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		utils.StartLogging()
		var pattern, folders string
		var createFolders bool
		var patternFile, foldersFile, backlog []map[string]string
		createFolders, _ = cmd.Flags().GetBool("create-folders")
		pattern = args[0]
		folders = args[1]
		zap.S().Infow("Applying POSIX Permissions Pattern definition", "pattern", pattern, "folders", folders, "create-folders", createFolders)
		patternFile = utils.ReadCSVFile(pattern, []string{"Pattern", "UID", "GID", "OwnerPermission", "GroupPermission", "OtherPermission", "SetGID", "StickyBit"})
		foldersFile = utils.ReadCSVFile(folders, []string{"Directory", "Pattern"})
		backlog = utils.JoinMaps(foldersFile, patternFile, "Pattern", "inner")
		for _, item := range backlog {
			var SetGID, StickyBit bool
			var UID int64
			var GID []int64
			var GroupPermission []string
			SetGID, _ = strconv.ParseBool(item["SetGID"])
			StickyBit, _ = strconv.ParseBool(item["StickyBit"])
			UID, _ = strconv.ParseInt(item["UID"], 10, 64)
			groups := strings.Split(item["GID"], "|")
			for _, group := range groups {
				groupid, _ := strconv.ParseInt(group, 10, 64)
				GID = append(GID, groupid)
			}
			gperms := strings.Split(item["GroupPermission"], "|")
			for _, gperm := range gperms {
				GroupPermission = append(GroupPermission, gperm)
			}
			permissions := utils.POSIX{
				UID:             UID,
				GID:             GID,
				OwnerPermission: item["OwnerPermission"],
				GroupPermission: GroupPermission,
				OtherPermission: item["OtherPermission"],
				SetGID:          SetGID,
				StickyBit:       StickyBit,
			}
			if createFolders {
				utils.ManagePOSIXFolders("create", item["Directory"], permissions)
			}
			utils.ManagePOSIXPermissions(item["Directory"], permissions)
		}
	},
}

func init() {
	posixCmd.AddCommand(posixApplyCmd)
	posixApplyCmd.Flags().BoolP("create-folders", "f", false, "create missing POSIX folders")
}
