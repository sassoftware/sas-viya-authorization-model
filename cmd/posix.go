// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

// posixCmd represents the posix command
var posixCmd = &cobra.Command{
	Use:   "posix",
	Short: "POSIX Permissions Pattern",
	Long:  `Apply or Remove POSIX Permissions Pattern.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.AddCommand(posixCmd)
}
