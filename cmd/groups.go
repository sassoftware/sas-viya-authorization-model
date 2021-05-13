// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

// groupsCmd represents the groups command
var groupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "SAS Viya Custom Groups",
	Long:  `Apply, Remove, or Declare a SAS Viya Custom Groups structure.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.AddCommand(groupsCmd)
}
