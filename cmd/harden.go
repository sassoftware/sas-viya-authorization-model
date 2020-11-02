// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

// hardenCmd represents the harden command
var hardenCmd = &cobra.Command{
	Use:   "harden",
	Short: "Harden SAS Viya",
	Long:  `Harden SAS Viya default configuration settings.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.AddCommand(hardenCmd)
}
