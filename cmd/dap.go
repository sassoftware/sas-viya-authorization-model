// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

// dapCmd represents the dap command
var dapCmd = &cobra.Command{
	Use:   "dap",
	Short: "Data Access Pattern (\"DAP\")",
	Long:  `Apply or remove Data Access Pattern ("DAP").`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.AddCommand(dapCmd)
}
