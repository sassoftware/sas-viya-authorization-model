// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

// ipapCmd represents the ipap command
var ipapCmd = &cobra.Command{
	Use:   "ipap",
	Short: "Information Product Access Pattern (\"IPAP\")",
	Long:  `Apply or Remove Information Product Access Pattern ("IPAP").`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.AddCommand(ipapCmd)
}
