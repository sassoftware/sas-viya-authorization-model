// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

// matrixCmd represents the matrix command
var matrixCmd = &cobra.Command{
	Use:   "matrix",
	Short: "SAS Viya Platform Capability Matrix",
	Long:  `Apply or Remove a SAS Viya Platform Capability Matrix.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.AddCommand(matrixCmd)
}
