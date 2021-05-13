// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string
var profile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "goviyaauth",
	Short: "Manage SAS Viya Authorization Concepts",
	Long:  `Manage all authorization concepts of a SAS Viya environment.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file location (default is $HOME/.sas/gva.json)")
	rootCmd.PersistentFlags().StringVar(&profile, "profile", "", "sas-viya CLI profile (default is Default)")
	rootCmd.PersistentFlags().Bool("insecure", false, "allow TLS connections without validating the server certificates (default is false)")
}

// initConfig reads in config file and ENV variables if set, otherwise reverts to defaults.
func initConfig() {
	home, err := homedir.Dir()
	t := time.Now()
	viper.Set("home", home)
	insecure, _ := rootCmd.PersistentFlags().GetBool("insecure")
	if err != nil {
		zap.S().Fatalw("Error finding the user's home directory", "error", err)
	}
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(home + "/.sas/")
		viper.SetConfigName("gva")
	}
	viper.SetEnvPrefix("gva")
	viper.AutomaticEnv()

	viper.SetDefault("clidir", "/opt/sas/viya/home/bin/")
	viper.SetDefault("casserver", "cas-shared-default")
	viper.SetDefault("logfile", "gva-"+t.Format("2006-01-02")+".log")
	viper.SetDefault("loglevel", "INFO")
	viper.SetDefault("responselimit", "1000")
	viper.SetDefault("baseurl", "")
	viper.SetDefault("validtls", !insecure)
	viper.SetDefault("user", "")
	viper.SetDefault("pw", "")
	viper.SetDefault("clientid", "sas.cli")
	viper.SetDefault("clientsecret", "")
	if profile != "" {
		viper.SetDefault("profile", profile)
	} else {
		viper.SetDefault("profile", "Default")
	}

	if err := viper.ReadInConfig(); err == nil {
		zap.S().Infow("Using provided config file", "ConfigFileUsed", viper.ConfigFileUsed())
	} else {
		zap.S().Errorw("Issue reading provided config file", "error", err)
	}
}
