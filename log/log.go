// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"os"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log object
type Log struct {
	Level    zapcore.Level
	FilePath string
	Logger   *zap.Logger
}

// New logger
func (l *Log) New() {
	switch viper.GetString("loglevel") {
	case "INFO":
		l.Level = zap.InfoLevel
	case "WARN":
		l.Level = zap.WarnLevel
	case "ERROR":
		l.Level = zap.ErrorLevel
	case "FATAL":
		l.Level = zap.FatalLevel
	default:
		l.Level = zap.DebugLevel
	}
	l.FilePath = viper.GetString("logfile")
	l.startLogging()
	zap.ReplaceGlobals(l.Logger)
}

// startLogging initializes a custom global logger
func (l *Log) startLogging() {
	pe := zap.NewProductionEncoderConfig()
	fileEncoder := zapcore.NewJSONEncoder(pe)
	pe.EncodeTime = zapcore.ISO8601TimeEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(pe)
	f, err := os.OpenFile(l.FilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		zap.S().Fatalw("Error when reading file", "error", err)
	}
	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, zapcore.AddSync(f), l.Level),
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), l.Level),
	)
	l.Logger = zap.New(core)
}
