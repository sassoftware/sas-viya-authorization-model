// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func TestNew(t *testing.T) {
	var TestCases = []struct {
		name string
		in   string
		out  int
	}{
		{"DEBUG", "DEBUG", 4},
		{"INFO", "INFO", 3},
		{"WARN", "WARN", 2},
		{"ERROR", "ERROR", 1},
	}
	for _, test := range TestCases {
		t.Run(test.name, func(t *testing.T) {
			viper.Set("loglevel", test.in)
			viper.Set("logfile", test.in+".log")
			l := new(Log)
			l.New()
			zap.S().Debugw("DEBUG entry")
			zap.S().Infow("INFO entry")
			zap.S().Warnw("WARN entry")
			zap.S().Errorw("ERROR entry")
			content, err := ioutil.ReadFile(test.in + ".log")
			if err != nil {
				t.Errorf(err.Error())
			}
			rows := bytes.Count(content, []byte{'\n'})
			if rows != test.out {
				t.Errorf("Expected: %v, Returned: %v.", test.out, rows)
			}
			os.Remove(test.in + ".log")
		})
	}
}
