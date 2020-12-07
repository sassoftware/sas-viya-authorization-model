// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestReadJSON(t *testing.T) {
	write := []byte(`{"Default": {"ansi-colors-enabled": "true", "oauth-client-id": "sas.cli", "output": "json", "sas-endpoint": "http://0.0.0.0"}}`)
	var expected string = "http://0.0.0.0"
	ioutil.WriteFile("test.json", write, 0644)
	f := new(File)
	f.Path = "test.json"
	f.Type = "json"
	// config of SAS Viya connection
	type config struct {
		Profile struct {
			ClientID string `json:"oauth-client-id"`
			Endpoint string `json:"sas-endpoint"`
		} `json:"Default"`
	}
	var conf config
	f.Content = conf
	f.Read()
	var returned string = f.Content.(map[string]interface{})["Default"].(map[string]interface{})["sas-endpoint"].(string)
	if expected != returned {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
	os.Remove("test.json")
}

func TestReadCSV(t *testing.T) {
	write := []byte("Col1,Col2\r\nTest1,Test2\r\n")
	expected := [][]string{
		0: {
			"Col1",
			"Col2",
		},
		1: {
			"Test1",
			"Test2",
		},
	}
	ioutil.WriteFile("test.csv", write, 0644)
	f := new(File)
	f.Path = "test.csv"
	f.Type = "csv"
	f.Schema = []string{"Col1", "Col2"}
	f.Read()
	var returned [][]string = f.Content.([][]string)
	if !reflect.DeepEqual(returned, expected) {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
	os.Remove("test.csv")
}
