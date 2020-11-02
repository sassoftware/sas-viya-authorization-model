// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"testing"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func TestReadJSONFile(t *testing.T) {
	write := []byte(`{"Default": {"ansi-colors-enabled": "true", "oauth-client-id": "sas.cli", "output": "json", "sas-endpoint": "http://0.0.0.0"}}`)
	var expected string = "http://0.0.0.0"
	ioutil.WriteFile("test.json", write, 0644)
	var returned Config
	ReadJSONFile("test.json", &returned)
	if expected != returned.Profile.Endpoint {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
	os.Remove("test.json")
}

func TestReadCSVFile(t *testing.T) {
	write := []byte("Col1,Col2\r\nTest1,Test2\r\n")
	expected := []map[string]string{
		0: {
			"Col1": "Test1",
			"Col2": "Test2",
		},
	}
	ioutil.WriteFile("test.csv", write, 0644)
	returned := ReadCSVFile("test.csv", []string{"Col1", "Col2"})
	if !reflect.DeepEqual(returned, expected) {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
	os.Remove("test.csv")
}

func TestStartLogging(t *testing.T) {
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
			StartLogging()
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

func TestCalculateFileMode(t *testing.T) {
	var TestCases = []struct {
		name string
		in   []string
		out  os.FileMode
	}{
		{"777", []string{
			"rwx",
			"rwx",
			"rwx",
		}, os.FileMode(0777)},
		{"750", []string{
			"rwx",
			"r-x",
			"---",
		}, os.FileMode(0750)},
		{"644", []string{
			"rw-",
			"r--",
			"r--",
		}, os.FileMode(0644)},
	}
	for _, test := range TestCases {
		t.Run(test.name, func(t *testing.T) {
			FileMode := CalculateFileMode(test.in[0], test.in[1], test.in[2])
			if FileMode != test.out {
				t.Errorf("Expected: %v, Returned: %v.", test.out, FileMode)
			}
		})
	}
}

func TestManagePOSIXPermissions(t *testing.T) {
	user, _ := user.Current()
	var uid, gid int64
	uid, _ = strconv.ParseInt(user.Uid, 10, 32)
	gid, _ = strconv.ParseInt(user.Gid, 10, 32)
	var TestCases = []struct {
		name     string
		path     string
		perm     POSIX
		expected bool
	}{
		{"Baseline", "dir01", POSIX{
			UID:             uid,
			GID:             []int64{gid},
			OwnerPermission: "rwx",
			GroupPermission: []string{"rwx"},
			OtherPermission: "rwx",
			SetGID:          false,
			StickyBit:       false,
		}, true},
		{"BaselineSetGID", "dir02", POSIX{
			UID:             uid,
			GID:             []int64{gid},
			OwnerPermission: "rwx",
			GroupPermission: []string{"rwx"},
			OtherPermission: "rwx",
			SetGID:          true,
			StickyBit:       false,
		}, true},
		{"BaselineSticky", "dir03", POSIX{
			UID:             uid,
			GID:             []int64{gid},
			OwnerPermission: "rwx",
			GroupPermission: []string{"rwx"},
			OtherPermission: "rwx",
			SetGID:          false,
			StickyBit:       true,
		}, true},
		{"BaselineBoth", "dir04", POSIX{
			UID:             uid,
			GID:             []int64{gid},
			OwnerPermission: "rwx",
			GroupPermission: []string{"rwx"},
			OtherPermission: "rwx",
			SetGID:          true,
			StickyBit:       true,
		}, true},
		{"ACL", "dir05", POSIX{
			UID:             uid,
			GID:             []int64{gid, 1337},
			OwnerPermission: "rwx",
			GroupPermission: []string{"rwx", "r-x"},
			OtherPermission: "---",
			SetGID:          false,
			StickyBit:       false,
		}, true},
		{"ACLFailGID", "dir06", POSIX{
			UID:             uid,
			GID:             []int64{gid},
			OwnerPermission: "rwx",
			GroupPermission: []string{"rwx", "r-x"},
			OtherPermission: "---",
			SetGID:          false,
			StickyBit:       false,
		}, false},
		{"ACLFailGroupPermission", "dir07", POSIX{
			UID:             uid,
			GID:             []int64{gid, 1337},
			OwnerPermission: "rwx",
			GroupPermission: []string{"rwx"},
			OtherPermission: "---",
			SetGID:          false,
			StickyBit:       false,
		}, false},
	}
	for _, test := range TestCases {
		t.Run(test.name, func(t *testing.T) {
			os.MkdirAll(test.path, os.FileMode(0755))
			returned := ManagePOSIXPermissions(test.path, test.perm)
			if returned != test.expected {
				t.Errorf("Expected: %v, Returned: %v.", test.expected, returned)
			}
			os.RemoveAll(test.path)
		})
	}
}

func TestManagePOSIXFolders(t *testing.T) {
	user, _ := user.Current()
	var uid, gid int64
	uid, _ = strconv.ParseInt(user.Uid, 10, 32)
	gid, _ = strconv.ParseInt(user.Gid, 10, 32)
	var TestCases = []struct {
		name     string
		path     string
		perm     POSIX
		expected bool
	}{
		{"validate", "test1/test/test", POSIX{
			UID:             uid,
			GID:             []int64{gid},
			OwnerPermission: "rwx",
			GroupPermission: []string{"rwx"},
			OtherPermission: "rwx",
			SetGID:          true,
			StickyBit:       false,
		}, false},
		{"create", "test1/test/test", POSIX{
			UID:             uid,
			GID:             []int64{gid},
			OwnerPermission: "rwx",
			GroupPermission: []string{"r-x"},
			OtherPermission: "r-x",
			SetGID:          false,
			StickyBit:       true,
		}, true},
		{"delete", "test1", POSIX{
			UID:             uid,
			GID:             []int64{gid},
			OwnerPermission: "rwx",
			GroupPermission: []string{"r-x"},
			OtherPermission: "---",
			SetGID:          true,
			StickyBit:       true,
		}, false},
		{"deleteRecursive", "test1/test2", POSIX{
			UID:             uid,
			GID:             []int64{gid},
			OwnerPermission: "rwx",
			GroupPermission: []string{"r-x"},
			OtherPermission: "---",
			SetGID:          true,
			StickyBit:       true,
		}, true},
	}
	for _, test := range TestCases {
		t.Run(test.name, func(t *testing.T) {
			returned := ManagePOSIXFolders(test.name, test.path, test.perm)
			os.RemoveAll(test.path)
			if returned != test.expected {
				t.Errorf("Expected: %v, Returned: %v.", test.expected, returned)
			}
		})
	}
}

func TestConvertNotation(t *testing.T) {
	var TestCases = []struct {
		in  string
		out string
	}{
		{"---", "0"},
		{"--x", "1"},
		{"-w-", "2"},
		{"-wx", "3"},
		{"r--", "4"},
		{"r-x", "5"},
		{"rw-", "6"},
		{"rwx", "7"},
		{"setgid", ""},
		{"rw", ""},
	}
	for _, test := range TestCases {
		t.Run(test.in, func(t *testing.T) {
			returned := ConvertNotation(test.in)
			if returned != test.out {
				t.Errorf("Expected: %v, Returned: %v.", test.out, returned)
			}
		})
	}
}

func TestConvertKV(t *testing.T) {
	var TestCases = []struct {
		name string
		in   []KV
		out  []byte
	}{
		{"CreateCustomGroup", []KV{{"id", "testgroup"}, {"name", "Test Group"}, {"description", "Automatically created by goViyaAuth"}, {"state", "active"}}, []byte(`{"description":"Automatically created by goViyaAuth","id":"testgroup","name":"Test Group","state":"active"}`)},
		{"CreateCustomFolder", []KV{{"name", "Test Folder"}, {"type", "folder"}}, []byte(`{"name":"Test Folder","type":"folder"}`)},
		{"CreateAuthorizationRule", []KV{{"permissions", []string{"read", "update"}}, {"principal", "geladmn"}}, []byte(`{"permissions":["read","update"],"principal":"geladmn"}`)},
	}
	for _, test := range TestCases {
		t.Run(test.name, func(t *testing.T) {
			returned := ConvertKV(test.in)
			if !reflect.DeepEqual(returned, test.out) {
				t.Errorf("Expected: %v, Returned: %v.", test.out, returned)
			}
		})
	}
}

func TestLookupID(t *testing.T) {
	user, _ := user.Current()
	uid, _ := strconv.ParseInt(user.Uid, 10, 32)
	returned := LookupID(user.Username, true)
	if uid != returned {
		t.Errorf("Expected: %v, Returned: %v.", uid, returned)
	}
}

func TestJoinMaps(t *testing.T) {
	right := []map[string]string{
		{
			"GrantType":   "object",
			"Permissions": "read",
			"Principal":   "per001",
			"Pattern":     "ipap_lob",
		},
		{
			"GrantType":   "object",
			"Permissions": "read,update,delete,secure,add,remove",
			"Principal":   "per007",
			"Pattern":     "ipap_lob",
		},
	}
	left := []map[string]string{
		{
			"Pattern":   "ipap_lob",
			"Directory": "/Test",
		},
		{
			"Pattern":   "ipap_lob",
			"Directory": "/Test/Sub Test 1",
		},
	}
	expected := []map[string]string{
		{
			"GrantType":   "object",
			"Permissions": "read",
			"Principal":   "per001",
			"Pattern":     "ipap_lob",
			"Directory":   "/Test",
		},
		{
			"GrantType":   "object",
			"Permissions": "read,update,delete,secure,add,remove",
			"Principal":   "per007",
			"Pattern":     "ipap_lob",
			"Directory":   "/Test",
		},
		{
			"GrantType":   "object",
			"Permissions": "read",
			"Principal":   "per001",
			"Pattern":     "ipap_lob",
			"Directory":   "/Test/Sub Test 1",
		},
		{
			"GrantType":   "object",
			"Permissions": "read,update,delete,secure,add,remove",
			"Principal":   "per007",
			"Pattern":     "ipap_lob",
			"Directory":   "/Test/Sub Test 1",
		},
	}
	returned := JoinMaps(left, right, "Pattern", "inner")
	if !reflect.DeepEqual(returned, expected) {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
}

func TestReverseMap(t *testing.T) {
	in := []map[string]string{
		{
			"Pattern":   "ipap_lob",
			"Directory": "/Test",
		},
		{
			"Pattern":   "ipap_lob",
			"Directory": "/Test/Sub Test 1",
		},
		{
			"Pattern":   "ipap_lob",
			"Directory": "/Test/Sub Test 2",
		},
	}
	expected := []map[string]string{
		{
			"Pattern":   "ipap_lob",
			"Directory": "/Test/Sub Test 2",
		},
		{
			"Pattern":   "ipap_lob",
			"Directory": "/Test/Sub Test 1",
		},
		{
			"Pattern":   "ipap_lob",
			"Directory": "/Test",
		},
	}
	returned := ReverseMap(in)
	if !reflect.DeepEqual(returned, expected) {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
}

func TestAssertString(t *testing.T) {
	var TestCases = []struct {
		name string
		in   interface{}
		out  string
	}{
		{"nil", nil, "nil"},
		{"int", 5, "5"},
		{"bool", true, "true"},
		{"string", "test", "test"},
		{"float", 8.8, "8.8"},
	}
	for _, test := range TestCases {
		t.Run(test.name, func(t *testing.T) {
			returned := AssertString(test.in)
			if returned != test.out {
				t.Errorf("Expected: %v, Returned: %v.", test.out, returned)
			}
		})
	}
}
