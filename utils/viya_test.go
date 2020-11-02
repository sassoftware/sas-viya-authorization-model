// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

func TestGetAccessToken(t *testing.T) {
	home, _ := homedir.Dir()
	viper.Set("home", home)
	var token string = GetAccessToken()
	var length int = len(token)
	if length < 1000 {
		t.Errorf("Expected: %v, Returned: %v.", ">= 1000", length)
	}
}

func TestGetBaseURL(t *testing.T) {
	home, _ := homedir.Dir()
	viper.Set("home", home)
	var baseurl string = GetBaseURL()
	var content bool = strings.Contains(baseurl, "http")
	if !content {
		t.Errorf("Expected: %v, Returned: %v.", true, content)
	}
}

func TestGetCASSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, `{"id": "testsessionid"}`)
	}))
	defer server.Close()
	viper.Set("baseurl", server.URL)
	var session string = GetCASSession()
	if session != "testsessionid" {
		t.Errorf("Expected: %v, Returned: %v.", "testsessionid", session)
	}
}

func TestDestroyCASSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
	}))
	defer server.Close()
	viper.Set("baseurl", server.URL)
	DestroyCASSession("test")
}

func TestValidateCASSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, `{"id": "test"}`)
	}))
	defer server.Close()
	viper.Set("baseurl", server.URL)
	response := ValidateCASSession("test")
	if !response {
		t.Errorf("Expected: %v, Returned: %v.", true, response)
	}
}

func TestManageSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
	}))
	defer server.Close()
	var TestCases = []struct {
		in  string
		out bool
	}{
		{"destroy", false},
		{"validate", false},
	}
	for _, test := range TestCases {
		t.Run(test.in, func(t *testing.T) {
			viper.Set("baseurl", server.URL)
			viper.Set("cassession", "testsessionid")
			viper.Set("accesstoken", "testaccesstoken")
			returned := ManageSession(test.in)
			if returned != test.out {
				t.Errorf("Expected: %v, Returned: %v.", test.out, returned)
			}
		})
	}
}

func TestCallViya(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, `{"success": true}`)
	}))
	defer server.Close()
	viper.Set("baseurl", server.URL)
	call := APICall{
		Verb: "GET",
		Path: "/test",
		Query: []KV{
			{"key", "value"},
		},
		Body: ConvertKV([]KV{
			{"key", "value"},
		}),
	}
	resp, status := CallViya(call)
	var returned bool = resp.(map[string]interface{})["success"].(bool)
	if !returned || status != 200 {
		t.Errorf("Expected: %v, Returned: %v.", true, returned)
	}
}

func TestManageGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, `{"count": 0}`)
	}))
	defer server.Close()
	var TestCases = []struct {
		mode  string
		group string
		out   bool
	}{
		{"validate", "testgroup", false},
		{"create", "testgroup", false},
		{"delete", "testgroup", true},
		{"deleteMembers", "testgroup", true},
	}
	for _, test := range TestCases {
		t.Run(test.mode, func(t *testing.T) {
			viper.Set("baseurl", server.URL)
			returned := ManageGroup(test.mode, test.group, test.group, "")
			if returned != test.out {
				t.Errorf("Expected: %v, Returned: %v.", test.out, returned)
			}
		})
	}
}

func TestManageFolder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, `{"id": "test 1/test2"}`)
	}))
	defer server.Close()
	var TestCases = []struct {
		mode string
		path string
		out  string
	}{
		{"validate", "/test1", "/folders/folders/test 1/test2"},
		{"create", "/test 1/test2", "/folders/folders/test 1/test2"},
		{"delete", "/test1/test 2", "/folders/folders/test 1/test2"},
		{"deleteRecursive", "/test 1/test 2", "/folders/folders/test 1/test2"},
	}
	for _, test := range TestCases {
		t.Run(test.mode, func(t *testing.T) {
			viper.Set("baseurl", server.URL)
			returned := ManageFolder(test.mode, test.path)
			if returned != test.out {
				t.Errorf("Expected: %v, Returned: %v.", test.out, returned)
			}
		})
	}
}

func TestAssertViyaPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, `{"accept":"application/vnd.sas.authorization.rule+json","count":1,"items":[{"createdBy":"geladm","createdTimestamp":"2020-05-06T06:46:39.933Z","creationTimeStamp":"2020-05-06T06:46:39.933Z","description":"Automatically created by goViyaAuth","enabled":true,"id":"a9ce98d4-90be-4e98-8a05-752f190d5255","links":[{"href":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255","method":"GET","rel":"self","responseType":"application/vnd.sas.authorization.rule","uri":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255"},{"href":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255","method":"PUT","rel":"update","responseType":"application/vnd.sas.authorization.rule","type":"application/vnd.sas.authorization.rule","uri":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255"},{"href":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255","method":"DELETE","rel":"delete","uri":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255"}],"matchParams":false,"modifiedBy":"geladm","modifiedTimeStamp":"2020-05-06T06:46:39.933Z","modifiedTimestamp":"2020-05-06T06:46:39.933Z","objectUri":"/SASEnvironmentManager/dashboard","permissions":["delete","update","read"],"principal":"HRModelers","principalType":"group","type":"grant","version":10}],"limit":1000,"links":[{"href":"/authorization/rules?filter=and(eq(principal,'HRModelers'),startsWith(objectUri,'/SASEnvironmentManager/dashboard'))&start=0&limit=1000","method":"GET","rel":"self","type":"application/vnd.sas.collection","uri":"/authorization/rules?filter=and(eq(principal,'HRModelers'),startsWith(objectUri,'/SASEnvironmentManager/dashboard'))&start=0&limit=1000"},{"href":"/authorization/rules","method":"GET","rel":"collection","type":"application/vnd.sas.collection","uri":"/authorization/rules"}],"name":"rules","start":0,"version":2}`)
	}))
	defer server.Close()
	var TestCases = []struct {
		mode string
		in   AuthorizationRule
		out  bool
	}{
		{"Container", AuthorizationRule{
			ContainerURI: "testuri",
			Permissions:  []string{"perm1", "perm2"},
			Enabled:      "true",
		}, true},
		{"Object", AuthorizationRule{
			ObjectURI:   "testuri",
			Permissions: []string{"perm1"},
			Enabled:     "true",
		}, true},
	}
	for _, test := range TestCases {
		t.Run(test.mode, func(t *testing.T) {
			viper.Set("baseurl", server.URL)
			returned := AssertViyaPermissions(test.in)
			if returned != test.out {
				t.Errorf("Expected: %v, Returned: %v.", test.out, returned)
			}
		})
	}
}

func TestManageCASLIB(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, `{"count": 1}`)
	}))
	defer server.Close()
	var TestCases = []struct {
		name string
		in   string
		out  bool
	}{
		{"validate", "Sample", true},
		{"lock", "Sample", true},
		{"test", "test", false},
	}
	for _, test := range TestCases {
		t.Run(test.name, func(t *testing.T) {
			viper.Set("baseurl", server.URL)
			viper.Set("cassession", "testsessionid")
			viper.Set("accesstoken", "testaccesstoken")
			returned := ManageCASLIB(test.name, test.in)
			if returned != test.out {
				t.Errorf("Expected: %v, Returned: %v.", test.out, returned)
			}
		})
	}
}
