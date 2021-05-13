// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cas

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	pr "github.com/sassoftware/sas-viya-authorization-model/principal"
)

func TestValidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"count": 1}`))
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	cas := new(LIB)
	cas.Connection = co
	cas.Name = "testcaslib"
	cas.Validate()
	if !cas.Exists {
		t.Errorf("Expected: %v, Returned: %v.", true, cas.Exists)
	}
}

func TestLock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		expected := "/casAccessManagement/servers/default/caslibControls/testcaslib/lock?sessionId=testsession"
		if req.URL.String() != expected {
			t.Errorf("URL = %q; want %q", req.URL, expected)
		}
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.CASServer = "default"
	co.CASSession = "testsession"
	co.Connected = true
	cas := new(LIB)
	cas.Connection = co
	cas.Name = "testcaslib"
	cas.lock()
}

func TestStartTransaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		expected := "/casManagement/servers/default/sessions/testsession?action=start"
		if req.URL.String() != expected {
			t.Errorf("URL = %q; want %q", req.URL, expected)
		}
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.CASServer = "default"
	co.CASSession = "testsession"
	co.Connected = true
	cas := new(LIB)
	cas.Connection = co
	cas.startTransaction()
}

func TestCommitTransaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		expected := "/casManagement/servers/default/sessions/testsession?action=commit"
		if req.URL.String() != expected {
			t.Errorf("URL = %q; want %q", req.URL, expected)
		}
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.CASServer = "default"
	co.CASSession = "testsession"
	co.Connected = true
	cas := new(LIB)
	cas.Connection = co
	cas.commitTransaction()
}

func TestApply(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		if req.URL.String() == "/casAccessManagement/servers/default/caslibControls/testcaslib?sessionId=testsession" {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Errorf("Failed reading request body: %s.", err)
			}
			expected := `[{"identity":"testgroup","identityType":"group","permission":"readInfo","tableFilter":"testfilter","type":"grant","version":"0"},{"identity":"testgroup","identityType":"group","permission":"select","tableFilter":"testfilter","type":"grant","version":"0"},{"identity":"testgroup","identityType":"group","permission":"limitedPromote","tableFilter":"testfilter","type":"grant","version":"0"}]`
			if string(body) != expected {
				t.Errorf("res.Body = %q; want %q", string(body), expected)
			}
		} else if (req.URL.String() != "/casAccessManagement/servers/default/caslibControls/testcaslib/lock?sessionId=testsession") && (req.URL.String() != "/casManagement/servers/default/sessions/testsession?action=start") && (req.URL.String() != "/casManagement/servers/default/sessions/testsession?action=commit") {
			t.Errorf("Wrong URL: %s.", req.URL.String())
		}
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.CASServer = "default"
	co.CASSession = "testsession"
	co.Connected = true
	pr := new(pr.Principal)
	pr.Connection = co
	pr.ID = "testgroup"
	pr.Name = "Test Group"
	pr.Type = "group"
	var ac AC = AC{
		Version:   "0",
		Type:      "grant",
		Principal: pr,
		Permissions: []string{
			"readInfo",
			"select",
			"limitedPromote",
		},
		TableFilter: "testfilter",
	}
	cas := new(LIB)
	cas.Connection = co
	cas.Name = "testcaslib"
	cas.ACL = append(cas.ACL, ac)
	cas.Apply()
}

func TestRemove(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		if req.URL.String() == "/casAccessManagement/servers/default/caslibControls/testcaslib?sessionId=testsession" {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Errorf("Failed reading request body: %s.", err)
			}
			expected := `[{"identity":"testgroup","identityType":"group","permission":"readInfo","tableFilter":"testfilter","type":"grant","version":"0"},{"identity":"testgroup","identityType":"group","permission":"select","tableFilter":"testfilter","type":"grant","version":"0"},{"identity":"testgroup","identityType":"group","permission":"limitedPromote","tableFilter":"testfilter","type":"grant","version":"0"}]`
			if string(body) != expected {
				t.Errorf("res.Body = %q; want %q", string(body), expected)
			}
		} else if (req.URL.String() != "/casAccessManagement/servers/default/caslibControls/testcaslib/lock?sessionId=testsession") && (req.URL.String() != "/casManagement/servers/default/sessions/testsession?action=start") && (req.URL.String() != "/casManagement/servers/default/sessions/testsession?action=commit") {
			t.Errorf("Wrong URL: %s.", req.URL.String())
		}
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.CASServer = "default"
	co.CASSession = "testsession"
	co.Connected = true
	pr := new(pr.Principal)
	pr.Connection = co
	pr.ID = "testgroup"
	pr.Name = "Test Group"
	pr.Type = "group"
	var ac AC = AC{
		Version:   "0",
		Type:      "grant",
		Principal: pr,
		Permissions: []string{
			"readInfo",
			"select",
			"limitedPromote",
		},
		TableFilter: "testfilter",
	}
	cas := new(LIB)
	cas.Connection = co
	cas.Name = "testcaslib"
	cas.ACL = append(cas.ACL, ac)
	cas.Remove()
}

func TestCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		if req.URL.String() == "/casManagement/servers/default/caslibs" {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Errorf("Failed reading request body: %s.", err)
			}
			expected := `{"description":"testdescription","hidden":false,"name":"testcaslib","path":"/test/path","scope":"global","transient":false,"type":"PATH"}`
			if string(body) != expected {
				t.Errorf("res.Body = %q; want %q", string(body), expected)
			}
		} else {
			t.Errorf("Wrong URL: %s.", req.URL.String())
		}
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.CASServer = "default"
	co.CASSession = "testsession"
	co.Connected = true
	cas := new(LIB)
	cas.Connection = co
	cas.Name = "testcaslib"
	cas.Description = "testdescription"
	cas.Path = "/test/path"
	cas.Type = "PATH"
	cas.Scope = "global"
	cas.Create()
}
