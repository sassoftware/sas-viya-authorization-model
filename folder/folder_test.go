// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package folder

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	co "github.com/sassoftware/sas-viya-authorization-model/connection"
)

func TestValidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"count": 1, "id": "testid"}`))
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	fo := new(Folder)
	fo.Connection = co
	fo.Path = "/testfolder"
	fo.Validate()
	if !fo.Exists {
		t.Errorf("Expected: %v, Returned: %v.", true, fo.Exists)
	}
}

func TestDelete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		expected := "/folders/folders/testuri"
		if req.URL.String() != expected {
			t.Errorf("URL = %q; want %q", req.URL, expected)
		}
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	fo := new(Folder)
	fo.Connection = co
	fo.URI = "/folders/folders/testuri"
	fo.Exists = true
	fo.Delete()
}

func TestDeleteRecursive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		expected := "/folders/folders/testuri?recursive=true"
		if req.URL.String() != expected {
			t.Errorf("URL = %q; want %q", req.URL, expected)
		}
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	fo := new(Folder)
	fo.Connection = co
	fo.URI = "/folders/folders/testuri"
	fo.Exists = true
	fo.DeleteRecursive()
}

func TestCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		if req.URL.String() == "/folders/folders?limit=&parentFolderUri=none" {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Errorf("Failed reading request body: %s.", err)
			}
			expected := `{"name": "testfolder", "type": "folder"}`
			if string(body) != expected {
				t.Errorf("res.Body = %q; want %q", string(body), expected)
			}
		} else if req.URL.String() == "/folders/folders?limit=&parentFolderUri=testuri" {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Errorf("Failed reading request body: %s.", err)
			}
			expected := `{"name": "subfolder", "type": "folder"}`
			if string(body) != expected {
				t.Errorf("res.Body = %q; want %q", string(body), expected)
			}
		} else {
			t.Errorf("Wrong URL: %s.", req.URL.String())
		}
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"id": "testid"}`))
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	fo := new(Folder)
	fo.Connection = co
	fo.Path = "/testfolder"
	fo.Create()
	fo.Exists = true
	fo.URI = "testuri"
	fo2 := new(Folder)
	fo2.Parent = fo
	fo2.Connection = co
	fo2.Path = "/testfolder/subfolder"
	fo2.Create()
	if fo2.URI != "/folders/folders/testid" {
		t.Errorf("URI = %q; want %q", fo2.URI, "/folders/folders/testid")
	}
}
