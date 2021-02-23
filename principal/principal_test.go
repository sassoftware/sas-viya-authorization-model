// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package principal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	co "github.com/sassoftware/sas-viya-authorization-model/connection"
)

func TestCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	p := new(Principal)
	p.Connection = co
	p.ID = "testgroup"
	p.Name = "Test Group"
	p.Type = "group"
	p.Create()
}

func TestNest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	p1 := new(Principal)
	p1.ID = "parent1"
	p2 := new(Principal)
	p2.ID = "parent2"
	p := new(Principal)
	p.Connection = co
	p.ID = "testgroup"
	p.Name = "Test Group"
	p.Type = "group"
	p.Parents = append(p.Parents, p1)
	p.Parents = append(p.Parents, p2)
	p.Exists = true
	p.Nest()
	p.ID = "testuser"
	p.Name = "Test User"
	p.Type = "user"
	p.Nest()
}

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
	p := new(Principal)
	p.Connection = co
	p.ID = "testgroup"
	p.Name = "Test Group"
	p.Type = "group"
	p.Validate()
	if !p.Exists {
		t.Errorf("Expected: %v, Returned: %v.", true, p.Exists)
	}
}

func TestDelete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	p := new(Principal)
	p.Connection = co
	p.ID = "testgroup"
	p.Name = "Test Group"
	p.Type = "group"
	p.Exists = true
	p.Delete()
	if p.Exists {
		t.Errorf("Expected: %v, Returned: %v.", false, p.Exists)
	}
}

func TestGetMembers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"count": 2, "items": [{"id": "groupmember", "type": "group"}, {"id": "usermember", "type": "user"}]}`))
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	p := new(Principal)
	p.Connection = co
	p.ID = "testgroup"
	p.Name = "Test Group"
	p.Type = "group"
	p.Exists = true
	p.GetMembers()
	if p.Members == nil {
		t.Error("Expected array of members.")
	} else if p.Members[0].ID != "groupmember" {
		t.Errorf("Expected: %v, Returned: %v.", "groupmember", p.Members[0].ID)
	} else if p.Members[1].ID != "usermember" {
		t.Errorf("Expected: %v, Returned: %v.", "usermember", p.Members[0].ID)
	}
}

func TestDeleteMembers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	p := new(Principal)
	p.Connection = co
	p.ID = "testgroup"
	p.Name = "Test Group"
	p.Type = "group"
	p.Exists = true
	m := new(Principal)
	m.ID = "testmember1"
	m.Type = "group"
	p.Members = append(p.Members, m)
	m = new(Principal)
	m.ID = "testmember2"
	m.Type = "user"
	p.Members = append(p.Members, m)
	p.DeleteMembers()
	if p.Members != nil {
		t.Errorf("Expected: %v, Returned: %v.", nil, p.Members)
	}
}
