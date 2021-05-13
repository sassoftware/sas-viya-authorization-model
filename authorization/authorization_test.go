// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	pr "github.com/sassoftware/sas-viya-authorization-model/principal"
)

func TestEnable(t *testing.T) {
	var actBody []byte
	expBody := []byte(`{"containerUri":"","description":"Automatically enabled by goViyaAuth","enabled":"true","objectUri":"testuri","permissions":["perm1","perm2"],"principal":"testgroup","principalType":"group","type":"grant"}`)
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		actBody, _ = ioutil.ReadAll(req.Body)
		if !reflect.DeepEqual(expBody, actBody) {
			t.Errorf("Expected: %v, Returned: %v.", string(expBody), string(actBody))
		}
	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	pr := new(pr.Principal)
	pr.Connection = co
	pr.ID = "testgroup"
	pr.Name = "Test Group"
	pr.Type = "group"
	pr.Exists = true
	a := new(Authorization)
	a.Permissions = []string{"perm1", "perm2"}
	a.Principal = pr
	a.Type = "grant"
	a.Enabled = "true"
	a.Description = "Automatically enabled by goViyaAuth"
	a.ObjectURI = "testuri"
	a.Enable()
}

func TestValidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"accept":"application/vnd.sas.authorization.rule+json","count":1,"items":[{"createdBy":"geladm","createdTimestamp":"2020-05-06T06:46:39.933Z","creationTimeStamp":"2020-05-06T06:46:39.933Z","description":"Automatically created by goViyaAuth","enabled":true,"id":"a9ce98d4-90be-4e98-8a05-752f190d5255","links":[{"href":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255","method":"GET","rel":"self","responseType":"application/vnd.sas.authorization.rule","uri":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255"},{"href":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255","method":"PUT","rel":"update","responseType":"application/vnd.sas.authorization.rule","type":"application/vnd.sas.authorization.rule","uri":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255"},{"href":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255","method":"DELETE","rel":"delete","uri":"/authorization/rules/a9ce98d4-90be-4e98-8a05-752f190d5255"}],"matchParams":false,"modifiedBy":"geladm","modifiedTimeStamp":"2020-05-06T06:46:39.933Z","modifiedTimestamp":"2020-05-06T06:46:39.933Z","objectUri":"/SASEnvironmentManager/dashboard","permissions":["delete","update","read"],"principal":"HRModelers","principalType":"group","type":"grant","version":10}],"limit":1000,"links":[{"href":"/authorization/rules?filter=and(eq(principal,'HRModelers'),startsWith(objectUri,'/SASEnvironmentManager/dashboard'))&start=0&limit=1000","method":"GET","rel":"self","type":"application/vnd.sas.collection","uri":"/authorization/rules?filter=and(eq(principal,'HRModelers'),startsWith(objectUri,'/SASEnvironmentManager/dashboard'))&start=0&limit=1000"},{"href":"/authorization/rules","method":"GET","rel":"collection","type":"application/vnd.sas.collection","uri":"/authorization/rules"}],"name":"rules","start":0,"version":2}`))

	}))
	defer server.Close()
	co := new(co.Connection)
	co.BaseURL = server.URL
	co.AccessToken = "testaccesstoken"
	co.Connected = true
	pr := new(pr.Principal)
	pr.Connection = co
	pr.ID = "testgroup"
	pr.Name = "Test Group"
	pr.Exists = true
	a := new(Authorization)
	a.Permissions = []string{"perm1", "perm2"}
	a.Principal = pr
	var TestCases = []struct {
		Name          string
		PrincipalType string
		ContainerURI  string
		ObjectURI     string
		EveryURI      bool
	}{
		{
			Name:          "GroupContainer",
			PrincipalType: "group",
			ContainerURI:  "testuri",
			ObjectURI:     "",
			EveryURI:      false,
		},
		{
			Name:          "GroupObject",
			PrincipalType: "group",
			ContainerURI:  "",
			ObjectURI:     "testuri",
			EveryURI:      false,
		},
		{
			Name:          "AUContainer",
			PrincipalType: "authentiatedUsers",
			ContainerURI:  "testuri",
			ObjectURI:     "",
			EveryURI:      false,
		},
		{
			Name:          "AUObject",
			PrincipalType: "authentiatedUsers",
			ContainerURI:  "",
			ObjectURI:     "testuri",
			EveryURI:      false,
		},
		{
			Name:          "AUEvery",
			PrincipalType: "authentiatedUsers",
			ContainerURI:  "",
			ObjectURI:     "",
			EveryURI:      true,
		},
	}
	for _, test := range TestCases {
		t.Run(test.Name, func(t *testing.T) {
			a.Principal.Type = test.PrincipalType
			a.ContainerURI = test.ContainerURI
			a.ObjectURI = test.ObjectURI
			a.EveryURI = test.EveryURI
			a.IDs = nil
			a.Validate()
			if !reflect.DeepEqual(a.IDs, []string{"a9ce98d4-90be-4e98-8a05-752f190d5255"}) {
				t.Errorf("Expected: %v, Returned: %v.", []string{"a9ce98d4-90be-4e98-8a05-752f190d5255"}, a.IDs)
			}
		})
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
	pr := new(pr.Principal)
	pr.Connection = co
	pr.ID = "testgroup"
	pr.Name = "Test Group"
	pr.Type = "group"
	pr.Exists = true
	a := new(Authorization)
	a.Permissions = []string{"perm1", "perm2"}
	a.Principal = pr
	a.IDs = []string{"a9ce98d4-90be-4e98-8a05-752f190d5255"}
	a.Delete()
	if a.IDs != nil {
		t.Errorf("Expected: %v, Returned: %v.", nil, a.IDs)
	}
}
