// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package connection

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/viper"
)

func TestGetBaseURL1(t *testing.T) {
	var expected string = "http://0.0.0.0"
	viper.Set("baseurl", expected)
	c := new(Connection)
	c.getBaseURL()
	var returned string = c.BaseURL
	if returned != expected {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
	viper.Set("baseurl", "")
}

func TestGetBaseURL2(t *testing.T) {
	viper.Set("home", "test")
	viper.Set("profile", "Default")
	write := []byte(`{"Default": {"ansi-colors-enabled": "true", "oauth-client-id": "sas.cli", "output": "json", "sas-endpoint": "http://1.1.1.1"}}`)
	var expected string = "http://1.1.1.1"
	os.MkdirAll("test/.sas/", os.ModePerm)
	ioutil.WriteFile("test/.sas/config.json", write, 0644)
	c := new(Connection)
	c.getBaseURL()
	var returned string = c.BaseURL
	if returned != expected {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
	os.RemoveAll("test")
	viper.Set("home", "")
}

func TestGetBaseURL3(t *testing.T) {
	viper.Set("home", "test")
	viper.Set("profile", "prod")
	write := []byte(`{"Default": {"ansi-colors-enabled": "true", "oauth-client-id": "sas.cli", "output": "json", "sas-endpoint": "http://1.1.1.1"}, "prod": {"ansi-colors-enabled": "true", "oauth-client-id": "sas.cli", "output": "json", "sas-endpoint": "http://2.2.2.2"}}`)
	var expected string = "http://2.2.2.2"
	os.MkdirAll("test/.sas/", os.ModePerm)
	ioutil.WriteFile("test/.sas/config.json", write, 0644)
	c := new(Connection)
	c.getBaseURL()
	var returned string = c.BaseURL
	if returned != expected {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
	os.RemoveAll("test")
	viper.Set("profile", "Default")
	viper.Set("home", "")
}

func TestGetAccessToken1(t *testing.T) {
	viper.Set("user", "user1")
	viper.Set("pw", "password1")
	viper.Set("validtls", "false")
	c := new(Connection)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		expected := "/SASLogon/oauth/token"
		if r.URL.String() != expected {
			t.Errorf("URL = %q; want %q", r.URL, expected)
		}
		headerAuth := r.Header.Get("Authorization")
		expected = "Basic Og=="
		if headerAuth != expected {
			t.Errorf("Authorization header = %q; want %q", headerAuth, expected)
		}
		headerContentType := r.Header.Get("Content-Type")
		expected = "application/x-www-form-urlencoded"
		if headerContentType != expected {
			t.Errorf("Content-Type header = %q; want %q", headerContentType, expected)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		expected = "grant_type=password&password=password1&username=user1"
		if string(body) != expected {
			t.Errorf("res.Body = %q; want %q", string(body), expected)
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	}))
	defer ts.Close()
	c.BaseURL = ts.URL
	c.getAccessToken()
	var returned string = c.AccessToken
	var expected string = "90d64460d14870c08c81352a05dedd3465940a7c"
	if returned != expected {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
	viper.Set("user", "")
	viper.Set("pw", "")
	viper.Set("validtls", "")
}

func TestGetAccessToken2(t *testing.T) {
	viper.Set("home", "test")
	viper.Set("profile", "Default")
	write := []byte(`{"Default": {"access-token": "testaccesstoken", "expiry": "9999-12-31T07:05:41Z", "refresh-token": "testrefreshtoken"}}`)
	var expected string = "testaccesstoken"
	os.MkdirAll("test/.sas/", os.ModePerm)
	ioutil.WriteFile("test/.sas/credentials.json", write, 0644)
	c := new(Connection)
	c.getAccessToken()
	var returned string = c.AccessToken
	if returned != expected {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
	os.RemoveAll("test")
	viper.Set("home", "")
}

func TestGetAccessToken3(t *testing.T) {
	viper.Set("home", "test")
	viper.Set("profile", "prod")
	write := []byte(`{"Default": {"access-token": "testaccesstoken", "expiry": "9999-12-31T07:05:41Z", "refresh-token": "testrefreshtoken"},"prod": {"access-token": "prodaccesstoken", "expiry": "9999-12-31T07:05:41Z", "refresh-token": "testrefreshtoken"}}`)
	var expected string = "prodaccesstoken"
	os.MkdirAll("test/.sas/", os.ModePerm)
	ioutil.WriteFile("test/.sas/credentials.json", write, 0644)
	c := new(Connection)
	c.getAccessToken()
	var returned string = c.AccessToken
	if returned != expected {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
	os.RemoveAll("test")
	viper.Set("home", "")
	viper.Set("profile", "Default")
}

func TestGetCASSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"id": "testsessionid"}`))
	}))
	defer server.Close()
	viper.Set("casserver", "test")
	viper.Set("validtls", "false")
	c := new(Connection)
	c.BaseURL = server.URL
	c.AccessToken = "testaccesstoken"
	c.getCASSession()
	var returned string = c.CASSession
	var expected string = "testsessionid"
	if returned != expected {
		t.Errorf("Expected: %v, Returned: %v.", expected, returned)
	}
}

func TestDestroyCASSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
	}))
	defer server.Close()
	viper.Set("casserver", "test")
	viper.Set("validtls", "false")
	c := new(Connection)
	c.BaseURL = server.URL
	c.AccessToken = "testaccesstoken"
	c.destroyCASSession()
}

func TestConnect(t *testing.T) {
	viper.Set("home", "test")
	write := []byte(`{"Default": {"access-token": "testaccesstoken", "expiry": "9999-12-31T07:05:41Z", "refresh-token": "testrefreshtoken"}}`)
	os.MkdirAll("test/.sas/", os.ModePerm)
	ioutil.WriteFile("test/.sas/credentials.json", write, 0644)
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"id": "testsessionid"}`))
	}))
	write = []byte(`{"Default": {"ansi-colors-enabled": "true", "oauth-client-id": "sas.cli", "output": "json", "sas-endpoint": "` + server.URL + `"}}`)
	ioutil.WriteFile("test/.sas/config.json", write, 0644)
	c := new(Connection)
	c.Connect()
	if !c.Connected {
		t.Errorf("Expected: %v, Returned: %v.", true, c.Connected)
	}
	os.RemoveAll("test")
	viper.Set("home", "")
}

func TestDisconnect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
	}))
	defer server.Close()
	viper.Set("casserver", "test")
	viper.Set("validtls", "false")
	c := new(Connection)
	c.Connected = true
	c.BaseURL = server.URL
	c.AccessToken = "testaccesstoken"
	c.Disconnect()
	if c.Connected {
		t.Errorf("Expected: %v, Returned: %v.", false, c.Connected)
	}
}
