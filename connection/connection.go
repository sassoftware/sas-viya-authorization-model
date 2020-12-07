// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package connection

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/sassoftware/sas-viya-authorization-model/file"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// Connection object to SAS Viya
type Connection struct {
	AccessToken string
	BaseURL     string
	CASSession  string
	CASServer   string
	Connected   bool
	Count       int64
}

// Connect to SAS Viya
func (c *Connection) Connect() {
	zap.S().Debugw("Connecting to SAS Viya")
	if !c.Connected {
		c.CASServer = viper.GetString("casserver")
		c.getBaseURL()
		c.getAccessToken()
		c.getCASSession()
		c.Connected = true
		zap.S().Debugw("Connected to SAS Viya")
	}
}

// Call the SAS Viya REST API
func (c *Connection) Call(method, path, contenttype, accepttype string, query [][]string, body []byte) (response interface{}, status int) {
	if contenttype == "" {
		contenttype = "application/json"
	}
	if accepttype == "" {
		accepttype = "application/json"
	}
	bodyReader := bytes.NewReader(body)
	zap.S().Debugw("Calling SAS Viya REST API")
	url, err := url.ParseRequestURI(c.BaseURL)
	if err != nil {
		zap.S().Fatalw("Error encoding Base URL", "baseurl", c.BaseURL, "error", err)
	}
	url.Path = path
	if query != nil {
		urlquery := url.Query()
		for i := 0; i <= len(query)-1; i++ {
			urlquery.Set(query[i][0], query[i][1])
		}
		url.RawQuery = urlquery.Encode()
	}
	var urlencode string = url.String()
	zap.S().Debugw("Encoded URL components", "urlencode", urlencode)
	req, err := http.NewRequest(method, urlencode, bodyReader)
	req.Close = true
	req.Header.Add("Authorization", "bearer "+c.AccessToken)
	req.Header.Add("Content-type", contenttype)
	req.Header.Add("Accept", accepttype)
	tr := &http.Transport{}
	if viper.GetString("validtls") == "false" {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	c.Count++
	if err != nil {
		zap.S().Fatalw("Error communicating with REST API", "error", err)
	}
	status = resp.StatusCode
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		zap.S().Warnw("Issue unmarshalling JSON response", "error", err)
	}
	defer resp.Body.Close()
	if (400 <= resp.StatusCode) && (resp.StatusCode <= 599) {
		zap.S().Warnw("Error code contained in REST response", "status", resp.StatusCode, "response", response)
	} else {
		zap.S().Debugw("Successful REST response", "status", resp.StatusCode, "response", response)
	}
	return
}

// Disconnect from SAS Viya
func (c *Connection) Disconnect() {
	zap.S().Debugw("Disconnecting from SAS Viya")
	if c.Connected {
		c.destroyCASSession()
		c.Connected = false
		zap.S().Debugw("Disconnected from SAS Viya", "Count", c.Count)
	}
}

// getBaseURL returns the user's saved SAS Viya environment base URL
func (c *Connection) getBaseURL() {
	if viper.GetString("baseurl") != "" {
		c.BaseURL = viper.GetString("baseurl")
	} else {
		zap.S().Debugw("Retrieving SAS Viya environment base URL")
		// config of SAS Viya connection
		type config struct {
			Profile struct {
				ClientID string `json:"oauth-client-id"`
				Endpoint string `json:"sas-endpoint"`
			} `json:"Default"`
		}
		var conf config
		f := new(file.File)
		f.Path = viper.GetString("home") + "/.sas/config.json"
		f.Content = conf
		f.Type = "json"
		f.Read()
		c.BaseURL = f.Content.(map[string]interface{})["Default"].(map[string]interface{})["sas-endpoint"].(string)
	}
	zap.S().Debugw("Retrieved SAS Viya environment base URL", "baseurl", c.BaseURL)
}

// getAccessToken either obtains a new or returns the user's existing OAuth Access Token
func (c *Connection) getAccessToken() {
	if viper.GetString("user") != "" && viper.GetString("pw") != "" && c.BaseURL != "" {
		zap.S().Debugw("Retrieving OAuth Access Token")
		config := &oauth2.Config{
			ClientID:     viper.GetString("clientid"),
			ClientSecret: viper.GetString("clientsecret"),
			Endpoint: oauth2.Endpoint{
				AuthURL:  c.BaseURL + "/SASLogon/oauth/authorize",
				TokenURL: c.BaseURL + "/SASLogon/oauth/token",
			},
		}
		tr := &http.Transport{}
		if viper.GetString("validtls") == "false" {
			tr = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: tr})
		token, err := config.PasswordCredentialsToken(ctx, viper.GetString("user"), viper.GetString("pw"))
		if err != nil {
			zap.S().Fatalw("OAuth Access Token cannot be acquired", "err", err)
		}
		c.AccessToken = token.AccessToken
	} else {
		zap.S().Debugw("Retrieving OAuth Access Token")
		// credential for OAuth authentication
		type credentials struct {
			Profile struct {
				AccessToken  string `json:"access-token"`
				Expiry       string `json:"expiry"`
				RefreshToken string `json:"refresh-token"`
			} `json:"Default"`
		}
		var cred credentials
		f := new(file.File)
		f.Path = viper.GetString("home") + "/.sas/credentials.json"
		f.Content = cred
		f.Type = "json"
		f.Read()
		expiry, _ := time.Parse(time.RFC3339, f.Content.(map[string]interface{})["Default"].(map[string]interface{})["expiry"].(string))
		if time.Now().After(expiry) {
			zap.S().Fatalw("OAuth Access Token expired. Please refresh using the 'sas-admin auth login' command", "expiry", expiry)
		}
		c.AccessToken = f.Content.(map[string]interface{})["Default"].(map[string]interface{})["access-token"].(string)
	}
	zap.S().Debugw("Retrieved OAuth Access Token")
}

// getCASSession creates a CAS Session
func (c *Connection) getCASSession() {
	zap.S().Debugw("Creating CAS session")
	resp, _ := c.Call("POST", "/casManagement/servers/"+c.CASServer+"/sessions", "", "", nil, nil)
	c.CASSession = resp.(map[string]interface{})["id"].(string)
	zap.S().Debugw("Elevating privileges for CAS session", "session", c.CASSession)
	c.Call("PUT", "/casAccessManagement/servers/"+c.CASServer+"/admUser/assumeRole/superUser", "", "", [][]string{{"sessionId", c.CASSession}}, nil)
	zap.S().Debugw("Created CAS session", "session", c.CASSession)
}

// destroyCASSession destroys a CAS Session
func (c *Connection) destroyCASSession() {
	zap.S().Debugw("Destroying CAS session", "session", c.CASSession)
	c.Call("DELETE", "/casManagement/servers/"+c.CASServer+"/sessions/"+c.CASSession, "", "", nil, nil)
}
