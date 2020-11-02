// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// Credential for OAuth authentication
type Credential struct {
	Profile struct {
		AccessToken  string `json:"access-token"`
		Expiry       string `json:"expiry"`
		RefreshToken string `json:"refresh-token"`
	} `json:"Default"`
}

// Config of SAS Viya connection
type Config struct {
	Profile struct {
		ClientID string `json:"oauth-client-id"`
		Endpoint string `json:"sas-endpoint"`
	} `json:"Default"`
}

// KV for generic Key-Value pairs
type KV struct {
	K string
	V interface{}
}

// APICall of REST API
type APICall struct {
	Host        string
	Port        string
	Verb        string
	Path        string
	ContentType string
	AcceptType  string
	Body        []byte
	Query       []KV
}

// AuthorizationRule for SAS Viya endpoint
type AuthorizationRule struct {
	Condition           string
	ContainerURI        string
	ExpirationTimeStamp string
	Filter              string
	MediaType           string
	ObjectURI           string
	Permissions         []string
	Principal           string
	PrincipalType       string
	Reason              string
	Type                string
	Version             string
	Description         string
	Enabled             string
	MatchParams         string
	EveryURI            bool
}

// AccessControl for CAS
type AccessControl struct {
	CASLIB      string
	CASTable    string
	Description string
	Action      string
	CASACL      []CASACL
}

// CASACL defines a CAS Access Control List
type CASACL struct {
	Version      int    `json:"version,omitempty"`
	Type         string `json:"type,omitempty"`
	Permission   string `json:"permission,omitempty"`
	IdentityType string `json:"identityType,omitempty"`
	Identity     string `json:"identity,omitempty"`
	TableFilter  string `json:"tableFilter,omitempty"`
}

// GetAccessToken either obtains or returns the user's saved OAuth Access Token
func GetAccessToken() (accessToken string) {
	if viper.GetString("user") != "" && viper.GetString("pw") != "" {
		config := &oauth2.Config{
			ClientID:     viper.GetString("clientid"),
			ClientSecret: viper.GetString("clientsecret"),
			Endpoint: oauth2.Endpoint{
				AuthURL:  viper.GetString("baseurl") + "/SASLogon/oauth/authorize",
				TokenURL: viper.GetString("baseurl") + "/SASLogon/oauth/token",
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
		accessToken = token.AccessToken
	} else {
		var credentialPath string = viper.GetString("home") + "/.sas/credentials.json"
		zap.S().Debugw("Retrieving OAuth Access Token", "credentialPath", credentialPath)
		var cred Credential
		ReadJSONFile(credentialPath, &cred)
		expiry, _ := time.Parse(time.RFC3339, cred.Profile.Expiry)
		if time.Now().After(expiry) {
			zap.S().Fatalw("OAuth Access Token expired. Please refresh using the 'sas-admin auth login' command", "expiry", expiry)
		}
		accessToken = cred.Profile.AccessToken
	}
	return
}

// GetBaseURL returns the user's saved SAS Viya environment base URL
func GetBaseURL() string {
	var configPath string = viper.GetString("home") + "/.sas/config.json"
	zap.S().Debugw("Retrieving SAS Viya environment base URL", "configPath", configPath)
	var conf Config
	ReadJSONFile(configPath, &conf)
	return conf.Profile.Endpoint
}

// GetCASSession creates a CAS Session and returns the session ID
func GetCASSession() string {
	zap.S().Debugw("Creating CAS session")
	call := APICall{
		Verb: "POST",
		Path: "/casManagement/servers/" + viper.GetString("casserver") + "/sessions",
	}
	resp, _ := CallViya(call)
	var session string = AssertString(resp.(map[string]interface{})["id"])
	zap.S().Debugw("Elevating privileges for CAS session", "session", session)
	call = APICall{
		Verb: "PUT",
		Path: "/casAccessManagement/servers/" + viper.GetString("casserver") + "/admUser/assumeRole/superUser",
		Query: []KV{
			{"sessionId", session},
		},
	}
	resp, _ = CallViya(call)
	return session
}

// DestroyCASSession destroys a given CAS Session
func DestroyCASSession(session string) {
	zap.S().Debugw("Destroying CAS session", "session", session)
	call := APICall{
		Verb: "DELETE",
		Path: "/casManagement/servers/" + viper.GetString("casserver") + "/sessions/" + session,
	}
	CallViya(call)
}

// ValidateCASSession validates a given CAS Session
func ValidateCASSession(session string) (exists bool) {
	zap.S().Debugw("Validating CAS session", "session", session)
	call := APICall{
		Verb: "GET",
		Path: "/casManagement/servers/" + viper.GetString("casserver") + "/sessions/" + session,
	}
	search, _ := CallViya(call)
	if search != nil {
		if id := AssertString(search.(map[string]interface{})["id"]); id != "" {
			zap.S().Debugw("CAS session exists", "session", id)
			exists = true
		} else {
			zap.S().Debugw("CAS session does not exist", "session", session)
		}
	}
	return
}

// ManageSession validates, creates, or destroys a SAS Viya and/or CAS session
func ManageSession(mode string) (exists bool) {
	switch mode {
	case "create":
		zap.S().Debugw("Creating SAS session")
		if viper.GetString("baseurl") == "" {
			viper.Set("baseurl", GetBaseURL())
		}
		viper.Set("accesstoken", GetAccessToken())
		viper.Set("cassession", GetCASSession())
		exists = ValidateCASSession(viper.GetString("cassession"))
	case "destroy":
		zap.S().Debugw("Destroying SAS session")
		DestroyCASSession(viper.GetString("cassession"))
	case "validate":
		exists = ValidateCASSession(viper.GetString("cassession"))
	}
	return
}

// CallViya interacts with the SAS Viya REST API
func CallViya(call APICall) (response interface{}, status int) {
	var baseurl, verb, path, contenttype, accepttype string
	if call.Host == "" || call.Port == "" {
		baseurl = viper.GetString("baseurl")
	} else {
		baseurl = call.Host + ":" + call.Port
	}
	verb = call.Verb
	path = call.Path
	if call.ContentType != "" {
		contenttype = call.ContentType
	} else {
		contenttype = "application/json"
	}
	if call.AcceptType != "" {
		accepttype = call.AcceptType
	} else {
		accepttype = "application/json"
	}
	query := call.Query
	bodyReader := bytes.NewReader(call.Body)
	zap.S().Debugw("Calling SAS Viya REST API", "verb", verb, "baseurl", baseurl, "path", path, "contenttype", contenttype, "accepttype", accepttype)
	url, err := url.ParseRequestURI(baseurl)
	if err != nil {
		zap.S().Fatalw("Error encoding Base URL", "baseurl", baseurl, "error", err)
	}
	url.Path = path
	if query != nil {
		urlquery := url.Query()
		for i := 0; i <= len(query)-1; i++ {
			urlquery.Set(query[i].K, query[i].V.(string))
		}
		url.RawQuery = urlquery.Encode()
	}
	var urlencode string = url.String()
	zap.S().Debugw("Encoded URL components", "urlencode", urlencode)
	req, err := http.NewRequest(verb, urlencode, bodyReader)
	req.Header.Add("Authorization", "bearer "+viper.GetString("accesstoken"))
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
	if err != nil {
		zap.S().Fatalw("Error communicating with REST API", "error", err)
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		zap.S().Debugw("Issue unmarshalling JSON response", "error", err)
	}
	status = resp.StatusCode
	defer resp.Body.Close()
	if (400 <= status) && (status <= 599) {
		zap.S().Debugw("Error code contained in REST response", "status", status, "response", response)
	} else {
		zap.S().Debugw("Successful REST response", "status", status, "response", response)
	}
	return
}

// ManageGroup validates, creates, or deletes SAS Viya custom groups
func ManageGroup(mode, id, name, parentid string) (success bool) {
	switch mode {
	case "validate":
		zap.S().Debugw("Validating custom group", "id", id)
		call := APICall{
			Verb: "GET",
			Path: "/identities/groups",
			Query: []KV{
				{"filter", "eq(id,'" + id + "')"},
				{"limit", viper.GetString("responselimit")},
			},
		}
		search, _ := CallViya(call)
		var count string = AssertString(search.(map[string]interface{})["count"])
		if count == "0" {
			zap.S().Debugw("Custom group does not exist", "id", id)
			success = false
		} else {
			zap.S().Debugw("Custom group exists", "id", id)
			success = true
		}
	case "create":
		if !ManageGroup("validate", id, "", "") {
			zap.S().Infow("Creating custom group", "id", id, "name", name)
			call := APICall{
				Verb: "POST",
				Path: "/identities/groups/",
				Body: ConvertKV([]KV{
					{"id", id},
					{"name", name},
					{"description", "Automatically created by goViyaAuth"},
					{"state", "active"},
				}),
			}
			CallViya(call)
			success = ManageGroup("validate", id, "", "")
		} else {
			success = true
		}
		if parentid != "" {
			if ManageGroup("validate", parentid, "", "") {
				zap.S().Infow("Nesting custom group", "id", id, "parentid", parentid)
				call := APICall{
					Verb: "PUT",
					Path: "/identities/groups/" + parentid + "/groupMembers/" + id,
				}
				CallViya(call)
			} else {
				zap.S().Errorw("Parent Group ID does not exist, cannot nest custom group", "id", id, "parentid", parentid)
			}
		}
	case "delete":
		if id != "SASAdministrators" {
			if ManageGroup("validate", id, "", "") {
				zap.S().Infow("Deleting custom group", "id", id)
				call := APICall{
					Verb: "DELETE",
					Path: "/identities/groups/" + id,
				}
				_, status := CallViya(call)
				if status <= 399 {
					success = true
				}
			} else {
				success = true
			}
		}
	case "deleteMembers":
		if id != "SASAdministrators" {
			if ManageGroup("validate", id, "", "") {
				zap.S().Infow("Deleting members from custom group", "id", id)
				call := APICall{
					Verb: "GET",
					Path: "/identities/groups/" + id + "/members",
					Query: []KV{
						{"limit", viper.GetString("responselimit")},
						{"showDuplicates", "true"},
						{"depth", "-1"},
					},
				}
				search, _ := CallViya(call)
				var count string = AssertString(search.(map[string]interface{})["count"])
				if count == "0" {
					zap.S().Debugw("Custom group does not have any members", "id", id)
					success = true
				} else {
					for _, item := range search.(map[string]interface{})["items"].([]interface{}) {
						var memberID string = AssertString(item.(map[string]interface{})["id"])
						var memberType string = AssertString(item.(map[string]interface{})["type"])
						if memberType == "group" {
							zap.S().Infow("Deleting group membership", "id", id, "memberID", memberID)
							call = APICall{
								Verb: "DELETE",
								Path: "/identities/groups/" + id + "/groupMembers/" + memberID,
							}
							CallViya(call)
							success = true
						} else if memberType == "user" {
							zap.S().Infow("Deleting group membership", "id", id, "memberID", memberID)
							call = APICall{
								Verb: "DELETE",
								Path: "/identities/groups/" + id + "/userMembers/" + memberID,
							}
							CallViya(call)
							success = true
						}
					}
				}
			} else {
				success = true
			}
		}
	}
	return
}

// ManageFolder validates, creates, or deletes SAS Viya custom folders
func ManageFolder(mode, path string) (uri string) {
	switch mode {
	case "validate":
		zap.S().Debugw("Validating custom folder", "path", path)
		call := APICall{
			Verb: "GET",
			Path: "/folders/folders/@item",
			Query: []KV{
				{"path", path},
				{"limit", viper.GetString("responselimit")},
			},
		}
		search, status := CallViya(call)
		if status <= 399 {
			id := AssertString(search.(map[string]interface{})["id"])
			uri = "/folders/folders/" + id
			zap.S().Debugw("Custom folder exists", "path", path, "uri", uri)
		} else {
			zap.S().Debugw("Custom folder does not exist", "path", path)
			uri = ""
		}
	case "create":
		uri = ManageFolder("validate", path)
		if uri != "" {
			zap.S().Debugw("Custom folder not created as it already exists", "path", path, "uri", uri)
		} else {
			var parents []string = strings.Split(path, "/")
			var parentpath, parenturi string
			var depth int = len(parents)
			if depth < 3 {
				parenturi = "none"
			} else {
				for i := 1; i <= depth-2; i++ {
					parentpath = parentpath + "/" + parents[i]
				}
				parenturi = ManageFolder("create", parentpath)
			}
			zap.S().Infow("Creating custom folder as it does not exist", "path", path)
			call := APICall{
				Verb: "POST",
				Path: "/folders/folders/",
				Query: []KV{
					{"parentFolderUri", parenturi},
					{"limit", viper.GetString("responselimit")},
				},
				Body: ConvertKV([]KV{
					{"name", parents[depth-1]},
					{"type", "folder"},
				}),
			}
			CallViya(call)
			uri = ManageFolder("validate", path)
		}
	case "delete":
		uri = ManageFolder("validate", path)
		if uri != "" {
			zap.S().Infow("Deleting custom folder", "path", path, "uri", uri)
			call := APICall{
				Verb: "DELETE",
				Path: uri,
			}
			CallViya(call)
		} else {
			zap.S().Debugw("Cannot delete custom folder as it does not exist", "path", path)
		}
	case "deleteRecursive":
		uri = ManageFolder("validate", path)
		if uri != "" {
			zap.S().Infow("Recursively deleting custom folder", "path", path, "uri", uri)
			call := APICall{
				Verb: "DELETE",
				Path: uri,
				Query: []KV{
					{"recursive", "true"},
				},
			}
			CallViya(call)
		} else {
			zap.S().Warnw("Cannot recursively delete custom folder as it does not exist", "path", path)
		}
	}
	return
}

// AssertViyaPermissions asserts (i.e. applies or removes) SAS Viya authorization rules to match those defined in "rule"
func AssertViyaPermissions(rule AuthorizationRule) (success bool) {
	zap.S().Debugw("Asserting SAS Viya permissions", "rule", rule)
	var filter string
	body := []KV{
		{"permissions", rule.Permissions},
		{"principal", rule.Principal},
		{"principalType", rule.PrincipalType},
		{"type", rule.Type},
		{"enabled", rule.Enabled},
		{"description", rule.Description},
	}
	if rule.PrincipalType == "group" {
		if rule.ContainerURI != "" {
			filter = "and(eq(principal,'" + rule.Principal + "'),eq(containerUri,'" + rule.ContainerURI + "'))"
		} else if rule.ObjectURI != "" {
			filter = "and(eq(principal,'" + rule.Principal + "'),eq(objectUri,'" + rule.ObjectURI + "'))"
		} else {
			zap.S().Fatalw("Either a Container or Object URI needs to be provided", "ContainerURI", rule.ContainerURI, "ObjectURI", rule.ObjectURI)
		}
	} else {
		if rule.ContainerURI != "" {
			filter = "and(eq(principalType,'" + rule.PrincipalType + "'),eq(containerUri,'" + rule.ContainerURI + "'))"
		} else if rule.ObjectURI != "" {
			filter = "and(eq(principalType,'" + rule.PrincipalType + "'),eq(objectUri,'" + rule.ObjectURI + "'))"
		} else if rule.EveryURI {
			filter = "eq(principalType,'" + rule.PrincipalType + "')"
		} else {
			zap.S().Fatalw("Either a Container or Object URI needs to be provided", "ContainerURI", rule.ContainerURI, "ObjectURI", rule.ObjectURI)
		}
	}
	if rule.ContainerURI != "" {
		body = append(body, KV{
			"containerUri", rule.ContainerURI,
		})
	} else {
		body = append(body, KV{
			"objectUri", rule.ObjectURI,
		})
	}
	call1 := APICall{
		Verb: "GET",
		Path: "/authorization/rules",
		Query: []KV{
			{"filter", filter},
			{"limit", viper.GetString("responselimit")},
		},
	}
	search, _ := CallViya(call1)
	var count string = AssertString(search.(map[string]interface{})["count"])
	if count == "0" {
		zap.S().Debugw("Authorization rule does not exist")
	} else {
		zap.S().Debugw("Authorization rule exists", "count", count)
		if items, ok := search.(map[string]interface{})["items"].([]interface{}); ok {
			for _, item := range items {
				var id string = AssertString(item.(map[string]interface{})["id"])
				zap.S().Infow("Removing existing authorization rule", "id", id)
				call2 := APICall{
					Verb: "DELETE",
					Path: "/authorization/rules/" + id,
				}
				CallViya(call2)
			}
		} else {
			zap.S().Errorw("No items returned")
		}
	}
	if rule.Enabled == "true" {
		call3 := APICall{
			Verb:        "POST",
			Path:        "/authorization/rules",
			ContentType: "application/vnd.sas.authorization.rule+json",
			Body:        ConvertKV(body),
		}
		_, status := CallViya(call3)
		if status <= 399 {
			zap.S().Infow("Successfully created authorization rule", "rule", rule)
			success = true
		} else {
			zap.S().Errorw("Error creating authorization rule", "rule", rule)
		}
	}
	return
}

// ManageCASLIB validates, locks, or unlocks a CASLIB
func ManageCASLIB(mode, name string) (success bool) {
	switch mode {
	case "validate":
		zap.S().Debugw("Validating CASLIB", "name", name)
		call := APICall{
			Verb: "GET",
			Path: "/casManagement/servers/" + viper.GetString("casserver") + "/caslibs",
			Query: []KV{
				{"sessionId", viper.GetString("cassession")},
				{"includeHidden", "true"},
				{"limit", viper.GetString("responselimit")},
				{"filter", `eq("name","` + name + `")`},
			},
		}
		search, _ := CallViya(call)
		var count string = AssertString(search.(map[string]interface{})["count"])
		if count == "0" {
			zap.S().Debugw("CASLIB does not exist in current scope")
			success = false
		} else {
			zap.S().Debugw("CASLIB exists in current scope", "count", count)
			success = true
		}
	case "lock":
		zap.S().Debugw("Locking CASLIB", "name", name)
		call := APICall{
			Verb: "POST",
			Path: "/casAccessManagement/servers/" + viper.GetString("casserver") + "/caslibControls/" + name + "/lock",
			Query: []KV{
				{"sessionId", viper.GetString("cassession")},
			},
		}
		_, status := CallViya(call)
		if status <= 399 {
			success = true
		}
	}
	return success
}

// AssertCASPermissions asserts (i.e. applies or removes) direct CAS access controls to match those defined in "acs"
func AssertCASPermissions(acs AccessControl) (success bool) {
	zap.S().Debugw("Asserting CAS access controls", "acs", acs)
	if ManageCASLIB("validate", acs.CASLIB) {
		success = ManageCASLIB("lock", acs.CASLIB)
		zap.S().Debugw("Starting CAS access control transaction")
		call := APICall{
			Verb: "POST",
			Path: "/casManagement/servers/" + viper.GetString("casserver") + "/sessions/" + viper.GetString("cassession"),
			Query: []KV{
				{"action", "start"},
			},
		}
		_, status := CallViya(call)
		if status >= 400 {
			success = false
		}
		if acs.Action == "" || acs.Action == "apply" {
			zap.S().Infow("Applying direct CAS access controls and replacing all existing", "CASLIB", acs.CASLIB, "CASACL", acs.CASACL)
			body, _ := json.Marshal(acs.CASACL)
			call = APICall{
				Verb: "PUT",
				Path: "/casAccessManagement/servers/" + viper.GetString("casserver") + "/caslibControls/" + acs.CASLIB,
				Query: []KV{
					{"sessionId", viper.GetString("cassession")},
				},
				Body:        body,
				ContentType: "application/vnd.sas.cas.access.controls+json",
			}
			_, status = CallViya(call)
			if status >= 400 {
				success = false
			}
		} else if acs.Action == "remove" {
			zap.S().Infow("Removing specified existing direct CAS access controls", "CASLIB", acs.CASLIB, "CASACL", acs.CASACL)
			body, _ := json.Marshal(acs.CASACL)
			call = APICall{
				Verb: "DELETE",
				Path: "/casAccessManagement/servers/" + viper.GetString("casserver") + "/caslibControls/" + acs.CASLIB,
				Query: []KV{
					{"sessionId", viper.GetString("cassession")},
				},
				Body:        body,
				ContentType: "application/vnd.sas.cas.access.controls+json",
			}
			_, status = CallViya(call)
			if status >= 400 {
				success = false
			}
		} else if acs.Action == "removeAll" {
			zap.S().Infow("Removing all existing direct CAS access controls", "CASLIB", acs.CASLIB)
			body, _ := json.Marshal([]CASACL{})
			call = APICall{
				Verb: "DELETE",
				Path: "/casAccessManagement/servers/" + viper.GetString("casserver") + "/caslibControls/" + acs.CASLIB,
				Query: []KV{
					{"sessionId", viper.GetString("cassession")},
				},
				Body:        body,
				ContentType: "application/vnd.sas.cas.access.controls+json",
			}
			_, status = CallViya(call)
			if status >= 400 {
				success = false
			}
		}
		zap.S().Debugw("Committing CAS access control transaction")
		call = APICall{
			Verb: "POST",
			Path: "/casManagement/servers/" + viper.GetString("casserver") + "/sessions/" + viper.GetString("cassession"),
			Query: []KV{
				{"action", "commit"},
			},
		}
		_, status = CallViya(call)
		if status >= 400 {
			success = false
		}
	}
	return
}
