// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cas

import (
	"encoding/json"

	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	pr "github.com/sassoftware/sas-viya-authorization-model/principal"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// LIB object
type LIB struct {
	Name        string
	Description string
	Path        string
	Scope       string
	Type        string
	ACL         []AC
	Exists      bool
	Connection  *co.Connection
}

// AC defines a CAS Access Control
type AC struct {
	Version     string
	Type        string
	Permissions []string
	Principal   *pr.Principal
	TableFilter string
}

// Create a global scope PATH or DNFS type CASLIB
func (cas *LIB) Create() {
	zap.S().Infow("Creating CASLIB", "name", cas.Name)
	body, _ := json.Marshal(map[string]interface{}{
		"description": cas.Description,
		"name":        cas.Name,
		"path":        cas.Path,
		"type":        cas.Type,
		"scope":       cas.Scope,
		"hidden":      false,
		"transient":   false,
	})
	cas.Connection.Call("POST", "/casManagement/servers/"+cas.Connection.CASServer+"/caslibs", "application/vnd.sas.cas.caslib+json", "application/vnd.sas.cas.caslib+json", nil, body)
}

// Validate whether a CASLIB exists
func (cas *LIB) Validate() {
	zap.S().Debugw("Validating CASLIB", "name", cas.Name)
	search, _ := cas.Connection.Call("GET", "/casManagement/servers/"+cas.Connection.CASServer+"/caslibs", "", "", [][]string{
		0: {
			"sessionId",
			cas.Connection.CASSession,
		},
		1: {
			"includeHidden",
			"true",
		},
		2: {
			"limit",
			viper.GetString("responselimit"),
		},
		3: {
			"filter",
			`eq("name","` + cas.Name + `")`,
		},
	}, nil)
	if search.(map[string]interface{})["count"].(float64) == 0 {
		zap.S().Debugw("CASLIB does not exist", "name", cas.Name)
		cas.Exists = false
	} else {
		zap.S().Debugw("CASLIB exists", "name", cas.Name)
		cas.Exists = true
	}
}

// lock a CASLIB for editing
func (cas *LIB) lock() {
	zap.S().Debugw("Locking CASLIB", "name", cas.Name)
	cas.Connection.Call("POST", "/casAccessManagement/servers/"+cas.Connection.CASServer+"/caslibControls/"+cas.Name+"/lock", "", "", [][]string{
		0: {
			"sessionId",
			cas.Connection.CASSession,
		},
	}, nil)
}

// startTransaction starts a CAS access control transaction
func (cas *LIB) startTransaction() {
	zap.S().Debugw("Starting CAS access control transaction")
	cas.Connection.Call("POST", "/casManagement/servers/"+cas.Connection.CASServer+"/sessions/"+cas.Connection.CASSession, "", "", [][]string{
		0: {
			"action",
			"start",
		},
	}, nil)
}

// commitTransaction commits a CAS access control transaction
func (cas *LIB) commitTransaction() {
	zap.S().Debugw("Committing CAS access control transaction")
	cas.Connection.Call("POST", "/casManagement/servers/"+cas.Connection.CASServer+"/sessions/"+cas.Connection.CASSession, "", "", [][]string{
		0: {
			"action",
			"commit",
		},
	}, nil)
}

// Apply a list of direct CAS Access Controls to a CASLIB while replacing all existing ACs
func (cas *LIB) Apply() {
	zap.S().Infow("Applying direct CAS access controls and replacing all existing", "CASLIB", cas.Name)
	cas.lock()
	cas.startTransaction()
	var body []map[string]string
	for _, ac := range cas.ACL {
		for _, perm := range ac.Permissions {
			add := make(map[string]string)
			add["type"] = ac.Type
			add["permission"] = perm
			add["identityType"] = ac.Principal.Type
			add["identity"] = ac.Principal.ID
			if ac.Version != "" {
				add["version"] = ac.Version
			}
			if ac.TableFilter != "" {
				add["tableFilter"] = ac.TableFilter
			}
			body = append(body, add)
		}
	}
	bodyJSON, _ := json.Marshal(body)
	cas.Connection.Call("PUT", "/casAccessManagement/servers/"+cas.Connection.CASServer+"/caslibControls/"+cas.Name, "application/vnd.sas.cas.access.controls+json", "", [][]string{
		0: {
			"sessionId",
			cas.Connection.CASSession,
		},
	}, bodyJSON)
	cas.commitTransaction()
}

// Remove a list of direct CAS Access Controls from a CASLIB. An empty ACL will remove all existing controls
func (cas *LIB) Remove() {
	zap.S().Infow("Removing specified existing direct CAS Access Controls", "CASLIB", cas.Name)
	cas.lock()
	cas.startTransaction()
	var body []map[string]string
	for _, ac := range cas.ACL {
		for _, perm := range ac.Permissions {
			add := make(map[string]string)
			add["type"] = ac.Type
			add["permission"] = perm
			add["identityType"] = ac.Principal.Type
			add["identity"] = ac.Principal.ID
			if ac.Version != "" {
				add["version"] = ac.Version
			}
			if ac.TableFilter != "" {
				add["tableFilter"] = ac.TableFilter
			}
			body = append(body, add)
		}
	}
	bodyJSON, _ := json.Marshal(body)
	cas.Connection.Call("DELETE", "/casAccessManagement/servers/"+cas.Connection.CASServer+"/caslibControls/"+cas.Name, "application/vnd.sas.cas.access.controls+json", "", [][]string{
		0: {
			"sessionId",
			cas.Connection.CASSession,
		},
	}, bodyJSON)
	cas.commitTransaction()
}
