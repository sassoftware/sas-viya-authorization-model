// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package principal

import (
	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Principal object
type Principal struct {
	ID          string
	Type        string
	Parents     []*Principal
	Members     []*Principal
	Name        string
	Description string
	State       string
	Exists      bool
	Connection  *co.Connection
}

// Create a SAS Viya principal if it does not already exist and nest if required
func (p *Principal) Create() {
	if !p.Exists && p.Type == "group" {
		zap.S().Infow("Creating custom group", "id", p.ID, "name", p.Name)
		if p.Description == "" {
			p.Description = "Automatically created by goViyaAuth"
		}
		if p.State == "" {
			p.State = "active"
		}
		if p.Name == "" {
			p.Name = p.ID
		}
		p.Connection.Call("POST", "/identities/groups", "application/vnd.sas.identity.group+json", "", nil, []byte(`{"id": "`+p.ID+`", "name": "`+p.Name+`", "description": "`+p.Description+`"}`))
		if p.Parents != nil {
			for _, parent := range p.Parents {
				zap.S().Infow("Nesting custom group", "id", p.ID, "parentid", parent.ID)
				p.Connection.Call("PUT", "/identities/groups/"+parent.ID+"/groupMembers/"+p.ID, "", "", nil, nil)
			}
		}
		p.Exists = true
	} else if p.Type == "user" && p.Parents != nil {
		for _, parent := range p.Parents {
			zap.S().Infow("Nesting user", "groupID", parent.ID, "userID", p.ID)
			p.Connection.Call("PUT", "/identities/groups/"+parent.ID+"/userMembers/"+p.ID, "", "", nil, nil)
		}
	}
}

// Validate whether a SAS Viya principal exists
func (p *Principal) Validate() {
	if p.Type == "group" {
		zap.S().Debugw("Validating custom group", "id", p.ID)
		search, _ := p.Connection.Call("GET", "/identities/groups", "", "", [][]string{
			0: {
				"filter",
				"eq(id,'" + p.ID + "')",
			},
			1: {
				"limit",
				viper.GetString("responselimit"),
			},
		}, nil)
		if search.(map[string]interface{})["count"].(float64) == 0 {
			zap.S().Debugw("Custom group does not exist", "id", p.ID)
			p.Exists = false
		} else {
			zap.S().Debugw("Custom group exists", "id", p.ID)
			p.Exists = true
		}
	}
}

// Delete a SAS Viya principal
func (p *Principal) Delete() {
	if p.ID != "SASAdministrators" && p.Type == "group" {
		zap.S().Infow("Deleting custom group", "id", p.ID)
		p.Connection.Call("DELETE", "/identities/groups/"+p.ID, "", "", nil, nil)
		p.Exists = false
	}
}

// GetMembers of a SAS Viya principal
func (p *Principal) GetMembers() {
	if p.Type == "group" {
		search, _ := p.Connection.Call("GET", "/identities/groups/"+p.ID+"/members", "", "", [][]string{
			0: {
				"showDuplicates",
				"true",
			},
			1: {
				"limit",
				viper.GetString("responselimit"),
			},
			2: {
				"depth",
				"-1",
			},
		}, nil)
		if search.(map[string]interface{})["count"] == "0" {
			zap.S().Debugw("Custom group does not have any members", "id", p.ID)
			p.Members = nil
		} else {
			for _, member := range search.(map[string]interface{})["items"].([]interface{}) {
				m := new(Principal)
				m.ID = member.(map[string]interface{})["id"].(string)
				m.Type = member.(map[string]interface{})["type"].(string)
				p.Members = append(p.Members, m)
			}
		}
	}
}

// DeleteMembers of a SAS Viya principal
func (p *Principal) DeleteMembers() {
	if p.ID != "SASAdministrators" && p.Type == "group" && p.Members != nil {
		for _, member := range p.Members {
			if member.Type == "group" {
				zap.S().Infow("Deleting group membership", "id", p.ID, "memberID", member.ID)
				p.Connection.Call("DELETE", "/identities/groups/"+p.ID+"/groupMembers/"+member.ID, "", "", nil, nil)
			} else if member.Type == "user" {
				zap.S().Infow("Deleting group membership", "id", p.ID, "memberID", member.ID)
				p.Connection.Call("DELETE", "/identities/groups/"+p.ID+"/userMembers/"+member.ID, "", "", nil, nil)
			}
		}
		p.Members = nil
	}
}
