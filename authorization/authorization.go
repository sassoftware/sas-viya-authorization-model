// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"encoding/json"

	pr "github.com/sassoftware/sas-viya-authorization-model/principal"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Authorization object for SAS Viya endpoint
type Authorization struct {
	Condition           string
	ContainerURI        string
	ExpirationTimeStamp string
	Filter              string
	MediaType           string
	ObjectURI           string
	Permissions         []string
	Principal           *pr.Principal
	Reason              string
	Type                string
	Version             string
	Description         string
	Enabled             string
	MatchParams         string
	EveryURI            bool
	IDs                 []string
}

// Enable authorization rule
func (a *Authorization) Enable() {
	zap.S().Debugw("Enabling authorization rule", "containerUri", a.ContainerURI, "objectUri", a.ObjectURI)
	body, _ := json.Marshal(map[string]interface{}{
		"permissions":   a.Permissions,
		"principal":     a.Principal.ID,
		"principalType": a.Principal.Type,
		"type":          a.Type,
		"enabled":       a.Enabled,
		"description":   a.Description,
		"containerUri":  a.ContainerURI,
		"objectUri":     a.ObjectURI,
	})
	a.Principal.Connection.Call("POST", "/authorization/rules", "application/vnd.sas.authorization.rule+json", "", nil, body)
}

// Validate authorization rule
func (a *Authorization) Validate() {
	zap.S().Debugw("Validating authorization rule", "containerUri", a.ContainerURI, "objectUri", a.ObjectURI)
	var filter string
	if a.Principal.Type == "group" {
		if a.ContainerURI != "" {
			filter = "and(eq(principal,'" + a.Principal.ID + "'),eq(containerUri,'" + a.ContainerURI + "'))"
		} else if a.ObjectURI != "" {
			filter = "and(eq(principal,'" + a.Principal.ID + "'),eq(objectUri,'" + a.ObjectURI + "'))"
		} else {
			zap.S().Fatalw("Either a Container or Object URI needs to be provided", "ContainerURI", a.ContainerURI, "ObjectURI", a.ObjectURI)
		}
	} else {
		if a.ContainerURI != "" {
			filter = "and(eq(principalType,'" + a.Principal.Type + "'),eq(containerUri,'" + a.ContainerURI + "'))"
		} else if a.ObjectURI != "" {
			filter = "and(eq(principalType,'" + a.Principal.Type + "'),eq(objectUri,'" + a.ObjectURI + "'))"
		} else if a.EveryURI {
			filter = "eq(principalType,'" + a.Principal.Type + "')"
		} else {
			zap.S().Fatalw("Either a Container or Object URI needs to be provided", "ContainerURI", a.ContainerURI, "ObjectURI", a.ObjectURI)
		}
	}
	search, _ := a.Principal.Connection.Call("GET", "/authorization/rules", "", "", [][]string{
		0: {
			"filter",
			filter,
		},
		1: {
			"limit",
			viper.GetString("responselimit"),
		},
	}, nil)
	if search.(map[string]interface{})["count"] == "0" {
		zap.S().Debugw("Authorization rule does not exist")
		a.IDs = nil
	} else {
		for _, rule := range search.(map[string]interface{})["items"].([]interface{}) {
			var id string = rule.(map[string]interface{})["id"].(string)
			zap.S().Debugw("Authorization rule exists", "id", id)
			a.IDs = append(a.IDs, id)
		}
	}
}

// Delete authorization rule
func (a *Authorization) Delete() {
	for _, id := range a.IDs {
		zap.S().Debugw("Removing existing authorization rule", "id", id)
		a.Principal.Connection.Call("DELETE", "/authorization/rules/"+id, "", "", nil, nil)
	}
	a.IDs = nil
}
