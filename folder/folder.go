// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package folder

import (
	"strings"

	au "github.com/sassoftware/sas-viya-authorization-model/authorization"
	co "github.com/sassoftware/sas-viya-authorization-model/connection"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Folder object
type Folder struct {
	Path          string
	URI           string
	Parent        *Folder
	Authorization []*au.Authorization
	Exists        bool
	Connection    *co.Connection
}

// Validate whether a SAS Viya custom folder exists
func (f *Folder) Validate() {
	zap.S().Debugw("Validating custom folder", "path", f.Path)
	search, status := f.Connection.Call("GET", "/folders/folders/@item", "", "", [][]string{
		0: {
			"path",
			f.Path,
		},
		1: {
			"limit",
			viper.GetString("responselimit"),
		},
	}, nil)
	if status == 404 {
		zap.S().Debugw("Custom folder does not exist", "path", f.Path)
		f.Exists = false
	} else {
		zap.S().Debugw("Custom folder exists", "path", f.Path)
		f.Exists = true
		f.URI = "/folders/folders/" + search.(map[string]interface{})["id"].(string)
	}
}

// Create a SAS Viya custom folder if it does not already exist and nest if required
func (f *Folder) Create() {
	if (!f.Exists) && (f.URI == "") {
		zap.S().Infow("Creating custom folder as it does not exist", "path", f.Path)
		var pathElements []string = strings.Split(f.Path, "/")
		var folderName string = pathElements[len(pathElements)-1]
		var response interface{}
		if len(pathElements) < 3 {
			response, _ = f.Connection.Call("POST", "/folders/folders", "", "", [][]string{
				0: {
					"parentFolderUri",
					"none",
				},
				1: {
					"limit",
					viper.GetString("responselimit"),
				}}, []byte(`{"name": "`+folderName+`", "type": "folder"}`))
			f.Exists = true
		} else if f.Parent != nil {
			response, _ = f.Connection.Call("POST", "/folders/folders", "", "", [][]string{
				0: {
					"parentFolderUri",
					f.Parent.URI,
				},
				1: {
					"limit",
					viper.GetString("responselimit"),
				}}, []byte(`{"name": "`+folderName+`", "type": "folder"}`))
			f.Exists = true
		} else {
			zap.S().Errorw("Parent folder must exist first", "path", f.Path)
		}
		if response != nil {
			f.URI = "/folders/folders/" + response.(map[string]interface{})["id"].(string)
		}
	} else {
		zap.S().Debugw("Cannot create custom folder as it already exists", "path", f.Path)
	}
}

// Delete a SAS Viya custom folder if it exists
func (f *Folder) Delete() {
	if (f.Exists) && (f.URI != "") {
		zap.S().Infow("Deleting custom folder", "path", f.Path, "uri", f.URI)
		f.Connection.Call("DELETE", f.URI, "", "", nil, nil)
		f.Exists = false
	} else {
		zap.S().Debugw("Cannot delete custom folder as it does not exist", "path", f.Path)
	}
}

// DeleteRecursive recursively deletes a SAS Viya custom folder path if it exists
func (f *Folder) DeleteRecursive() {
	if (f.Exists) && (f.URI != "") {
		zap.S().Infow("Recursively deleting custom folder", "path", f.Path, "uri", f.URI)
		f.Connection.Call("DELETE", f.URI, "", "", [][]string{
			0: {
				"recursive",
				"true",
			},
		}, nil)
		f.Exists = false
	} else {
		zap.S().Debugw("Cannot recursively delete custom folder as it does not exist", "path", f.Path)
	}
}
