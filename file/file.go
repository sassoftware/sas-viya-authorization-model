// Copyright © 2021, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"reflect"
	"regexp"

	"go.uber.org/zap"
)

// File object
type File struct {
	Path    string
	Type    string
	Schema  []string
	Content interface{}
}

// Read file
func (f *File) Read() {
	zap.S().Debugw("Reading file", "path", f.Path, "type", f.Type)
	switch f.Type {
	case "csv":
		f.readCSV()
	case "json":
		f.readJSON()
	default:
		zap.S().Fatalw("Unsupported file type")
	}
}

// readJSON opens the JSON file and returns the content
func (f *File) readJSON() {
	osf, err := os.OpenFile(f.Path, os.O_RDONLY, 0644)
	if err != nil {
		zap.S().Fatalw("Error when reading file", "error", err)
	}
	err = json.NewDecoder(osf).Decode(&f.Content)
	if err != nil {
		zap.S().Fatalw("Error when unmarshalling JSON file", "error", err)
	}
}

// readCSV opens the CSV file and returns the content
func (f *File) readCSV() {
	osf, err := os.OpenFile(f.Path, os.O_RDONLY, 0644)
	if err != nil {
		zap.S().Fatalw("Error when reading file", "error", err)
	}
	f.Content, err = csv.NewReader(osf).ReadAll()
	if err != nil {
		zap.S().Fatalw("Error when unmarshalling CSV file", "error", err)
	}
	if !f.checkHeader() {
		zap.S().Fatalw("Header row does not match expected schema", "header", f.Content.([][]string)[0], "schema", f.Schema)
	}
}

// checkHeader validates the file header against the provided schema
func (f *File) checkHeader() bool {
	var header []string
	for _, col := range f.Content.([][]string)[0] {
		clean, err := regexp.Compile("[^a-zA-Z0-9]+")
		if err != nil {
			zap.S().Errorw("Error compiling regular expression", "error", err)
		}
		header = append(header, clean.ReplaceAllString(col, ""))
	}
	if reflect.DeepEqual(header, f.Schema) {
		return true
	} else {
		return false
	}
}
