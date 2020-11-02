// Copyright © 2020, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// POSIX ownership and permissions
type POSIX struct {
	UID             int64
	GID             []int64
	OwnerPermission string
	GroupPermission []string
	OtherPermission string
	SetGID          bool
	StickyBit       bool
}

// ReadJSONFile opens the JSON file, unmarshalls the content, and returns it through the schema pointer
func ReadJSONFile(path string, schema interface{}) {
	zap.S().Debugw("Reading file", "path", path, "schema", schema)
	content, err := ioutil.ReadFile(path)
	if err != nil {
		zap.S().Fatalw("Error when reading file", "error", err)
	}
	err = json.Unmarshal([]byte(content), &schema)
	if err != nil {
		zap.S().Fatalw("Error when unmarshalling JSON file", "error", err)
	}
}

// ReadCSVFile opens the CSV file and returns a dict of its content
func ReadCSVFile(path string, schema []string) []map[string]string {
	zap.S().Debugw("Reading file", "path", path)
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		zap.S().Fatalw("Error when reading file", "error", err)
	}
	r := csv.NewReader(f)
	rows := []map[string]string{}
	var header []string
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			zap.S().Fatalw("Error when unmarshalling CSV file", "error", err)
		}
		if len(header) == 0 {
			for _, col := range record {
				clean, err := regexp.Compile("[^a-zA-Z0-9]+")
				if err != nil {
					zap.S().Errorw("Error compiling regular expression", "error", err)
				}
				header = append(header, clean.ReplaceAllString(col, ""))
			}
		} else if !reflect.DeepEqual(header, schema) {
			zap.S().Fatalw("Header row does not match expected schema", "header", header, "schema", schema)
		} else {
			dict := map[string]string{}
			for i := range header {
				dict[header[i]] = record[i]
			}
			rows = append(rows, dict)
		}
	}
	return rows
}

// StartLogging initializes a custom global logger
func StartLogging() {
	pe := zap.NewProductionEncoderConfig()
	fileEncoder := zapcore.NewJSONEncoder(pe)
	pe.EncodeTime = zapcore.ISO8601TimeEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(pe)
	level := zap.DebugLevel
	switch viper.GetString("loglevel") {
	case "DEBUG":
		level = zap.DebugLevel
	case "INFO":
		level = zap.InfoLevel
	case "WARN":
		level = zap.WarnLevel
	case "ERROR":
		level = zap.ErrorLevel
	case "FATAL":
		level = zap.FatalLevel
	}
	f, err := os.OpenFile(viper.GetString("logfile"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		zap.S().Fatalw("Error when reading file", "error", err)
	}
	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, zapcore.AddSync(f), level),
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), level),
	)
	l := zap.New(core)
	zap.ReplaceGlobals(l)
}

// CalculateFileMode calculates the octal file mode
func CalculateFileMode(owner, group, other string) (FileMode os.FileMode) {
	var perm string = ConvertNotation(owner) + ConvertNotation(group) + ConvertNotation(other)
	perm2, err := strconv.ParseInt(perm, 8, 32)
	if err != nil {
		zap.S().Errorw("Error calculating file mode", "error", err, "perm", perm)
	}
	FileMode = os.FileMode(perm2)
	zap.S().Debugw("Calculated file mode", "FileMode", FileMode)
	return
}

// ManagePOSIXPermissions applies the POSIX permissions to the directory
func ManagePOSIXPermissions(path string, permissions POSIX) (success bool) {
	zap.S().Infow("Applying POSIX permissions", "path", path, "permissions", permissions)
	if ManagePOSIXFolders("validate", path, permissions) {
		if len(permissions.GID) == 1 && len(permissions.GroupPermission) == 1 {
			FileMode := CalculateFileMode(permissions.OwnerPermission, permissions.GroupPermission[0], permissions.OtherPermission)
			err := os.Chown(path, int(permissions.UID), int(permissions.GID[0]))
			if err != nil {
				zap.S().Errorw("Error changing directory ownership", "error", err, "path", path, "UID", permissions.UID, "GID", permissions.GID)
			} else {
				zap.S().Debugw("Changed directory ownership", "path", path, "UID", permissions.UID, "GID", permissions.GID)
				success = true
			}
			err = os.Chmod(path, FileMode)
			if err != nil {
				zap.S().Errorw("Error changing directory permissions", "error", err, "path", path, "FileMode", FileMode)
			} else {
				zap.S().Debugw("Changed directory permissions", "path", path, "FileMode", FileMode)
				success = true
			}
			if permissions.SetGID && !permissions.StickyBit {
				err = os.Chmod(path, FileMode|os.ModeSetgid)
				if err != nil {
					zap.S().Errorw("Error setting GID", "error", err, "path", path, "mode", FileMode|os.ModeSetgid)
				} else {
					zap.S().Debugw("Set GID", "path", path, "mode", FileMode|os.ModeSetgid)
					success = true
				}
			} else if !permissions.SetGID && permissions.StickyBit {
				err = os.Chmod(path, FileMode|os.ModeSticky)
				if err != nil {
					zap.S().Errorw("Error setting sticky bit", "error", err, "path", path, "mode", FileMode|os.ModeSticky)
				} else {
					zap.S().Debugw("Set sticky bit", "path", path, "mode", FileMode|os.ModeSticky)
					success = true
				}
			} else if permissions.SetGID && permissions.StickyBit {
				err = os.Chmod(path, FileMode|os.ModeSetgid|os.ModeSticky)
				if err != nil {
					zap.S().Errorw("Error simultaneously setting sticky bit & GID", "error", err, "path", path, "mode", FileMode|os.ModeSetgid|os.ModeSticky)
				} else {
					zap.S().Debugw("Set GID & sticky bit", "path", path, "mode", FileMode|os.ModeSetgid|os.ModeSticky)
					success = true
				}
			}
		} else if len(permissions.GID) > 1 && len(permissions.GID) == len(permissions.GroupPermission) {
			if runtime.GOOS == "linux" {
				zap.S().Debugw("Applying directory POSIX ACLs")
				type Command struct {
					name string
					args []string
				}
				var commands []Command
				// Start with directory owner permissions - assumed to be first entry in Group Permissions
				commands = append(commands, Command{"setfacl", []string{"--set", fmt.Sprintf("u::%s,g::%s,o:%s", permissions.OwnerPermission, permissions.GroupPermission[0], permissions.OtherPermission), path}})
				// Add inherited (default) owner permissions - assumed to be first entry in GIDs
				commands = append(commands, Command{"setfacl", []string{"-m", fmt.Sprintf("d:u::%s,d:g::%s,d:o:%s", permissions.OwnerPermission, permissions.GroupPermission[0], permissions.OtherPermission), path}})
				// Set directory ownership
				commands = append(commands, Command{"chown", []string{"-R", fmt.Sprintf("%d:%d", permissions.UID, permissions.GID[0]), path}})
				// For each additional GID add an ACL entry. Sequence of GIDs and Group Permissions need to be identical
				for i := 1; i < len(permissions.GID); i++ {
					commands = append(commands, Command{"setfacl", []string{"-m", fmt.Sprintf("g:%d:%s", permissions.GID[i], permissions.GroupPermission[i]), path}})
					commands = append(commands, Command{"setfacl", []string{"-m", fmt.Sprintf("d:g:%d:%s", permissions.GID[i], permissions.GroupPermission[i]), path}})
				}
				// Log final ACL
				commands = append(commands, Command{"getfacl", []string{path}})
				for _, command := range commands {
					osCmd := exec.Command(command.name, command.args...)
					var out, stderr bytes.Buffer
					osCmd.Stdout = &out
					osCmd.Stderr = &stderr
					zap.S().Debugw("Executing OS command", "name", command.name, "arguments", command.args)
					err := osCmd.Run()
					if err != nil {
						zap.S().Errorw("OS command execution returned an error", "err", err, "Stderr", stderr.String())
					} else {
						if out.String() != "" {
							zap.S().Debugw(out.String())
						}
						success = true
					}
				}
			} else {
				zap.S().Errorw("Multiple group permissions are currently only supported on Linux Operating Systems")
			}
		} else {
			zap.S().Errorw("Cannot apply POSIX permissions as there is a mismatch of UID, GID, and expected permissions", "permissions", permissions)
		}
	} else {
		zap.S().Errorw("Cannot apply POSIX permissions as directory does not exist", "path", path)
	}
	return
}

// ManagePOSIXFolders validates, creates, or deletes POSIX folders
func ManagePOSIXFolders(mode, path string, permissions POSIX) (success bool) {
	switch mode {
	case "validate":
		zap.S().Debugw("Validating POSIX folder", "path", path)
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			zap.S().Debugw("POSIX folder does not exist", "path", path)
		} else {
			zap.S().Debugw("POSIX folder exists", "path", path)
			success = true
		}
	case "create":
		zap.S().Debugw("Creating POSIX folder", "path", path, "permissions", permissions)
		if !ManagePOSIXFolders("validate", path, permissions) {
			err := os.MkdirAll(path, CalculateFileMode(permissions.OwnerPermission, permissions.GroupPermission[0], permissions.OtherPermission))
			if err != nil {
				zap.S().Errorw("Error creating new directory path", "path", path, "error", err)
			} else {
				zap.S().Infow("Created new directory path", "path", path)
				success = true
			}
		} else {
			zap.S().Debugw("Directory path already exists", "path", path)
			success = true
		}
	case "delete":
		zap.S().Debugw("Deleting POSIX folder", "path", path, "permissions", permissions)
		err := os.Remove(path)
		if err != nil {
			zap.S().Errorw("Error deleting directory", "path", path, "error", err)
		} else {
			zap.S().Infow("Successfully deleted directory", "path", path)
			success = true
		}
	case "deleteRecursive":
		zap.S().Debugw("Recursively deleting POSIX folder", "path", path, "permissions", permissions)
		err := os.RemoveAll(path)
		if err != nil {
			zap.S().Errorw("Error recursively deleting directory", "path", path, "error", err)
		} else {
			zap.S().Infow("Successfully recursively deleted directory", "path", path)
			success = true
		}
	}
	return
}

// ConvertNotation converts symbolic POSIX permission notation to numeric (octal)
func ConvertNotation(symbolic string) (numeric string) {
	if len(symbolic) == 3 {
		var num int64 = 0
		perm := strings.SplitAfter(symbolic, "")
		if perm[0] != "-" {
			num = num + 4
		}
		if perm[1] != "-" {
			num = num + 2
		}
		if perm[2] != "-" {
			num = num + 1
		}
		numeric = strconv.FormatInt(num, 10)
	}
	zap.S().Debugw("Converted POSIX permission notation", "symbolic", symbolic, "numeric", numeric)
	return
}

// ConvertKV converts a Key-Value struct into a JSON object
func ConvertKV(in []KV) (out []byte) {
	var tmp2 map[string]interface{}
	tmp2 = make(map[string]interface{})
	for _, pair := range in {
		switch pair.V.(type) {
		case string:
			tmp2[pair.K] = pair.V.(string)
		case []string:
			tmp2[pair.K] = pair.V.([]string)
		case bool:
			tmp2[pair.K] = pair.V.(bool)
		case int:
			tmp2[pair.K] = pair.V.(int)
		}
	}
	out, _ = json.Marshal(tmp2)
	zap.S().Debugw("Converted Key-Value struct into a JSON object", "out", string(out))
	return
}

// LookupID looks up the name of a user or group and returns the UID or GID
func LookupID(name string, isuser bool) (id int64) {
	if isuser {
		lookup, err := user.Lookup(name)
		if err != nil {
			zap.S().Errorw("User lookup failed", "name", name, "isuser", isuser, "err", err)
		}
		id, err = strconv.ParseInt(lookup.Uid, 10, 32)
		if err != nil {
			zap.S().Errorw("UID parsing failed", "name", name, "isuser", isuser, "uid", lookup.Uid, "err", err)
		}
	} else {
		lookup, err := user.LookupGroup(name)
		if err != nil {
			zap.S().Errorw("Group lookup failed", "name", name, "isuser", isuser, "err", err)
		}
		id, err = strconv.ParseInt(lookup.Gid, 10, 32)
		if err != nil {
			zap.S().Errorw("GID parsing failed", "name", name, "isuser", isuser, "gid", lookup.Gid, "err", err)
		}
	}
	zap.S().Debugw("Lookup of name to ID completed", "name", name, "isuser", isuser, "id", id)
	return
}

// JoinMaps joins a left and right map based on a selected key and join operation
func JoinMaps(left, right []map[string]string, key, join string) (result []map[string]string) {
	var count int
	switch join {
	case "inner":
		for _, rowLeft := range left {
			for _, rowRight := range right {
				if rowRight[key] == rowLeft[key] {
					tmp := map[string]string{}
					for k, v := range rowLeft {
						tmp[k] = v
					}
					for k, v := range rowRight {
						tmp[k] = v
					}
					result = append(result, tmp)
					count++
				}
			}
		}
		zap.S().Debugw("Joined Maps", "key", key, "join", join, "count", count)
	}
	return
}

// ReverseMap reverses the map by index
func ReverseMap(in []map[string]string) (out []map[string]string) {
	for i := len(in) - 1; i >= 0; i-- {
		out = append(out, in[i])
	}
	zap.S().Debugw("Reversed Map")
	return
}

// AssertString ensures that an interface variable can be handled as type string
func AssertString(variable interface{}) (asserted string) {
	switch assertedVariable := variable.(type) {
	case nil:
		asserted = "nil"
	case int:
		asserted = strconv.Itoa(assertedVariable)
	case int64:
		asserted = strconv.FormatInt(assertedVariable, 10)
	case bool:
		asserted = strconv.FormatBool(assertedVariable)
	case string:
		asserted = assertedVariable
	case float64:
		asserted = strconv.FormatFloat(assertedVariable, 'f', -1, 64)
	default:
		zap.S().Fatalw("Cannot assert unknown type to string")
	}
	return asserted
}
