// SPDX-License-Identifier: MIT

//go:build schemagen

// Command schema generates a JSON Schema for the dizgin configuration file.
// Run: go run -tags schemagen ./cmd/schemagen > schema/dizgin.schema.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/sungurerdim/dizgin/internal/config"
)

func main() {
	r := &jsonschema.Reflector{
		AllowAdditionalProperties: false,
		// Use yaml struct tags for property names so the schema matches dizgin.yaml.
		Namer:    func(t reflect.Type) string { return t.Name() },
		KeyNamer: yamlKey,
	}

	schema := r.Reflect(&config.Config{})
	schema.Title = "dizgin Configuration"
	schema.Description = "Configuration schema for dizgin.yaml — platform-native sandbox wrapper for AI coding tools. " +
		"Add '# yaml-language-server: $schema=https://raw.githubusercontent.com/sungurerdim/dizgin/main/schema/dizgin.schema.json' " +
		"to the top of your dizgin.yaml for IDE autocomplete."

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(schema); err != nil {
		fmt.Fprintf(os.Stderr, "schema: encode: %v\n", err)
		os.Exit(1)
	}
}

// yamlKey returns the YAML field name for the given struct field name.
// It looks up the yaml struct tag and falls back to lowercase.
func yamlKey(key string) string {
	// Look up the yaml tag via reflection on the config types.
	if name := yamlTagFor(key); name != "" {
		return name
	}
	return strings.ToLower(key)
}

// yamlTagFor searches the config package structs for a field with the given
// Go name and returns its yaml tag value.
func yamlTagFor(fieldName string) string {
	types := []any{
		config.Config{},
		config.FilesystemConfig{},
		config.NetworkConfig{},
		config.SecurityConfig{},
		config.ResourceConfig{},
		config.PrivilegeConfig{},
		config.CredentialConfig{},
		config.AuditConfig{},
		config.ToolDef{},
	}
	for _, t := range types {
		rt := reflect.TypeOf(t)
		if f, ok := rt.FieldByName(fieldName); ok {
			tag := f.Tag.Get("yaml")
			if tag != "" && tag != "-" {
				// yaml tag may have options like "name,omitempty" — take only the name part.
				return strings.SplitN(tag, ",", 2)[0]
			}
		}
	}
	return ""
}
