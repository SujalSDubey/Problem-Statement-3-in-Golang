package main
import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"gopkg.in/yaml.v3"
)

type OpenAPISpec map[string]interface{}

func ParseSpec(reader io.Reader, specText string) (OpenAPISpec, error) {
	var content []byte
	var err error
	// Case 1: File upload
	if reader != nil {
		content, err = io.ReadAll(reader)
		if err != nil {
			return nil, errors.New("unable to read uploaded file")
		}
	} else if strings.TrimSpace(specText) != "" {
		// Case 2: Raw text
		content = []byte(specText)
	} else {
		return nil, errors.New("no OpenAPI specification provided")
	}
	// YAML parser can also parse JSON
	var spec OpenAPISpec
	if err := yaml.Unmarshal(content, &spec); err == nil {
		return spec, nil
	}
	// Fallback: JSON
	if err := json.Unmarshal(content, &spec); err == nil {
		return spec, nil
	}
	return nil, errors.New("invalid OpenAPI spec: unable to parse YAML or JSON")
}