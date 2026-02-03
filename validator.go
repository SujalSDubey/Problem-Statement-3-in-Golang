package main

import "errors"

func ValidateSpec(spec OpenAPISpec) error {
	if spec == nil {
		return errors.New("invalid OpenAPI structure")
	}

	if _, ok := spec["paths"]; !ok {
		return errors.New("missing 'paths' in OpenAPI spec")
	}
	// Check OpenAPI / Swagger version
	if openapi, ok := spec["openapi"]; ok {
		if s, ok := openapi.(string); !ok || s == "" {
			return errors.New("invalid OpenAPI version")
		}
		return nil
	}

	if swagger, ok := spec["swagger"]; ok {
		if swagger != "2.0" {
			return errors.New("unsupported Swagger version")
		}
		return nil
	}

	return errors.New("unsupported OpenAPI version")
}
