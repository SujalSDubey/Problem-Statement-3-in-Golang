package main

import (
	"fmt"
	"strings"
)

func CheckSEC001NoGlobalSecurity(spec OpenAPISpec) []Finding {
	var findings []Finding

	_, isV2 := spec["swagger"]
	_, isV3 := spec["openapi"]

	_, hasGlobalSecurity := spec["security"]

	hasDefinitions := false
	if isV2 {
		_, hasDefinitions = spec["securityDefinitions"]
	} else if isV3 {
		if components, ok := spec["components"].(map[string]interface{}); ok {
			_, hasDefinitions = components["securitySchemes"]
		}
	}

	if !hasGlobalSecurity && !hasDefinitions {
		findings = append(findings, CreateFinding(
			"SEC001",
			"Critical",
			"No global security definition found in OpenAPI specification",
			"root",
			"Define global security schemes and apply them at the root level",
		))
	}

	return findings
}
func CheckSEC002UnprotectedEndpoints(spec OpenAPISpec) []Finding {
	var findings []Finding

	globalSecurity, hasGlobal := spec["security"]

	paths, _ := spec["paths"].(map[string]interface{})

	for path, methodsRaw := range paths {
		methods, ok := methodsRaw.(map[string]interface{})
		if !ok {
			continue
		}

		for method, detailsRaw := range methods {
			if strings.HasPrefix(method, "x-") {
				continue
			}

			details, ok := detailsRaw.(map[string]interface{})
			if !ok {
				continue
			}

			_, hasOperationSecurity := details["security"]

			if !hasGlobal || globalSecurity == nil {
				if !hasOperationSecurity {
					findings = append(findings, CreateFinding(
						"SEC002",
						"High",
						"Endpoint has no security requirements defined",
						fmt.Sprintf("paths.%s.%s.security", path, method),
						"Apply authentication using global or operation-level security",
					))
				}
			}
		}
	}

	return findings
}
func CheckSEC003HTTPAllowed(spec OpenAPISpec) []Finding {
	var findings []Finding

	// OpenAPI v3
	if _, ok := spec["openapi"]; ok {
		servers, _ := spec["servers"].([]interface{})
		for i, s := range servers {
			server, ok := s.(map[string]interface{})
			if !ok {
				continue
			}

			url, _ := server["url"].(string)
			if strings.HasPrefix(url, "http://") {
				findings = append(findings, CreateFinding(
					"SEC003",
					"High",
					"Insecure HTTP protocol allowed in server URL",
					fmt.Sprintf("servers[%d].url", i),
					"Use HTTPS instead of HTTP for all server URLs",
				))
			}
		}
	}

	// OpenAPI v2
	if swagger, ok := spec["swagger"]; ok && swagger == "2.0" {
		schemes, _ := spec["schemes"].([]interface{})
		for _, s := range schemes {
			if s == "http" {
				findings = append(findings, CreateFinding(
					"SEC003",
					"High",
					"Insecure HTTP protocol allowed in schemes",
					"schemes",
					"Remove HTTP and enforce HTTPS only",
				))
				break
			}
		}
	}

	return findings
}
func CheckSEC004NoRateLimitHeaders(spec OpenAPISpec) []Finding {
	var findings []Finding

	paths, _ := spec["paths"].(map[string]interface{})

	for path, methodsRaw := range paths {
		methods, ok := methodsRaw.(map[string]interface{})
		if !ok {
			continue
		}

		for method, detailsRaw := range methods {
			if strings.HasPrefix(method, "x-") {
				continue
			}

			details, ok := detailsRaw.(map[string]interface{})
			if !ok {
				continue
			}

			responses, _ := details["responses"].(map[string]interface{})
			rateLimitFound := false

			for _, respRaw := range responses {
				resp, ok := respRaw.(map[string]interface{})
				if !ok {
					continue
				}

				headers, _ := resp["headers"].(map[string]interface{})
				for header := range headers {
					if strings.HasPrefix(strings.ToLower(header), "x-ratelimit") {
						rateLimitFound = true
						break
					}
				}
			}

			if !rateLimitFound {
				findings = append(findings, CreateFinding(
					"SEC004",
					"Medium",
					"No rate limiting headers defined in responses",
					fmt.Sprintf("paths.%s.%s.responses", path, method),
					"Include X-RateLimit-* headers to indicate API rate limits",
				))
			}
		}
	}

	return findings
}
func CheckSEC005SensitiveQueryParams(spec OpenAPISpec) []Finding {
	var findings []Finding

	sensitive := []string{"password", "token", "secret", "api_key", "apikey", "auth"}

	paths, _ := spec["paths"].(map[string]interface{})

	for path, methodsRaw := range paths {
		methods, ok := methodsRaw.(map[string]interface{})
		if !ok {
			continue
		}

		for method, detailsRaw := range methods {
			if strings.HasPrefix(method, "x-") {
				continue
			}

			details, ok := detailsRaw.(map[string]interface{})
			if !ok {
				continue
			}

			params, _ := details["parameters"].([]interface{})
			for _, p := range params {
				param, ok := p.(map[string]interface{})
				if !ok {
					continue
				}

				if param["in"] == "query" {
					name, _ := param["name"].(string)
					lower := strings.ToLower(name)
					for _, k := range sensitive {
						if strings.Contains(lower, k) {
							findings = append(findings, CreateFinding(
								"SEC005",
								"Medium",
								"Sensitive data exposed in query parameter",
								fmt.Sprintf("paths.%s.%s.parameters.%s", path, method, name),
								"Avoid using sensitive data in query parameters; use headers or request body instead",
							))
							break
						}
					}
				}
			}
		}
	}
	return findings
}
func CheckSEC006MissingErrorResponses(spec OpenAPISpec) []Finding {
	var findings []Finding
	required := map[string]bool{"401": true, "403": true, "429": true}
	paths, _ := spec["paths"].(map[string]interface{})
	for path, methodsRaw := range paths {
		methods, ok := methodsRaw.(map[string]interface{})
		if !ok {
			continue
		}
		for method, detailsRaw := range methods {
			if strings.HasPrefix(method, "x-") {
				continue
			}

			details, ok := detailsRaw.(map[string]interface{})
			if !ok {
				continue
			}
			responses, _ := details["responses"].(map[string]interface{})
			missing := false

			for code := range required {
				if _, ok := responses[code]; !ok {
					missing = true
					break
				}
			}

			if missing {
				findings = append(findings, CreateFinding(
					"SEC006",
					"Medium",
					"Missing standard error response definitions (401, 403, 429)",
					fmt.Sprintf("paths.%s.%s.responses", path, method),
					"Define 401, 403, and 429 error responses for better security and API resilience",
				))
			}
		}
	}

	return findings
}
func CheckSEC007MissingSecurityContact(spec OpenAPISpec) []Finding {
	var findings []Finding

	info, _ := spec["info"].(map[string]interface{})

	_, hasContact := info["contact"]
	_, hasSecurityContact := info["x-security-contact"]

	if !hasContact && !hasSecurityContact {
		findings = append(findings, CreateFinding(
			"SEC007",
			"Low",
			"No contact or security contact information provided",
			"info",
			"Add info.contact or x-security-contact for vulnerability reporting",
		))
	}

	return findings
}
func CheckSEC008DeprecatedWithoutSunset(spec OpenAPISpec) []Finding {
	var findings []Finding

	paths, _ := spec["paths"].(map[string]interface{})

	for path, methodsRaw := range paths {
		methods, ok := methodsRaw.(map[string]interface{})
		if !ok {
			continue
		}

		for method, detailsRaw := range methods {
			if strings.HasPrefix(method, "x-") {
				continue
			}

			details, ok := detailsRaw.(map[string]interface{})
			if !ok {
				continue
			}

			if deprecated, ok := details["deprecated"].(bool); ok && deprecated {
				if _, ok := details["sunset"]; !ok {
					if _, ok := details["x-sunset"]; !ok {
						if _, ok := details["x-deprecation-date"]; !ok {
							findings = append(findings, CreateFinding(
								"SEC008",
								"Low",
								"Deprecated endpoint does not specify sunset or removal information",
								fmt.Sprintf("paths.%s.%s", path, method),
								"Add sunset or deprecation timeline information for deprecated endpoints",
							))
						}
					}
				}
			}
		}
	}

	return findings
}
func CheckSEC009WildcardServerURL(spec OpenAPISpec) []Finding {
	var findings []Finding

	if _, ok := spec["openapi"]; !ok {
		return findings
	}

	servers, _ := spec["servers"].([]interface{})

	for i, s := range servers {
		server, ok := s.(map[string]interface{})
		if !ok {
			continue
		}

		url, _ := server["url"].(string)
		vars, hasVars := server["variables"].(map[string]interface{})

		hasWildcard := strings.Contains(url, "*")
		hasTemplate := strings.Contains(url, "{") && strings.Contains(url, "}")

		if (hasWildcard || hasTemplate) && !hasVars {
			findings = append(findings, CreateFinding(
				"SEC009",
				"High",
				"Server URL contains wildcard or templated host without variable constraints",
				fmt.Sprintf("servers[%d].url", i),
				"Avoid wildcards or define server variables with enum constraints",
			))
			continue
		}

		if hasTemplate && hasVars {
			for name, v := range vars {
				variable, ok := v.(map[string]interface{})
				if !ok {
					continue
				}

				if _, ok := variable["enum"]; !ok {
					findings = append(findings, CreateFinding(
						"SEC009",
						"High",
						"Server URL contains templated host without enum constraints",
						fmt.Sprintf("servers[%d].variables.%s", i, name),
						"Constrain server variables using enum values",
					))
					break
				}
			}
		}
	}

	return findings
}
func CheckSEC010NoInputValidation(spec OpenAPISpec) []Finding {
	var findings []Finding

	validationKeys := map[string]bool{
		"minLength": true,
		"maxLength": true,
		"minimum":   true,
		"maximum":   true,
		"pattern":   true,
		"enum":      true,
	}

	paths, _ := spec["paths"].(map[string]interface{})

	for path, methodsRaw := range paths {
		methods, ok := methodsRaw.(map[string]interface{})
		if !ok {
			continue
		}

		for method, detailsRaw := range methods {
			if strings.HasPrefix(method, "x-") {
				continue
			}

			details, ok := detailsRaw.(map[string]interface{})
			if !ok {
				continue
			}

			// Parameters
			params, _ := details["parameters"].([]interface{})
			for _, p := range params {
				param, ok := p.(map[string]interface{})
				if !ok {
					continue
				}

				schema, _ := param["schema"].(map[string]interface{})
				if schema != nil && !hasAnyKey(schema, validationKeys) {
					findings = append(findings, CreateFinding(
						"SEC010",
						"Medium",
						"Input parameter lacks validation constraints",
						fmt.Sprintf("paths.%s.%s.parameters.%v", path, method, param["name"]),
						"Define input validation such as min/max, pattern, or enum",
					))
				}
			}

			// Request body
			requestBody, _ := details["requestBody"].(map[string]interface{})
			content, _ := requestBody["content"].(map[string]interface{})

			for _, mediaRaw := range content {
				media, ok := mediaRaw.(map[string]interface{})
				if !ok {
					continue
				}

				schema, _ := media["schema"].(map[string]interface{})
				if schema != nil && !hasAnyKey(schema, validationKeys) {
					findings = append(findings, CreateFinding(
						"SEC010",
						"Medium",
						"Request body schema lacks validation constraints",
						fmt.Sprintf("paths.%s.%s.requestBody", path, method),
						"Add validation constraints to request body schema",
					))
				}
			}
		}
	}

	return findings
}
func hasAnyKey(m map[string]interface{}, keys map[string]bool) bool {
	for k := range m {
		if keys[k] {
			return true
		}
	}
	return false
}
