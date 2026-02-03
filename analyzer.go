package main

type Analyzer struct {
	rules []func(OpenAPISpec) []Finding
}

func NewAnalyzer(rules []func(OpenAPISpec) []Finding) *Analyzer {
	return &Analyzer{rules: rules}
}

func (a *Analyzer) Analyze(spec OpenAPISpec) []Finding {
	var findings []Finding
	for _, rule := range a.rules {
		findings = append(findings, rule(spec)...)
	}
	return findings
}

func DefaultRules() []func(OpenAPISpec) []Finding {
	return []func(OpenAPISpec) []Finding{
		CheckSEC001NoGlobalSecurity,
		CheckSEC002UnprotectedEndpoints,
		CheckSEC003HTTPAllowed,
		CheckSEC004NoRateLimitHeaders,
		CheckSEC005SensitiveQueryParams,
		CheckSEC006MissingErrorResponses,
		CheckSEC007MissingSecurityContact,
		CheckSEC008DeprecatedWithoutSunset,
		CheckSEC009WildcardServerURL,
		CheckSEC010NoInputValidation,
	}
}
