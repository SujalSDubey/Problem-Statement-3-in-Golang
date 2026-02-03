package main

// Finding represents a security issue found in the OpenAPI spec
type Finding struct {
	RuleID         string `json:"rule_id"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Location       string `json:"location"`
	Recommendation string `json:"recommendation"`
}

// CreateFinding creates a new Finding
func CreateFinding(
	ruleID string,
	severity string,
	description string,
	location string,
	recommendation string,
) Finding {
	return Finding{
		RuleID:         ruleID,
		Severity:       severity,
		Description:    description,
		Location:       location,
		Recommendation: recommendation,
	}
}
