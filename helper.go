package main

// GroupedFinding represents aggregated findings for a rule
type GroupedFinding struct {
	RuleID         string   `json:"rule_id"`
	Severity       string   `json:"severity"`
	Count          int      `json:"count"`
	Locations      []string `json:"locations"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation"`
}

// GroupFindings groups findings by rule_id
func GroupFindings(findings []Finding) []GroupedFinding {
	groupMap := make(map[string][]Finding)

	// Group by RuleID
	for _, f := range findings {
		groupMap[f.RuleID] = append(groupMap[f.RuleID], f)
	}

	var grouped []GroupedFinding

	for ruleID, items := range groupMap {
		first := items[0]

		grouped = append(grouped, GroupedFinding{
			RuleID:         ruleID,
			Severity:       first.Severity,
			Count:          len(items),
			Locations:      extractLocations(items),
			Description:    first.Description,
			Recommendation: first.Recommendation,
		})
	}

	return grouped
}

func extractLocations(items []Finding) []string {
	locations := make([]string, 0, len(items))
	for _, item := range items {
		locations = append(locations, item.Location)
	}
	return locations
}
