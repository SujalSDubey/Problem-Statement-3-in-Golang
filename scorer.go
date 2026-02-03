package main
func CalculateScore(findings []Finding) int {
	score := 100

	for _, finding := range findings {
		switch finding.Severity {
		case "Critical":
			score -= 20
		case "High":
			score -= 10
		case "Medium":
			score -= 5
		case "Low":
			score -= 2
		}
	}

	if score < 0 {
		return 0
	}
	return score
}
