package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchSpecFromURL fetches an OpenAPI spec from a remote URL
func FetchSpecFromURL(url string) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("error fetching URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch spec. HTTP %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")

	if !isValidContentType(contentType) {
		return "", errors.New("URL does not appear to return JSON or YAML content")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("failed to read response body")
	}

	return string(body), nil
}

func isValidContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "json") ||
		strings.Contains(ct, "yaml") ||
		strings.Contains(ct, "text")
}
