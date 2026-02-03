package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RegisterAnalyzerRoutes(router *gin.Engine) {
	group := router.Group("/analyze")

	group.POST("/", AnalyzeSpecText)
	group.POST("/file", AnalyzeSpecFile)
	group.POST("/url", AnalyzeSpecURL)
}

func AnalyzeSpecText(c *gin.Context) {
	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to read request body"})
		return
	}

	spec, err := ParseSpec(nil, string(body))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := ValidateSpec(spec); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	an := NewAnalyzer(DefaultRules())
	findings := an.Analyze(spec)
	score := CalculateScore(findings)

	c.JSON(http.StatusOK, gin.H{
		"total_issues":   len(findings),
		"security_score": score,
		"findings":       findings,
	})
}

func AnalyzeSpecFile(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File is required"})
		return
	}
	f, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to open file"})
		return
	}
	defer f.Close()
	spec, err := ParseSpec(f, "")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := ValidateSpec(spec); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	an := NewAnalyzer(DefaultRules())
	findings := an.Analyze(spec)
	score := CalculateScore(findings)

	c.JSON(http.StatusOK, gin.H{
		"filename":       file.Filename,
		"total_issues":   len(findings),
		"security_score": score,
		"findings":       findings,
	})
}

type urlRequest struct {
	URL string `json:"url"`
}

func AnalyzeSpecURL(c *gin.Context) {
	var req urlRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid URL payload"})
		return
	}

	specText, err := FetchSpecFromURL(req.URL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	spec, err := ParseSpec(nil, specText)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := ValidateSpec(spec); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	an := NewAnalyzer(DefaultRules())
	findings := an.Analyze(spec)
	grouped := GroupFindings(findings)
	score := CalculateScore(findings)
	c.JSON(http.StatusOK, gin.H{
		"total_issues":   len(findings),
		"grouped_issues": len(grouped),
		"security_score": score,
		"findings":       grouped,
	})
}
