package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	// Create Gin router
	router := gin.Default()
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "running",
		})
	})
	RegisterAnalyzerRoutes(router)

	if err := router.Run(":8000"); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
