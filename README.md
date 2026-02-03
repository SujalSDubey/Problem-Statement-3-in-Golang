# OpenAPI Security Analyzer – Go

A Go-based API that analyzes OpenAPI (Swagger) specifications and reports common security issues using predefined rules.

---

## Features
- Analyze OpenAPI specs via:
  - Raw text
  - File upload (YAML / JSON)
  - URL
- Supports OpenAPI 3.x and Swagger 2.0
- Detects security issues (SEC001–SEC010)
- Returns security score and grouped findings

---

## Tech Stack
- Go
- Gin (HTTP framework)
- YAML / JSON parsing

---

## How to Run
```bash
go mod tidy
go run .
