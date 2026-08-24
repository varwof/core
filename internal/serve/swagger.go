package serve

import (
	"net/http"
	"os"
)

var swaggerHTML = []byte(`<!DOCTYPE html>
<html>
<head><title>pki API</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:"/swagger/openapi.yaml", dom_id:"#swagger-ui"})</script>
</body>
</html>`)

func (s *Server) serveSwagger(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/swagger/openapi.yaml" {
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		// Try doc/openapi.yaml first, then openapi.yaml
		if _, err := os.Stat("docs/openapi.yaml"); err == nil {
			http.ServeFile(w, r, "docs/openapi.yaml")
		} else {
			http.ServeFile(w, r, "openapi.yaml")
		}
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(swaggerHTML)
}
