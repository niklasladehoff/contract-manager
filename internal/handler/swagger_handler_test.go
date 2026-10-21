package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAPISpec(t *testing.T) {
	w := httptest.NewRecorder()
	NewSwaggerHandler().OpenAPISpec(w, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected response: %d %v", w.Code, w.Header())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	// Resolve every local reference so missing schema names cannot silently
	// break Swagger UI or clients generated from this document.
	var checkRefs func(any)
	checkRefs = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			if ref, ok := v["$ref"].(string); ok && strings.HasPrefix(ref, "#/") {
				var target any = spec
				for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
					object, ok := target.(map[string]any)
					if !ok {
						t.Fatalf("invalid reference %s", ref)
					}
					target, ok = object[part]
					if !ok {
						t.Fatalf("unresolved reference %s", ref)
					}
				}
			}
			for _, child := range v {
				checkRefs(child)
			}
		case []any:
			for _, child := range v {
				checkRefs(child)
			}
		}
	}
	checkRefs(spec)
}
