package respond

import (
	"encoding/json"
	"log"
	"net/http"
)

// WithJSON writes a JSON-encoded payload with the given status code.
func WithJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("respond: failed to encode JSON: %v", err)
	}
}

// WithError writes a JSON error response with the given status code.
func WithError(w http.ResponseWriter, code int, msg string) {
	WithJSON(w, code, map[string]string{"error": msg})
}
