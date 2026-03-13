package handlers

import (
	"fmt"
	"log"
	"net/http"

	"github.com/jamesboder/ChirpySocialMedia/internal/respond"
)

// Healthz handles GET /api/healthz — simple liveness check.
func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Metrics handles GET /admin/metrics — returns fileserver hit count as HTML.
func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w,
		"<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>",
		h.FileHits.Load(),
	)
}

// Reset handles POST /admin/reset — deletes all users (dev only).
func (h *Handler) Reset(w http.ResponseWriter, r *http.Request) {
	if h.Platform != "dev" {
		respond.WithError(w, http.StatusForbidden, "forbidden")
		return
	}

	if err := h.DB.DeleteAllUsers(r.Context()); err != nil {
		log.Printf("reset: DeleteAllUsers error: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	h.FileHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}

// MetricsInc is middleware that increments the fileserver hit counter on /app/ requests.
func (h *Handler) MetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && (r.URL.Path == "/app/" || r.URL.Path == "/app") {
			h.FileHits.Add(1)
		}
		next.ServeHTTP(w, r)
	})
}
