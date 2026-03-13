package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthz(t *testing.T) {
	h := newTestHandler(&mockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	w := httptest.NewRecorder()

	h.Healthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Healthz() status = %d, want %d", w.Code, http.StatusOK)
	}
	if body := w.Body.String(); body != "OK" {
		t.Errorf("Healthz() body = %q, want %q", body, "OK")
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("Healthz() Content-Type = %q, want text/plain", ct)
	}
}

func TestMetrics_ZeroHits(t *testing.T) {
	h := newTestHandler(&mockStore{})
	req := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
	w := httptest.NewRecorder()

	h.Metrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Metrics() status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "0") {
		t.Errorf("Metrics() body should contain hit count 0, got: %s", body)
	}
}

func TestMetrics_WithHits(t *testing.T) {
	h := newTestHandler(&mockStore{})
	h.FileHits.Store(42)

	req := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
	w := httptest.NewRecorder()

	h.Metrics(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "42") {
		t.Errorf("Metrics() body should contain 42 hits, got: %s", body)
	}
}

func TestReset_DevPlatform(t *testing.T) {
	h := newTestHandler(&mockStore{})
	h.FileHits.Store(5)

	req := httptest.NewRequest(http.MethodPost, "/admin/reset", nil)
	w := httptest.NewRecorder()

	h.Reset(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Reset() status = %d, want %d", w.Code, http.StatusOK)
	}
	if hits := h.FileHits.Load(); hits != 0 {
		t.Errorf("Reset() FileHits = %d, want 0", hits)
	}
}

func TestReset_NonDevPlatform(t *testing.T) {
	h := newTestHandler(&mockStore{})
	h.Platform = "prod"

	req := httptest.NewRequest(http.MethodPost, "/admin/reset", nil)
	w := httptest.NewRecorder()

	h.Reset(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Reset() status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestMetricsInc_IncrementsOnAppGet(t *testing.T) {
	h := newTestHandler(&mockStore{})
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := h.MetricsInc(inner)

	req := httptest.NewRequest(http.MethodGet, "/app/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if hits := h.FileHits.Load(); hits != 1 {
		t.Errorf("MetricsInc() FileHits = %d, want 1", hits)
	}
}

func TestMetricsInc_DoesNotIncrementOnNonAppPath(t *testing.T) {
	h := newTestHandler(&mockStore{})
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := h.MetricsInc(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if hits := h.FileHits.Load(); hits != 0 {
		t.Errorf("MetricsInc() FileHits = %d, want 0 for non-app path", hits)
	}
}
