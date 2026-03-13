package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// okHandler is a simple handler that writes 200 OK.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// panicHandler always panics.
var panicHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	panic("test panic")
})

// --- Logger ---

func TestLogger_LogsRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	handler := Logger(logger)(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	logged := buf.String()
	if !strings.Contains(logged, "GET") {
		t.Errorf("Logger() log missing method, got: %s", logged)
	}
	if !strings.Contains(logged, "/api/healthz") {
		t.Errorf("Logger() log missing path, got: %s", logged)
	}
	if !strings.Contains(logged, "200") {
		t.Errorf("Logger() log missing status code, got: %s", logged)
	}
}

func TestLogger_CapturesNon200Status(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	notFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := Logger(logger)(notFoundHandler)

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !strings.Contains(buf.String(), "404") {
		t.Errorf("Logger() log should contain 404, got: %s", buf.String())
	}
}

func TestLogger_PassesThroughResponse(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	handler := Logger(logger)(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Logger() downstream status = %d, want %d", w.Code, http.StatusOK)
	}
}

// --- CORS ---

func TestCORS_SetsHeaders(t *testing.T) {
	handler := CORS("*")(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/chirps", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("CORS() Allow-Origin = %q, want %q", got, "*")
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Errorf("CORS() Allow-Methods header missing")
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Errorf("CORS() Allow-Headers header missing")
	}
}

func TestCORS_PreflightReturns204(t *testing.T) {
	handler := CORS("*")(okHandler)
	req := httptest.NewRequest(http.MethodOptions, "/api/chirps", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("CORS() OPTIONS status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestCORS_PreflightDoesNotCallNext(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := CORS("*")(next)
	req := httptest.NewRequest(http.MethodOptions, "/api/chirps", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if called {
		t.Errorf("CORS() OPTIONS should not call next handler")
	}
}

func TestCORS_CustomOrigin(t *testing.T) {
	handler := CORS("https://app.example.com")(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("CORS() Allow-Origin = %q, want %q", got, "https://app.example.com")
	}
}

// --- Recover ---

func TestRecover_CatchesPanic(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	handler := Recover(logger)(panicHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Recover() status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestRecover_LogsPanicMessage(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	handler := Recover(logger)(panicHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !strings.Contains(buf.String(), "test panic") {
		t.Errorf("Recover() should log panic message, got: %s", buf.String())
	}
}

func TestRecover_NoPanicPassesThrough(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	handler := Recover(logger)(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Recover() status = %d, want %d", w.Code, http.StatusOK)
	}
	if buf.Len() > 0 {
		t.Errorf("Recover() should not log when no panic occurs, got: %s", buf.String())
	}
}

// --- Chain ---

func TestChain_AppliesMiddlewareOutermostFirst(t *testing.T) {
	order := []string{}

	a := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "A-before")
			next.ServeHTTP(w, r)
			order = append(order, "A-after")
		})
	}
	b := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "B-before")
			next.ServeHTTP(w, r)
			order = append(order, "B-after")
		})
	}

	handler := Chain(okHandler, a, b)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	want := []string{"A-before", "B-before", "B-after", "A-after"}
	for i, step := range want {
		if i >= len(order) || order[i] != step {
			t.Errorf("Chain() execution order = %v, want %v", order, want)
			break
		}
	}
}
