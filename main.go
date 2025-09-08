package main

import (
	"log"
	"net/http"
)

func main() {

	// Create a new http.ServeMux
	mux := http.NewServeMux()

	// Create a new http.Server struct
	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// use NewServeMux .Handle() to add a handler for the root path "/". Use .FileServer as the handler
	mux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.Dir("."))))

	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/", http.StatusMovedPermanently)
	})

	// Add a Readiness Endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	// Use the server ListenAndServe method to start the server
	log.Println("Starting server on :8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}

}
