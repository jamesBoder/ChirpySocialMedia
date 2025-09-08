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

	// Use the server ListenAndServe method to start the server
	log.Println("Starting server on :8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}

}
