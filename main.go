package main

import (
	"log"
	"net/http"

	"github.com/shazeedul/go-first/api/auth"
	"github.com/shazeedul/go-first/api/products"
	"github.com/shazeedul/go-first/services/jwt"

	"github.com/gorilla/mux"
)

func main() {

	route := mux.NewRouter()

	// Create a subrouter for the API
	api := route.PathPrefix("/api").Subrouter()

	// Public API Routes
	api.HandleFunc("/register", auth.RegisterHandler).Methods("POST")
	api.HandleFunc("/login", auth.LoginHandler).Methods("POST")
	api.HandleFunc("/reset-password", auth.ResetPasswordHandler).Methods("POST")
	api.HandleFunc("/logout", auth.LogoutHandler).Methods("POST")

	// Protected API with JWT authentication
	api.Handle("/products", jwt.JWTMiddleware(http.HandlerFunc(products.GetProducts))).Methods("GET")

	// Start server
	log.Println("Server running on port 8090")
	log.Fatal(http.ListenAndServe(":8090", route))
}
