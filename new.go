package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"github.com/MicahParks/keyfunc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Person struct {
	Name  string `json:"given_name"`
	Email string `json:"email"`
}

// Global maps to keep track of state and PKCE code verifiers
var listRandomStates map[string]bool = make(map[string]bool)
var pkceCodeVerifiers map[string]string = make(map[string]string)

// randomHex returns a random hexadecimal string of n bytes.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func googleConfig() *oauth2.Config {
	// Credentials must be set in your .env file (see Task #1)
	return &oauth2.Config{
		ClientID:     os.Getenv("CLIENTID"),
		ClientSecret: os.Getenv("CLIENTSECRET"),
		RedirectURL:  "http://localhost:8080/callback",
		Scopes: []string{
			"openid",
			"email",
			"profile",
		},
		Endpoint: google.Endpoint,
	}
}

func handlerLogin(w http.ResponseWriter, req *http.Request) {
	fmt.Println("User is trying to login...")
	config := googleConfig()

	// Generate a random state string
	state, err := randomHex(8)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}
	listRandomStates[state] = true

	// --- PKCE Extension (Task #5) ---
	// Generate a code verifier (a high-entropy random string)
	codeVerifier, err := randomHex(32) // 32 bytes gives a 64-character hex string
	if err != nil {
		http.Error(w, "Failed to generate code verifier", http.StatusInternalServerError)
		return
	}
	// Store the verifier against the state for later use
	pkceCodeVerifiers[state] = codeVerifier

	// Create the code challenge by SHA256-hashing the verifier and then base64-url encoding it without padding.
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Redirect user with PKCE parameters appended to the authorization URL.
	authURL := config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	fmt.Printf("User %v is being redirected to: %v\n", state, authURL)
	http.Redirect(w, req, authURL, http.StatusFound)
}

func handlerCallback(w http.ResponseWriter, req *http.Request) {
	// Parse state from the callback
	state := req.FormValue("state")
	fmt.Printf("Callback from state: %v\n", state)
	if !listRandomStates[state] {
		log.Fatal("Invalid or reused state detected")
	}
	// Remove the state since it’s now used
	delete(listRandomStates, state)

	// Retrieve and remove the PKCE code verifier associated with this state.
	codeVerifier, ok := pkceCodeVerifiers[state]
	if !ok {
		log.Fatal("Missing PKCE code verifier")
	}
	delete(pkceCodeVerifiers, state)

	// Parse the authorization code.
	code := req.FormValue("code")
	config := googleConfig()

	// Exchange the authorization code for tokens, sending the code verifier.
	token, err := config.Exchange(context.TODO(), code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		log.Fatalf("Token exchange failed: %v", err)
	}

	// Extract the id_token from the token response.
	idTokenRaw, ok := token.Extra("id_token").(string)
	if !ok {
		log.Fatal("No id_token field in token")
	}

	// --- Validate the digital signature (Task #3) ---
	// Obtain Google's JWKS from the well-known endpoint.
	jwksURL := "https://www.googleapis.com/oauth2/v3/certs"
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to get JWKS from Google: %v", err)
	}

	parsedToken, err := jwt.Parse(idTokenRaw, jwks.Keyfunc)
	if err != nil {
		log.Fatalf("Failed to parse/validate token: %v", err)
	}
	if !parsedToken.Valid {
		log.Fatal("Invalid token")
	}
	fmt.Println("Received a valid token!")

	// --- Validate claims (Task #4) ---
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		log.Fatal("Cannot parse claims")
	}

	// Check issuer
	issuer, ok := claims["iss"].(string)
	if !ok || (issuer != "https://accounts.google.com" && issuer != "accounts.google.com") {
		log.Fatalf("Invalid issuer: %v", issuer)
	}

	// Check audience
	audience, ok := claims["aud"].(string)
	if !ok || audience != os.Getenv("CLIENTID") {
		log.Fatalf("Invalid audience: %v", audience)
	}

	// Check expiration
	exp, ok := claims["exp"].(float64)
	if !ok {
		log.Fatal("No exp claim in token")
	}
	if int64(exp) < time.Now().Unix() {
		log.Fatal("Token is expired")
	}

	// Create a Person instance from token claims.
	person := Person{
		Name:  fmt.Sprintf("%v", claims["given_name"]),
		Email: fmt.Sprintf("%v", claims["email"]),
	}
	fmt.Printf("Name: %v, Email: %v\n", person.Name, person.Email)

	// Use a template to display the person’s information.
	t, err := template.ParseFiles("html/callback.html")
	if err != nil {
		log.Fatalf("Template parse error: %v", err)
	}
	t.Execute(w, person)
}

func main() {
	// Load environment variables from .env (Task #1)
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Setup HTTP handlers.
	http.Handle("/", http.FileServer(http.Dir("html")))
	http.HandleFunc("/login", handlerLogin)
	http.HandleFunc("/callback", handlerCallback)

	// Start the HTTP server.
	fmt.Println("Starting server on :8080 ...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
