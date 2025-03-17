package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"time"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/base64"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"   // had to change this to v4 instead of v5 because: "cannot use googleJwks.Keyfunc (value of type func(token *"github.com/golang-jwt/jwt/v4".Token) (interface{}, error)) as "github.com/golang-jwt/jwt/v5".Keyfunc value in argument to jwt.Parse"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Person struct {
	Name  string `json:"given_name"`
	Email string `json:"email"`
}

var listRandomStates map[string]bool = make(map[string]bool)

var pkceMap = make(map[string]string)

func randomHex(n int) (string, error) {
	// ***** TASK #2: FIX RANDOM STATE *****
	// DONE

	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func googleConfig() *oauth2.Config {
	// credentials should be obtained from https://console.developers.google.com
	config := &oauth2.Config{
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
	return config
}

func handlerLogin(w http.ResponseWriter, req *http.Request) {
	fmt.Println("User is trying to login...")
	config := googleConfig()

	// sample random state
	state, _ := randomHex(8)

	// Generate a code verifier
	codeVerifier, _ := randomHex(32)
	// Generate a code challenge (SHA256 hashed & base64-URL-encoded)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	// Store the verifier for use in callback
	pkceMap[state] = codeVerifier

	// redirect user to Google's consent page to ask for permission for the scopes specified in config
	listRandomStates[state] = true
	url := config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	fmt.Printf("User %v is being redirected to... %v\n", state, url)
	http.Redirect(w, req, url, http.StatusFound)
}

func handlerCallback(w http.ResponseWriter, req *http.Request) {
	// parse state
	state := req.FormValue("state")
	fmt.Printf("Callback from... %v\n", state)
	if listRandomStates[state] == true {
		// all good, mark state as used
		delete(listRandomStates, state)
	} else {
		log.Fatal("Callback from whom? ¯\\_(ツ)_/¯")
	}

	// parse code
	code := req.FormValue("code")

	// we need config usable inside func handlerCallback
	config := googleConfig()

	// exchange authorization code for token
	token, _ := config.Exchange(context.TODO(), code,
		oauth2.SetAuthURLParam("code_verifier", pkceMap[state]),
	)

	// extract token_id
	idToken := token.Extra("id_token")
	// fmt.Println(idToken) // inspect token here: https://jwt.io // inspection works for me


	jwksURL := "https://www.googleapis.com/oauth2/v3/certs"
	googleJwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to create Google JWKS: %v", err)
	}


	// parsedToken, err := jwt.Parse(idToken.(string), myDummyKeyFunc)
	parsedToken, err := jwt.Parse(idToken.(string), googleJwks.Keyfunc)


	if err != nil {
		fmt.Println("ERROR: Could not validate token!")
	} else {
		fmt.Println("Received a valid token!")
	}

	// parse claims and create person
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		fmt.Println("ERROR: Invalid token claims!")
		return
	}

	// Check issuer
	if claims["iss"] != "accounts.google.com" && claims["iss"] != "https://accounts.google.com" {
		fmt.Println("ERROR: Invalid issuer (iss)!")
		return
	}

	// Check audience
	if claims["aud"] != googleConfig().ClientID {
		fmt.Println("ERROR: Invalid audience (aud)!")
		return
	}

	// Check expiration
	expFloat, ok := claims["exp"].(float64)
	if !ok {
		fmt.Println("ERROR: Invalid or missing exp claim!")
		return
	}
	if float64(time.Now().Unix()) > expFloat {
		fmt.Println("ERROR: Token is expired!")
		return
	}
	
	person := Person{Name: claims["given_name"].(string), Email: claims["email"].(string)}
	fmt.Printf("Name: %v, Email: %v\n", person.Name, person.Email)

	// use template package to inject person into callback.html
	t, _ := template.ParseFiles("html/callback.html")
	t.Execute(w, person)
}

func main() {


	// load .env file
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// handler
	http.Handle("/", http.FileServer(http.Dir("html")))
	http.HandleFunc("/login", handlerLogin)
	http.HandleFunc("/callback", handlerCallback)

	// start server
	fmt.Println("Starting server...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
