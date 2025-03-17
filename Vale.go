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

	"github.com/golang-jwt/jwt/v4"  // made sure to use version v4 to match the keyfunc package otherwise we kept getting errors
	"github.com/joho/godotenv"
	"github.com/MicahParks/keyfunc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Person struct {
	Name  string `json:"given_name"`
	Email string `json:"email"`
}

var (
	listRandomStates map[string]bool = make(map[string]bool)
	oauthConfig      *oauth2.Config
	jwks             *keyfunc.JWKS
)

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("unable to generate random bytes: %v", err)
	}
	return hex.EncodeToString(bytes), nil
}

func generateCodeVerifier() (string, string, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", fmt.Errorf("unable to generate code verifier: %v", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	return verifier, challenge, nil
}

func googleConfig() *oauth2.Config {
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

	state, _ := randomHex(8)

	// added PKCE extension
	codeVerifier, codeChallenge, err := generateCodeVerifier()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// stored codeVerifier in a place associated with the state
	listRandomStates[state] = true
	http.SetCookie(w, &http.Cookie{
		Name:  "code_verifier",
		Value: codeVerifier,
		Path:  "/",
	})

	// redirect user to Google's consent page to ask for permission for the scopes specified in config
	url := config.AuthCodeURL(state, oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
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

	// retrieved codeVerifier from the place mentioned above
	cookie, err := req.Cookie("code_verifier")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	codeVerifier := cookie.Value

	// parse code
	code := req.FormValue("code")

	// we need config usable inside handlerCallback
	config := googleConfig()

	// exchange code for token
	token, err := config.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		log.Fatalf("Failed to exchange token: %v", err)
	}

	// extract idToken from token
	idToken := token.Extra("id_token")
	if idToken == nil {
		log.Fatal("No id_token field in oauth2 token.")
	}

	// validate the digital signature of `idToken`
	if jwks == nil {
		jwks, err = keyfunc.Get("https://www.googleapis.com/oauth2/v3/certs", keyfunc.Options{
			RefreshInterval: time.Hour,
		})
		if err != nil {
			log.Fatalf("Failed to create JWKS from the given URL.\nError: %s", err)
		}
	}

	parsedToken, err := jwt.Parse(idToken.(string), jwks.Keyfunc)
	if err != nil {
		log.Fatalf("Failed to parse JWT.\nError: %s", err)
	}

	// validate `iss`, `aud`, and `exp`
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		if claims["iss"] != "https://accounts.google.com" && claims["iss"] != "accounts.google.com" {
			log.Fatal("Invalid token issuer.")
		}

		if claims["aud"] != os.Getenv("CLIENTID") {
			log.Fatal("Invalid token audience.")
		}

		if exp, ok := claims["exp"].(float64); !ok || int64(exp) < time.Now().Unix() {
			log.Fatal("Token is expired.")
		}

		// create person
		person := Person{Name: claims["given_name"].(string), Email: claims["email"].(string)}
		fmt.Printf("Name: %v, Email: %v\n", person.Name, person.Email)

		// use template package to inject person into callback.html
		t, _ := template.ParseFiles("html/callback.html")
		t.Execute(w, person)
	} else {
		log.Fatalf("Invalid JWT.")
	}
}

func main() {
	// load .env file
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// initialize oauthConfig
	oauthConfig = googleConfig()

	// handler
	http.Handle("/", http.FileServer(http.Dir("html")))
	http.HandleFunc("/login", handlerLogin)
	http.HandleFunc("/callback", handlerCallback)

	// start server
	fmt.Println("Starting server...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}