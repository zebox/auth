// Implementation sign in with Apple for allow users to sign in to web services using their Apple ID.
// For correct work this provider user must has Apple developer account and correct configure "sign in with Apple" at in
// See more: https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api
package provider

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
	"github.com/go-pkgz/rest"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"time"
)

const (
	// appleAuthUrl is the base authentication URL for sign in with Apple ID and fetch request code for user validation request.
	appleAuthUrl = "https://appleid.apple.com/auth/authorize"

	// appleValidationURL is the endpoint for verifying tokens and get user unique ID and E-mail
	appleValidationURL = "https://appleid.apple.com/auth/token"

	// apple REST API accept only from-data with it content-type
	ContentType = "application/x-www-form-urlencoded"

	// UserAgent required to every request to Apple REST API
	UserAgent = "github.com/go-pkgz/auth"

	// AcceptHeader is the content to accept from response
	AcceptHeader = "application/json"
)

// AppleHandler implements login via Apple ID
type AppleHandler struct {
	logger.L

	ProviderName     string
	TokenService     TokenService
	Scopes           []string             // for apple provider allow only "email" and "name" scope values
	ClientID         string               // the identifier Services ID for your app created in Apple developer account.
	TeamID           string               // developer Team ID (10 characters), required for create JWT. It available, after signed in at developer account, by link: https://developer.apple.com/account/#/membership
	PrivateKeyLoader PrivateKeyLoaderFunc // custom loader function interface

	keyID      string      // private key ID  assigned to private key obtain in Apple developer account
	privateKey interface{} // private key from Apple obtained in developer account (the keys section). Required for create the Client Secret (https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens#3262048)

}

// PrivateKeyLoaderFunc interface for implement custom private key loader from some sources
type PrivateKeyLoaderFunc interface {
	LoadPrivateKey(keyID string, signingKey interface{}) ([]byte, error)
}

// LoadPrivateKey implement pre-defined PrivateKeyLoaderFunc interface method for load private key from local file
func (ah *AppleHandler) LoadPrivateKey(keyID string, signingKey interface{}) ([]byte, error) {
	if reflect.TypeOf(signingKey).Kind() != reflect.String {
		return nil, errors.New("signingKey not a string type for load private key from file")
	}
	keyPath := signingKey.(string)
	kFile, err := os.Open(keyPath)
	if err != nil {
		return nil, err
	}
	keyValue, err := ioutil.ReadAll(kFile)
	if err != nil {
		return nil, err
	}
	return keyValue, nil
}

// setPrivateKey is the private method for assign keyID and private key to AppleHandler
func (ah *AppleHandler) InitPrivateKey(keyID string, signingKey interface{}) error {
	if ah.PrivateKeyLoader == nil {
		return errors.New("load private key interface is nil")
	}
	sKey, err := ah.PrivateKeyLoader.LoadPrivateKey(keyID, signingKey)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(sKey)
	if block == nil {
		return errors.New("empty block after decoding")
	}
	ah.privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	return nil
}

// Name of the provider
func (ah *AppleHandler) Name() string { return ah.ProviderName }

// LoginHandler - GET */{provider-name}/login
func (ah *AppleHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {

	ah.Logf("[DEBUG] login with %s", ah.Name())
	// make state (random) and store in session
	state, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "failed to make oauth2 state")
		return
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}

	claims := token.Claims{
		Handshake: &token.Handshake{
			State: state,
			From:  r.URL.Query().Get("from"),
		},
		SessionOnly: r.URL.Query().Get("session") != "" && r.URL.Query().Get("session") != "0",
		StandardClaims: jwt.StandardClaims{
			Id:        cid,
			Audience:  r.URL.Query().Get("site"),
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
			NotBefore: time.Now().Add(-1 * time.Minute).Unix(),
		},
	}

	/*if _, err := ah.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	// setting RedirectURL to rootURL/routingPath/provider/callback
	// e.g. http://localhost:8080/auth/github/callback
	p.conf.RedirectURL = p.makeRedirURL(r.URL.Path)

	// return login url
	loginURL := p.conf.AuthCodeURL(state)
	p.Logf("[DEBUG] login url %s, claims=%+v", loginURL, claims)

	http.Redirect(w, r, loginURL, http.StatusFound)*/
}
