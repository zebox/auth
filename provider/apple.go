// implementation of Apple SignIn provider
package provider

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
	"github.com/go-pkgz/rest"
	"net/http"
	"time"
)

// The main Apple authentication url for sign in with apple id (https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms)
// Apple not support response with unique apple id after auth request and can return only either email + name both or one.
// If user reject share email your can't bind one by some unique id, because add email+name to scope
const appleAuthUrl = "https://appleid.apple.com/auth/authorize?state=%s&response_type=code id_token&client_id=88909&scope=%s+%s&response_mode=form_post&redirect_uri=%s"

type AppleHandler struct {
	logger.L

	ProviderName string
	clientID     string   // a main ServiceID identifier in Apple developer account
	Scopes       []string // for apple provider allow only "email" and "name" scope values
}

// Name of the provider
func (ah *AppleHandler) Name() string { return ah.ProviderName }

// LoginHandler - GET /login
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
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to make claim's id")
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

	if _, err := p.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	// setting RedirectURL to rootURL/routingPath/provider/callback
	// e.g. http://localhost:8080/auth/github/callback
	p.conf.RedirectURL = p.makeRedirURL(r.URL.Path)

	// return login url
	loginURL := p.conf.AuthCodeURL(state)
	p.Logf("[DEBUG] login url %s, claims=%+v", loginURL, claims)

	http.Redirect(w, r, loginURL, http.StatusFound)
}
