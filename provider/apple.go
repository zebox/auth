// Implementation sign in with Apple for allow users to sign in to web services using their Apple ID.
// For correct work this provider user must has Apple developer account and correct configure "sign in with Apple" at in
// See more: https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api
package provider

import (
	"context"
	"crypto/x509"
	"encoding/json"

	"encoding/pem"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
	"github.com/go-pkgz/rest"
	"io/ioutil"

	"net/http"
	"net/url"
	"os"

	"strings"
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
	defaultUserAgent = "github.com/go-pkgz/auth"

	// AcceptHeader is the content to accept from response
	AcceptHeader = "application/json"
)

// VerificationResponse is based on https://developer.apple.com/documentation/signinwithapplerestapi/tokenresponse
type AppleVerificationResponse struct {
	// A token used to access allowed user data, but now not implemented public interface for it.
	AccessToken string `json:"access_token"`

	// Access token type, always equal the "bearer".
	TokenType string `json:"token_type"`

	// Access token expires time in seconds.
	ExpiresIn int `json:"expires_in"`

	// The refresh token used to regenerate new access tokens.
	RefreshToken string `json:"refresh_token"`

	// Main JSON Web Token that contains the user’s identity information.
	IDToken string `json:"id_token"`

	// Used to capture any error returned in response. Always check error for empty
	Error string `json:"error"`
}

// AppleHandler implements login via Apple ID
type AppleHandler struct {
	logger.L

	URL                string // main auth domain URI
	ProviderName       string
	TokenService       TokenService
	Scopes             []string                  // for apple provider allow only "email" and "name" scope values
	ClientID           string                    // the identifier Services ID for your app created in Apple developer account.
	TeamID             string                    // developer Team ID (10 characters), required for create JWT. It available, after signed in at developer account, by link: https://developer.apple.com/account/#/membership
	KeyID              string                    // private key ID  assigned to private key obtain in Apple developer account
	UserAgent          string                    // UserAgent value for Apple API request. Default: "github.com/go-pkgz/auth"
	PrivateKeyLoader   PrivateKeyLoaderInterface // custom loader function interface
	ClientSecretExpire int64                     // time in seconds for client secret expired (default: 24h)

	privateKey   interface{} // private key from Apple obtained in developer account (the keys section). Required for create the Client Secret (https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens#3262048)
	clientSecret string      // is the JWT client secret will create after first call and then used until expired

}

// PrivateKeyLoaderInterface interface for implement custom private key loader from user source
type PrivateKeyLoaderInterface interface {
	LoadPrivateKey() ([]byte, error)
}

// PrivateKeyLoaderFunc is the built-in type for use pre-defined private key loader function
// Path to key file must be set
type LoadFromFileFunc struct {
	Path string
}

// AppleLoadPrivateKeyFromFile return instance for built-in loader function from local file
func AppleLoadPrivateKeyFromFile(path string) LoadFromFileFunc {
	return LoadFromFileFunc{
		Path: path,
	}
}

// LoadPrivateKey implement pre-defined (built-in) PrivateKeyLoaderInterface interface method for load private key from local file
func (lf LoadFromFileFunc) LoadPrivateKey() ([]byte, error) {
	keyPath := lf.Path // override input parameters with "Path" field
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

func NewAppleProvider(appleSetting AppleHandler) (*AppleHandler, error) {
	var ah AppleHandler
	ah = appleSetting

	//setting default values
	if ah.UserAgent == "" {
		ah.UserAgent = defaultUserAgent
	}

	err := ah.InitPrivateKey()
	return &ah, err
}

// setPrivateKey is the private method for assign keyID and private key to AppleHandler
func (ah *AppleHandler) InitPrivateKey() error {
	if ah.PrivateKeyLoader == nil {
		return errors.New("private key loader interface is nil")
	}
	if ah.KeyID == "" {
		return errors.New("keyID can't be empty")
	}
	sKey, err := ah.PrivateKeyLoader.LoadPrivateKey()
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

	ah.clientSecret, err = ah.generateClientSecret()
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

	if _, err := ah.TokenService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	// return login url
	loginURL, err := ah.prepareLoginURL(state, r.URL.Path)
	if err != nil {
		errMsg := fmt.Sprintf("prepare login url for [%s] provider failed", ah.ProviderName)
		ah.Logf("[ERROR] %s", errMsg)
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, errMsg)
		return
	}
	ah.Logf("[DEBUG] login url %s, claims=%+v", loginURL, claims)

	http.Redirect(w, r, loginURL, http.StatusFound)
}

// AuthHandler fills user info and redirects to "from" url. This is callback url redirected locally by browser
// GET /callback
func (ah AppleHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	// read response data
	if err := r.ParseForm(); err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusForbidden, err, "read callback response from data failed")
		return
	}

	state := r.FormValue("state") // state value which sent with auth request
	code := r.FormValue("code")   //  client code for validation

	oauthClaims, _, err := ah.TokenService.Get(r)
	if err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "failed to get token")
		return
	}

	if oauthClaims.Handshake == nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusForbidden, nil, "invalid handshake token")
		return
	}

	retrievedState := oauthClaims.Handshake.State
	if retrievedState == "" || retrievedState != state {
		rest.SendErrorJSON(w, r, ah.L, http.StatusForbidden, nil, "unexpected state")
		return
	}

	var resp AppleVerificationResponse
	err = ah.exchange(context.Background(), code, ah.makeRedirURL(r.URL.Path), &resp)
	if err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "exchange failed")
		return
	}
	ah.Logf("[DEBUG]response data %+v", resp)
	if resp.Error != "" {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, nil, fmt.Sprintf("response return error: %s", resp.Error))
		return
	}
	// Get token claims for extract uid (and email or name if their scopes exist)
	tokenClaims, err := ah.getTokenClaims(resp.IDToken)
	if err != nil {
		fmt.Println("failed to get claims: " + err.Error())
		return
	}

	uid := tokenClaims["sub"]
	//name:=claims["name"]
	//email:=claims["email"]

	u := token.User{
		ID: uid.(string),
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}
	claims := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Issuer:   ah.ProviderName,
			Id:       cid,
			Audience: oauthClaims.Audience,
		},
		SessionOnly: oauthClaims.SessionOnly,
	}

	if _, err = ah.TokenService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	ah.Logf("[DEBUG] user info %+v", u)

	// redirect to back url if presented in login query params
	if oauthClaims.Handshake != nil && oauthClaims.Handshake.From != "" {
		http.Redirect(w, r, oauthClaims.Handshake.From, http.StatusTemporaryRedirect)
		return
	}
	rest.RenderJSON(w, &u)

}

// LogoutHandler - GET /logout
func (ah AppleHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if _, _, err := ah.TokenService.Get(r); err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusForbidden, err, "logout not allowed")
		return
	}
	ah.TokenService.Reset(w)
}

// VerifyWebToken sends the WebValidationTokenRequest and gets validation result
func (ah *AppleHandler) exchange(ctx context.Context, code, redirectURI string, result interface{}) (err error) {

	// check jwt is expired ang recreate new JWT if need
	ok, err := ah.isClientSecretExpired()
	if err != nil || ok {
		jwt, err := ah.generateClientSecret()
		if err != nil {
			return err
		}
		ah.clientSecret = jwt
	}

	data := url.Values{}
	data.Set("client_id", ah.ClientID)
	data.Set("client_secret", ah.clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI) // redirect URL can't refer to localhost and must have trusted https certificated
	data.Set("grant_type", "authorization_code")

	client := http.Client{Timeout: time.Second * 5}
	req, err := http.NewRequestWithContext(ctx, "POST", appleValidationURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("content-type", ContentType)
	req.Header.Add("accept", AcceptHeader)
	req.Header.Add("user-agent", ah.UserAgent) // apple requires a user agent

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	// Apple REST API response either 200 (ok OK) or 400 (if error)
	if res.StatusCode >= 400 {
		return errors.New(fmt.Sprintf("exchange response error code: %d", res.StatusCode))
	}

	err = json.NewDecoder(res.Body).Decode(result)
	defer res.Body.Close()
	return err
}

// GetUniqueID decodes the id_token response and returns the unique from "sub" claim to identify the user
func (ah AppleHandler) getTokenClaims(idToken string) (jwt.MapClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("can't convert token claims to standard claims")
	}
	return claims, nil
}

// generateClientSecret create the JWT client secret used to make requests to the Apple validation server.
// for more details go to link: https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens#3262048
func (ah *AppleHandler) generateClientSecret() (string, error) {

	// Create the Claims
	now := time.Now()
	exp := now.Add(time.Second * 86400).Unix() // default value

	if ah.ClientSecretExpire != 0 {
		exp = now.Add(time.Second * time.Duration(ah.ClientSecretExpire)).Unix()
	}

	claims := &jwt.StandardClaims{
		Issuer:    ah.TeamID,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp,
		Audience:  "https://appleid.apple.com",
		Subject:   ah.ClientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["alg"] = "ES256"
	token.Header["kid"] = ah.KeyID

	return token.SignedString(ah.privateKey)
}

func (ah *AppleHandler) isClientSecretExpired() (bool, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(ah.clientSecret, jwt.MapClaims{})
	if err != nil {
		return false, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, errors.New("can't convert token claims to standard claims")
	}
	var expTime int64
	exp, ok := claims["exp"]

	if !ok {
		return false, errors.New("exp claim doesn't exist")
	}
	switch exp.(type) {
	case float64:
		expTime = int64(exp.(float64))
	case int64:
		expTime = exp.(int64)
	}
	if time.Unix(expTime, 0).Unix() <= time.Now().Unix() {
		return true, nil
	}

	return false, nil
}

func (ah *AppleHandler) prepareLoginURL(state, path string) (string, error) {
	extractScopeFn := func(scopes []string) string {

		if len(scopes) == 0 {
			return ""
		}

		var scopeList string
		for _, item := range scopes {
			scopeList = fmt.Sprintf("%s %s", scopeList, item)
		}
		scopeList = strings.TrimPrefix(scopeList, " ") // trimming scopes delimiter from first item
		return scopeList
	}
	authURL, err := url.Parse(appleAuthUrl)
	if err != nil {
		return "", err
	}

	query := authURL.Query()
	query.Set("state", state)
	query.Set("response_type", "code")
	query.Set("response_mode", "form_post")
	query.Set("client_id", ah.ClientID)
	query.Set("scope", extractScopeFn(ah.Scopes))
	query.Set("redirect_uri", ah.makeRedirURL(path))
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil

}

func (ah AppleHandler) makeRedirURL(path string) string {
	elems := strings.Split(path, "/")
	newPath := strings.Join(elems[:len(elems)-1], "/")

	return strings.TrimRight(ah.URL, "/") + strings.TrimRight(newPath, "/") + urlCallbackSuffix
}
