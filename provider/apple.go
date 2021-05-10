// Implementation sign in with Apple for allow users to sign in to web services using their Apple ID.
// For correct work this provider user must has Apple developer account and correct configure "sign in with Apple" at in
// See more: https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api
// and https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms
package provider

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"golang.org/x/oauth2"

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

	// appleTokenURL is the endpoint for verifying tokens and get user unique ID and E-mail
	appleTokenURL = "https://appleid.apple.com/auth/token"

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

	// Access token expires time in seconds. Always equal 3600 seconds (1 hour)
	ExpiresIn int `json:"expires_in"`

	// The refresh token used to regenerate new access tokens.
	RefreshToken string `json:"refresh_token"`

	// Main JSON Web Token that contains the user’s identity information.
	IDToken string `json:"id_token"`

	// Used to capture any error returned in response. Always check error for empty
	Error string `json:"error"`
}

// AppleConfig is the main oauth2 required parameters for "Sign in with Apple"
type AppleConfig struct {
	ClientID           string   // the identifier Services ID for your app created in Apple developer account.
	TeamID             string   // developer Team ID (10 characters), required for create JWT. It available, after signed in at developer account, by link: https://developer.apple.com/account/#/membership
	KeyID              string   // private key ID  assigned to private key obtain in Apple developer account
	UserAgent          string   // UserAgent value for Apple API request. Default: "github.com/go-pkgz/auth"
	ClientSecretExpire int64    // time in seconds for client secret expired (default: 24h)
	Scopes             []string // for apple provider allow only "email" and "name" scope values

	privateKey   interface{} // private key from Apple obtained in developer account (the keys section). Required for create the Client Secret (https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens#3262048)
	clientSecret string      // is the JWT client secret will create after first call and then used until expired
}

// AppleHandler implements login via Apple ID
type AppleHandler struct {
	Params

	// all of these fields specific to particular oauth2 provider
	name string
	// infoURL  string not implemented at Apple side
	endpoint oauth2.Endpoint

	mapUser func(jwt.MapClaims) token.User // map info from InfoURL to User
	conf    AppleConfig

	PrivateKeyLoader PrivateKeyLoaderInterface // custom function interface for load private key

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
func LoadApplePrivateKeyFromFile(path string) LoadFromFileFunc {
	return LoadFromFileFunc{
		Path: path,
	}
}

// LoadPrivateKey implement pre-defined (built-in) PrivateKeyLoaderInterface interface method for load private key from local file
func (lf LoadFromFileFunc) LoadPrivateKey() ([]byte, error) {
	if lf.Path == "" {
		return nil, errors.New("empty private key path not allowed")
	}

	kFile, err := os.Open(lf.Path)
	if err != nil {
		return nil, err
	}
	keyValue, err := ioutil.ReadAll(kFile)
	if err != nil {
		return nil, err
	}
	err = kFile.Close()
	return keyValue, nil
}

// NewApple create new AppleProvider with custom name and parameters
// endpoints used in constructor  required only for testing and can't be define one outside the package
// Private must be when instance create for use JWT for make request to Apple REST API
func NewApple(name string, p Params, appleCfg AppleConfig, endpoints oauth2.Endpoint, privateKeyLoader PrivateKeyLoaderInterface) (*AppleHandler, error) {

	if name == "" {
		return nil, errors.New("empty name for apple provider not allowed")
	}

	if p.L == nil {
		p.L = logger.NoOp
	}

	// configuring default values for userAgent
	if appleCfg.UserAgent == "" {
		appleCfg.UserAgent = defaultUserAgent
	}
	if endpoints.AuthURL == "" {
		endpoints.AuthURL = appleAuthUrl
	}
	if endpoints.TokenURL == "" {
		endpoints.TokenURL = appleTokenURL
	}
	ah := AppleHandler{
		Params: p,
		name:   name,

		conf: AppleConfig{
			ClientID:           appleCfg.ClientID,
			TeamID:             appleCfg.TeamID,
			KeyID:              appleCfg.KeyID,
			ClientSecretExpire: appleCfg.ClientSecretExpire,
			UserAgent:          appleCfg.UserAgent,
			Scopes:             appleCfg.Scopes,
		},

		endpoint: endpoints,

		mapUser: func(claims jwt.MapClaims) token.User {
			var usr token.User
			if uid, ok := claims["sub"]; ok {
				usr.ID = fmt.Sprintf("apple_%s", uid.(string))
			}

			if email, ok := claims["email"]; ok {
				usr.Email = email.(string)
			}

			if emailVerified, ok := claims["email_verified"]; ok {
				usr.SetBoolAttr("email_verified", emailVerified.(string) == "true")
			}
			return usr
		},
	}

	if privateKeyLoader == nil {
		return nil, errors.New("private key loader function undefined")
	}
	ah.PrivateKeyLoader = privateKeyLoader

	err := ah.initPrivateKey()
	return &ah, err
}

// setPrivateKey is the private method for assign keyID and private key to AppleHandler
func (ah *AppleHandler) initPrivateKey() error {
	if ah.PrivateKeyLoader == nil {
		return errors.New("private key loader interface is nil")
	}
	if ah.conf.KeyID == "" {
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
	ah.conf.privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	ah.conf.clientSecret, err = ah.generateClientSecret()
	if err != nil {
		return err
	}
	return nil
}

// Name of the provider
func (ah *AppleHandler) Name() string { return ah.name }

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

	if _, err := ah.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	// return login url
	loginURL, err := ah.prepareLoginURL(state, r.URL.Path)
	if err != nil {
		errMsg := fmt.Sprintf("prepare login url for [%s] provider failed", ah.name)
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

	// read response form data
	if err := r.ParseForm(); err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "read callback response from data failed")
		return
	}

	state := r.FormValue("state") // state value which sent with auth request
	code := r.FormValue("code")   //  client code for validation

	// response with user name filed return only one time at first login, next login  field user doesn't exist
	// until user delete sign with Apple ID in account profile (security section)
	// example response: {"name":{"firstName":"Chan","lastName":"Lu"},"email":"user@email.com"}
	jUser := r.FormValue("user")  // json string with user name

	oauthClaims, _, err := ah.JwtService.Get(r)
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

	u := ah.mapUser(tokenClaims)

	// try parse user name data if it exist in scope and response
	if jUser != "" {
		ah.parseUserData(&u, jUser)
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}
	claims := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Issuer:   ah.Issuer,
			Id:       cid,
			Audience: oauthClaims.Audience,
		},
		SessionOnly: false,
	}

	if _, err = ah.JwtService.Set(w, claims); err != nil {
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
	if _, _, err := ah.JwtService.Get(r); err != nil {
		rest.SendErrorJSON(w, r, ah.L, http.StatusForbidden, err, "logout not allowed")
		return
	}
	ah.JwtService.Reset(w)
}

// exchange sends the validation token request and gets access token and user claims
// (e.g. https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens)
func (ah *AppleHandler) exchange(ctx context.Context, code, redirectURI string, result interface{}) (err error) {

	// check jwt is expired ang recreate new JWT if need
	ok, err := ah.isClientSecretExpired()
	if err != nil || !ok {
		jToken, err := ah.generateClientSecret()
		if err != nil {
			return err
		}
		ah.conf.clientSecret = jToken
	}

	data := url.Values{}
	data.Set("client_id", ah.conf.ClientID)
	data.Set("client_secret", ah.conf.clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI) // redirect URL can't refer to localhost and must have trusted https certificated
	data.Set("grant_type", "authorization_code")

	client := http.Client{Timeout: time.Second * 5}
	req, err := http.NewRequestWithContext(ctx, "POST", ah.endpoint.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("content-type", ContentType)
	req.Header.Add("accept", AcceptHeader)
	req.Header.Add("user-agent", ah.conf.UserAgent) // apple requires a user agent

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	// Apple REST API response either 200 (ok OK) or 400 (if error)
	if res.StatusCode >= 400 {
		return errors.New(fmt.Sprintf("exchange response error code: %d", res.StatusCode))
	}

	err = json.NewDecoder(res.Body).Decode(result)
	defer func() {
		if err := res.Body.Close(); err != nil {
			ah.L.Logf("[ERROR] close request body failed when get access token: %v", err)
		}
	}()
	return err
}

// GetUniqueID decodes the id_token response and returns the unique from "sub" claim to identify the user
func (ah AppleHandler) getTokenClaims(idToken string) (jwt.MapClaims, error) {
	tkn, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})

	if err != nil {
		return nil, err
	}

	claims, ok := tkn.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("can't convert token claims to standard claims")
	}
	return claims, nil
}

// generateClientSecret create the JWT client secret used to make requests to the Apple validation server.
// for more details go to link: https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens#3262048
func (ah *AppleHandler) generateClientSecret() (string, error) {
	if ah.conf.privateKey == nil {
		return "", errors.New("private key can't be empty")
	}
	// Create the Claims
	now := time.Now()
	exp := now.Add(time.Second * 86400).Unix() // default value

	if ah.conf.ClientSecretExpire != 0 {
		exp = now.Add(time.Second * time.Duration(ah.conf.ClientSecretExpire)).Unix()
	}

	claims := &jwt.StandardClaims{
		Issuer:    ah.conf.TeamID,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp,
		Audience:  "https://appleid.apple.com",
		Subject:   ah.conf.ClientID,
	}

	tkn := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tkn.Header["alg"] = "ES256"
	tkn.Header["kid"] = ah.conf.KeyID

	return tkn.SignedString(ah.conf.privateKey)
}

func (ah *AppleHandler) isClientSecretExpired() (bool, error) {

	tkn, _, err := new(jwt.Parser).ParseUnverified(ah.conf.clientSecret, jwt.MapClaims{})

	if err != nil {
		return false, err
	}
	claims, ok := tkn.Claims.(jwt.MapClaims)
	if !ok {
		return false, errors.New("can't convert token claims to standard claims")
	}
	return claims.VerifyExpiresAt(time.Now().Unix(), true), nil
}
func (ah *AppleHandler) parseUserData(user *token.User, jUser string) {

	type UserData struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
		Email string `json:"email"`
	}

	var userData UserData
	err := json.Unmarshal([]byte(jUser), &userData)
	if err != nil {
		ah.L.Logf("[ERROR] failed to parse user data %s: %v", user, err)
		return
	}
	user.Name = fmt.Sprintf("%s %s", userData.Name.FirstName, userData.Name.LastName)
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
	authURL, err := url.Parse(ah.endpoint.AuthURL)
	if err != nil {
		return "", err
	}

	query := authURL.Query()
	query.Set("state", state)
	query.Set("response_type", "code")
	query.Set("response_mode", "form_post")
	query.Set("client_id", ah.conf.ClientID)
	query.Set("scope", extractScopeFn(ah.conf.Scopes))
	query.Set("redirect_uri", ah.makeRedirURL(path))
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil

}

func (ah AppleHandler) makeRedirURL(path string) string {
	elems := strings.Split(path, "/")
	newPath := strings.Join(elems[:len(elems)-1], "/")

	return strings.TrimRight(ah.URL, "/") + strings.TrimRight(newPath, "/") + urlCallbackSuffix
}
