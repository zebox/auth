package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testCustomLoader struct{} // implement custom private key loader interface

func TestAppleHandler_NewApple(t *testing.T) {

	testIdToken := `eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJ0ZXN0LmF1dGguZXhhbXBsZS5jb20iLCJzdWIiOiIwMDExMjIuNzg5M2Y3NmViZWRjNDExOGE3OTE3ZGFiOWE4YTllYTkuMTEyMiIsImlzcyI6Imh0dHBzOi8vYXBwbGVpZC5hcHBsZS5jb20iLCJleHAiOiIxOTIwNjQ3MTgyIiwiaWF0IjoiMTYyMDYzNzE4MiIsImVtYWlsIjoidGVzdEBlbWFpbC5jb20ifQ.CQCPa7ov-IdZ5bEKfhhnxEXafMAM_t6mj5OAnaoyy0A`
	p := Params{
		URL:     "http://localhost",
		Issuer:  "test-issuer",
		Cid:     "cid",
		Csecret: "cs",
	}

	aCfg := AppleConfig{
		ClientID:           "auth.example.com",
		TeamID:             "AA11BB22CC",
		KeyID:              "BS2A79VCTT",
		UserAgent:          "test-user-agent",
		ClientSecretExpire: 3600,
		Scopes:             []string{"name", "email"},
	}
	cl := testCustomLoader{}

	ah, err := NewApple("apple-provider-test", p, aCfg, oauth2.Endpoint{}, cl)
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)
	assert.Equal(t, ah.name, "apple-provider-test")
	assert.Equal(t, ah.conf.ClientID, aCfg.ClientID)
	assert.NotEmpty(t, ah.conf.privateKey)
	assert.NotEmpty(t, ah.conf.clientSecret)

	tknClaims, err := ah.getTokenClaims(testIdToken)
	assert.NoError(t, err)

	// testing mapUser
	u := ah.mapUser(tknClaims)
	t.Logf("%+v", u)
	assert.Equal(t, u.ID, "apple_001122.7893f76ebedc4118a7917dab9a8a9ea9.1122")
	assert.Equal(t, u.Email, "test@email.com")

}

// TestAppleHandler_LoadPrivateKey need for testing pre-defined loader from local file
func TestAppleHandler_LoadPrivateKey(t *testing.T) {
	testValidKey := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgTxaHXzyuM85Znw7y
SJ9XeeC8gqcpE/VLhZHGsnPPiPagCgYIKoZIzj0DAQehRANCAATnwlOv7I6eC3Ec
/+GeYXT+hbcmhEVveDqLmNcHiXCR9XxJZXtpMRlcRfY8eaJpUdig27dfsbvpnfX5
Ivx5tHkv
-----END PRIVATE KEY-----`
	testPrivKeyFileName := "privKeyTest.tmp"

	dir, err := ioutil.TempDir(os.TempDir(), testPrivKeyFileName)
	assert.NoError(t, err)
	assert.NotNil(t, dir)
	if err != nil {
		log.Fatal(err)
		return
	}

	defer func() {
		err := os.RemoveAll(dir)
		require.NoError(t, err)
	}()

	tmpfn := filepath.Join(dir, testPrivKeyFileName)
	if err = ioutil.WriteFile(tmpfn, []byte(testValidKey), 0666); err != nil {
		assert.NoError(t, err)
		log.Fatal(err)
		return
	}
	assert.NoError(t, err)
	p := Params{
		URL:     "http://localhost",
		Issuer:  "test-issuer",
		Cid:     "cid",
		Csecret: "cs",
	}

	aCfg := AppleConfig{
		ClientID:           "auth.example.com",
		TeamID:             "AA11BB22CC",
		KeyID:              "BS2A79VCTT",
		UserAgent:          "test-user-agent",
		ClientSecretExpire: 3600,
		Scopes:             []string{"name", "email"},
	}

	ah, err := NewApple("apple-provider-test", p, aCfg, oauth2.Endpoint{}, LoadApplePrivateKeyFromFile(tmpfn))
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)
	assert.Equal(t, ah.name, "apple-provider-test")
	assert.Equal(t, ah.conf.ClientID, aCfg.ClientID)
	assert.NotEmpty(t, ah.conf.privateKey)
	assert.NotEmpty(t, ah.conf.clientSecret)

}

func TestAppleHandlerGenerateClientSecret(t *testing.T) {
	ah := &AppleHandler{}
	tkn, err := ah.generateClientSecret()
	assert.Error(t, err)
	assert.Empty(t, tkn)

	ah, err = prepareAppleHandlerTest()
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)

	tkn, err = ah.generateClientSecret()
	assert.NoError(t, err)
	assert.NotEmpty(t, tkn)
}

func TestAppleHandlerIsTokenExpire(t *testing.T) {
	expiredToken := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnby10ZXN0IiwiaWF0IjoxNjIwNjQxMDUyLCJleHAiOjE2MjA2NDExMjgsImF1ZCI6ImdpdGh1Yi5jb20vZ28tcGtnei9hdXRoIiwic3ViIjoiZ29sYW5nQHRlc3QuY29tIn0.ZPDgw9pnJGbc3ez-EFVsFHRwlv0s0K7VjKKbEPsGCS0`
	validToken := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnby10ZXN0IiwiaWF0IjoxNjIwNjQxMDUyLCJleHAiOjQwODIwOTA3NTEsImF1ZCI6ImdpdGh1Yi5jb20vZ28tcGtnei9hdXRoIiwic3ViIjoiZ29sYW5nQHRlc3QuY29tIn0.tY9FB-DNSuv1y0PcpOgwcgnxxV-RJbrRSOb5b-4RiGQ`

	ah, err := prepareAppleHandlerTest()
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)

	ah.conf.clientSecret = expiredToken
	isExp, err := ah.isClientSecretExpired()
	assert.False(t, isExp)
	assert.NoError(t, err)

	ah.conf.clientSecret = validToken
	isExp, err = ah.isClientSecretExpired()
	assert.True(t, isExp)
	assert.NoError(t, err)
}

func TestPrepareLoginURL(t *testing.T) {
	ah, err := prepareAppleHandlerTest()
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)

	lURL, err := ah.prepareLoginURL("1112233", "apple-test/login")
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(lURL, ah.endpoint.AuthURL))

	checkURL, err := url.Parse(lURL)
	assert.NoError(t, err)
	q := checkURL.Query()
	assert.Equal(t, q.Get("state"), "1112233")
	assert.Equal(t, q.Get("response_type"), "code")
	assert.Equal(t, q.Get("response_mode"), "form_post")
	assert.Equal(t, q.Get("client_id"), ah.conf.ClientID)
}

func TestAppleHandlerMakeRedirURL(t *testing.T) {
	cases := []struct{ rootURL, route, out string }{
		{"localhost:8080/", "/my/auth/path/apple", "localhost:8080/my/auth/path/callback"},
		{"localhost:8080", "/auth/apple", "localhost:8080/auth/callback"},
		{"localhost:8080/", "/auth/apple", "localhost:8080/auth/callback"},
		{"localhost:8080", "/", "localhost:8080/callback"},
		{"localhost:8080/", "/", "localhost:8080/callback"},
		{"mysite.com", "", "mysite.com/callback"},
	}

	ah, err := prepareAppleHandlerTest()
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)

	for i := range cases {
		c := cases[i]
		ah.URL = c.rootURL
		assert.Equal(t, c.out, ah.makeRedirURL(c.route))
	}
}

func TestAppleHandler_LoginHandler(t *testing.T) {
	teardown := prepareAppleOauthTest(t, 8981, 8982)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	// check non-admin, permanent
	resp, err := client.Get("http://localhost:8981/login?site=remark")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)

	assert.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.Equal(t, 2678400, resp.Cookies()[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
	assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

	u := token.User{}
	err = json.Unmarshal(body, &u)
	assert.Nil(t, err)
	assert.Equal(t, token.User{ID: "mock_userid1", Email: "test@example.go", Attributes: map[string]interface{}{"email_verified": true}}, u)

	tk := resp.Cookies()[0].Value
	jwtSvc := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31})

	claims, err := jwtSvc.Parse(tk)
	require.NoError(t, err)
	t.Log(claims)
	assert.Equal(t, "go-pkgz/auth", claims.Issuer)
	assert.Equal(t, "remark", claims.Audience)

}

func TestAppleHandler_LogoutHandler(t *testing.T) {

	teardown := prepareAppleOauthTest(t, 8691, 8692)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	req, err := http.NewRequest("GET", "http://localhost:8691/logout", nil)
	require.Nil(t, err)
	resp, err := client.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 403, resp.StatusCode, "user not lagged in")

	req, err = http.NewRequest("GET", "http://localhost:8691/logout", nil)
	require.NoError(t, err)
	expiration := int(365 * 24 * time.Hour.Seconds()) //nolint
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err = client.Do(req)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name, "token cookie cleared")
	assert.Equal(t, "", resp.Cookies()[0].Value)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name, "xsrf cookie cleared")
	assert.Equal(t, "", resp.Cookies()[1].Value)

}

func (cl testCustomLoader) LoadPrivateKey() ([]byte, error) {

	// valid p8 key
	testValidKey := []byte(`-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgTxaHXzyuM85Znw7y
SJ9XeeC8gqcpE/VLhZHGsnPPiPagCgYIKoZIzj0DAQehRANCAATnwlOv7I6eC3Ec
/+GeYXT+hbcmhEVveDqLmNcHiXCR9XxJZXtpMRlcRfY8eaJpUdig27dfsbvpnfX5
Ivx5tHkv
-----END PRIVATE KEY-----`)

	//testWrongKey := []byte(`MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJJC+7viVTZtE1yM0IX+Zt8ZNJW6RYLg8fovmEo8AfDo+dvE/ssFSiMSqRcmHhp5y0K+LHAy9QSz8lrIivdPC19LEc9dFUzAM3aCKpVCAbz51OCYRV6/01kyMPiIMYItG1RufF+XJCYHxHZY9JyuheOgGaqmdOIZQmcTwk6r3VYtAgMBAAECgYAuJ5caxiSPxUHr3b/b2NkLo/+VFC/lSijyA1zyaBdQt6RJNtQUqvmnMbdMR8oOHssGp86MJXhuYH6lKU25FyeGEReXIuvoz25z1mLUxbzSAjuWWNq32sfuBx+sYMUMKrt0W0wJrbofRwIElTDaFBXP/arycALT323hWAOp5RKo/QJBAO0tAEBgvq9VqakVHo8pnoN+MFKIQ8pl03zvHWRFmxIsPj1iCO8JeHnRVhr2V8mpHwx+/oHwFDYQWG57FniH8cMCQQCd3sP3EvTwgXctpUNLxfzURZMEOxXEE84iUM2UkrQ4Sb7tJwCEezfIofC7GPQv1yJ8hN9guX0W+lgmiNbScKlPAkBPmkb3VIErf+jNoxT6n9Ff+L5nNOzrxXlR+T84JFSDqO3K1FiDQf55hFUN/5g/Ss/s9cKeAeIGsz269vz3v0jZAkBmlO7vaEEC2o1vepic7xzXbhIWyLHfBCOIxsqfBSjX/otynEpIy6w20YuUd6WMRJXjJY/k0QLIYInRGE/G1HAfAkEAx3UnSl/XLJLXkNawVNhgxWgQWpb7st5rug+MUVqtj3Qtfp55GswBzvHaaMCJOizZc+UjWc4fhRLoi3prBAKAXA==`)

	return testValidKey, nil
}

func prepareTestPrivateKey(t *testing.T) (filePath string, cancelFunc context.CancelFunc) {
	testValidKey := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgTxaHXzyuM85Znw7y
SJ9XeeC8gqcpE/VLhZHGsnPPiPagCgYIKoZIzj0DAQehRANCAATnwlOv7I6eC3Ec
/+GeYXT+hbcmhEVveDqLmNcHiXCR9XxJZXtpMRlcRfY8eaJpUdig27dfsbvpnfX5
Ivx5tHkv
-----END PRIVATE KEY-----`
	testPrivKeyFileName := "privKeyTest.tmp"

	dir, err := ioutil.TempDir(os.TempDir(), testPrivKeyFileName)
	assert.NoError(t, err)
	assert.NotNil(t, dir)
	if err != nil {
		log.Fatal(err)
		return "", nil
	}

	filePath = filepath.Join(dir, testPrivKeyFileName)
	if err = ioutil.WriteFile(filePath, []byte(testValidKey), 0666); err != nil {
		assert.NoError(t, err)
		log.Fatal(err)
		return "", nil
	}
	assert.NoError(t, err)
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Second*60)

	go func() {
		<-ctx.Done()
		require.NoError(t, os.RemoveAll(dir))
	}()
	return filePath, cancelCtx
}

func prepareAppleHandlerTest() (*AppleHandler, error) {

	p := Params{
		URL:     "http://localhost",
		Issuer:  "test-issuer",
		Cid:     "cid",
		Csecret: "cs",
	}

	aCfg := AppleConfig{
		ClientID:           "auth.example.com",
		TeamID:             "AA11BB22CC",
		KeyID:              "BS2A79VCTT",
		UserAgent:          "test-user-agent",
		ClientSecretExpire: 3600,
		Scopes:             []string{"name", "email"},
	}
	cl := testCustomLoader{}
	return NewApple("apple-provider-test", p, aCfg, oauth2.Endpoint{}, cl)
}

func prepareAppleOauthTest(t *testing.T, loginPort, authPort int) func() {
	provider, err := prepareAppleHandlerTest()
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, provider)

	filePath, cancelCtx := prepareTestPrivateKey(t)
	if cancelCtx == nil {
		t.Fatal(errors.New("failed to create test private key file"))
		return nil
	}

	provider.name = "mock"
	provider.endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("http://localhost:%d/login/oauth/authorize", authPort),
		TokenURL: fmt.Sprintf("http://localhost:%d/login/oauth/access_token", authPort),
	}
	provider.PrivateKeyLoader = LoadApplePrivateKeyFromFile(filePath)
	provider.mapUser = func(claims jwt.MapClaims) token.User {
		var usr token.User
		if uid, ok := claims["sub"]; ok {
			usr.ID = fmt.Sprintf("mock_%s", uid.(string))
		}
		if email, ok := claims["email"]; ok {
			usr.Email = email.(string)
		}
		if emailVerified, ok := claims["email_verified"]; ok {
			usr.SetBoolAttr("email_verified", emailVerified.(string) == "true")
		}
		return usr
	}

	jwtService := token.NewService(token.Opts{
		SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false, TokenDuration: time.Hour, CookieDuration: days31,
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			if claims.User != nil {
				switch claims.User.ID {
				case "mock_myuser2":
					claims.User.SetBoolAttr("admin", true)
				case "mock_myuser1":
					claims.User.Picture = "http://example.com/custom.png"
				}
			}
			return claims
		}),
	})

	params := Params{URL: "url", Cid: "cid", Csecret: "csecret", JwtService: jwtService,
		Issuer: "go-pkgz/auth", L: logger.Std}
	provider.Params = params

	svc := Service{Provider: provider}

	ts := &http.Server{Addr: fmt.Sprintf(":%d", loginPort), Handler: http.HandlerFunc(svc.Handler)}

	count := 0
	useIds := []string{"myuser1", "myuser2"} // user for first ans second calls

	oauth := &http.Server{
		Addr: fmt.Sprintf(":%d", authPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[MOCK OAUTH] request %s %s %+v", r.Method, r.URL, r.Header)
			switch {
			case strings.HasPrefix(r.URL.Path, "/login/oauth/authorize"):
				state := r.URL.Query().Get("state")
				w.Header().Add("Location", fmt.Sprintf("http://localhost:%d/callback?state=%s", loginPort, state))
				w.WriteHeader(302)
			case strings.HasPrefix(r.URL.Path, "/login/oauth/access_token"):
				res := `{
					"access_token":"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3",
					"token_type":"bearer",
					"expires_in":3600,
					"refresh_token":"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk",
					"id_token":"eyJhbGciOiJIUzI1NiJ9.eyJhdF9oYXNoIjoiSmgySTAtRVBZZEMyM3RoS24xWkgwUSIsImF1ZCI6ImdvLnBrZy50ZXN0Lm9yZyIsInN1YiI6InVzZXJpZDEiLCJub25jZV9zdXBwb3J0ZWQiOiJ0cnVlIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIiwiYXV0aF90aW1lIjoiMjAyMS0wNS0xMFQxMjowMjowMC4yMDFaIiwiaXNzIjoiaHR0cDovL2dvLmxvY2FsaG9zdC50ZXN0IiwiZXhwIjoiMjAyOS0wNS0xMFQxMjowMjowMC4yMDFaIiwiaWF0IjoiMjAyMS0wNS0xMFQxMjowMjowMC4yMDFaIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuZ28ifQ.Agf569IMQO2w1LdBd3RGLFXUrEy7oT3wVfqHOPDqkgA"
					}`
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(200)
				_, err := w.Write([]byte(res))
				assert.NoError(t, err)
			case strings.HasPrefix(r.URL.Path, "/user"):
				res := fmt.Sprintf(`{
					"id": "%s",
					"name":"blah",
					"picture":"http://exmple.com/pic1.png"
					}`, useIds[count])
				count++
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(200)
				_, err := w.Write([]byte(res))
				assert.NoError(t, err)
			default:
				t.Fatalf("unexpected oauth request %s %s", r.Method, r.URL)
			}
		}),
	}

	go func() { _ = oauth.ListenAndServe() }()
	go func() { _ = ts.ListenAndServe() }()

	time.Sleep(time.Millisecond * 100) // let them start

	return func() {

		assert.NoError(t, ts.Close())
		assert.NoError(t, oauth.Close())
		cancelCtx() // delete test private key file
	}
}
