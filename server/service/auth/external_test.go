package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"NanoKVM-Server/authn"
	"NanoKVM-Server/authn/external"
	"NanoKVM-Server/middleware"

	"github.com/gin-gonic/gin"
)

// fakeDirectory replaces the directory chain for the login handler.
type fakeDirectory struct {
	identities map[string]*external.Identity // "user/password" -> identity
	down       bool
	calls      []string
}

func (f *fakeDirectory) authenticate(ctx context.Context, conf *external.Config, req external.Request) (*external.Identity, error) {
	f.calls = append(f.calls, req.Username)
	if f.down {
		return nil, external.ErrUnavailable
	}
	username, err := external.NormalizeUsername(req.Username)
	if err != nil {
		return nil, external.ErrInvalidCredentials
	}
	identity, ok := f.identities[username+"/"+req.Password]
	if !ok {
		return nil, external.ErrInvalidCredentials
	}
	copy := *identity
	copy.Username = username
	return &copy, nil
}

func useExternal(t *testing.T, directory *fakeDirectory) *external.Store {
	t.Helper()
	store := external.NewConfigStore(filepath.Join(t.TempDir(), "external-auth.yaml"))
	conf := external.Default()
	conf.SessionDuration = 600
	conf.TACACS.Enabled = true
	conf.TACACS.Servers = []string{"127.0.0.1:49"}
	conf.TACACS.Secret = "secret"
	if err := store.Save(conf); err != nil {
		t.Fatal(err)
	}
	originalStore := external.DefaultConfigStore
	originalAuth := externalAuthenticate
	external.DefaultConfigStore = store
	externalAuthenticate = directory.authenticate
	t.Cleanup(func() {
		external.DefaultConfigStore = originalStore
		externalAuthenticate = originalAuth
	})
	return store
}

func externalRouter() *gin.Engine {
	service := NewService()
	router := gin.New()
	router.POST("/login", service.Login)
	authenticated := router.Group("/").Use(middleware.CheckToken())
	authenticated.GET("/account", service.GetAccount)
	authenticated.POST("/password", service.ChangePassword)
	admin := router.Group("/").Use(middleware.CheckToken(), middleware.RequireRole(authn.RoleAdmin))
	admin.GET("/users", service.ListUsers)
	admin.PUT("/users/:username", service.UpdateUser)
	admin.POST("/users/:username/password", service.ChangeUserPassword)
	admin.GET("/external", service.GetExternalAuth)
	admin.PUT("/external", service.SetExternalAuth)
	return router
}

func loginCode(t *testing.T, router http.Handler, username, password string) (int, int) {
	t.Helper()
	body := map[string]any{"username": username, "password": encryptForRequest(password)}
	recorder := requestJSONRecorder(router, http.MethodPost, "/login", body, nil)
	var rsp struct {
		Code int `json:"code"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &rsp)
	return recorder.Code, rsp.Code
}

func TestExternalLoginCreatesAndUpdatesAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := useTestStore(authn.NewStore(filepath.Join(t.TempDir(), "pwd")))
	defer restore()
	directory := &fakeDirectory{identities: map[string]*external.Identity{
		"alice/alice-pw": {Source: "tacacs", Role: authn.RoleUser, Permissions: []authn.Permission{authn.PermConsoleView}},
	}}
	useExternal(t, directory)
	router := externalRouter()

	cookie := loginCookie(t, router, `CORP\Alice`, "alice-pw")
	if cookie.MaxAge != 600 {
		t.Fatalf("external session must use sessionDuration, got MaxAge %d", cookie.MaxAge)
	}
	user, err := authn.DefaultStore.Get("alice")
	if err != nil || user.Source != "tacacs" || user.Role != authn.RoleUser || !authn.Has(user.Permissions, authn.PermConsoleView) {
		t.Fatalf("account not recorded: %+v %v", user, err)
	}
	recorder := requestJSONRecorder(router, http.MethodGet, "/account", nil, cookie)
	if !strings.Contains(recorder.Body.String(), `"source":"tacacs"`) {
		t.Fatalf("account must report its source: %s", recorder.Body.String())
	}

	// The directory promotes alice: the next login takes the new role over.
	directory.identities["alice/alice-pw"] = &external.Identity{Source: "tacacs", Role: authn.RoleAdmin, Permissions: []authn.Permission{}}
	adminCookie := loginCookie(t, router, "alice", "alice-pw")
	if user, _ = authn.DefaultStore.Get("alice"); user.Role != authn.RoleAdmin {
		t.Fatalf("role not updated: %+v", user)
	}

	// An external account has no local password.
	if _, ok, _ := authn.DefaultStore.Authenticate("alice", "alice-pw"); ok {
		t.Fatal("external account authenticated locally")
	}
	body := map[string]any{"currentPassword": encryptForRequest("alice-pw"), "password": encryptForRequest("new-password")}
	recorder = requestJSONRecorder(router, http.MethodPost, "/password", body, adminCookie)
	if !strings.Contains(recorder.Body.String(), "managed by") {
		t.Fatalf("password change must be refused: %s", recorder.Body.String())
	}
	if code := requestJSON(router, http.MethodPut, "/users/alice", map[string]any{"role": "user"}, adminCookie); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if user, _ = authn.DefaultStore.Get("alice"); user.Role != authn.RoleAdmin {
		t.Fatal("role edit of an external account must be refused")
	}
}

func TestExternalAccountDisabledLocally(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := useTestStore(authn.NewStore(filepath.Join(t.TempDir(), "pwd")))
	defer restore()
	directory := &fakeDirectory{identities: map[string]*external.Identity{
		"bob/bob-pw": {Source: "ldap", Role: authn.RoleUser, Permissions: []authn.Permission{}},
	}}
	useExternal(t, directory)
	router := externalRouter()

	bobCookie := loginCookie(t, router, "bob", "bob-pw")
	adminCookie := loginCookie(t, router, "admin", "admin")
	if code := requestJSON(router, http.MethodPut, "/users/bob", map[string]any{"enabled": false}, adminCookie); code != http.StatusOK {
		t.Fatalf("disable status %d", code)
	}
	if code := requestJSON(router, http.MethodGet, "/account", nil, bobCookie); code != http.StatusUnauthorized {
		t.Fatalf("disabled session status %d", code)
	}
	if _, code := loginCode(t, router, "bob", "bob-pw"); code == 0 {
		t.Fatal("a locally disabled external account must not log in")
	}
	if user, _ := authn.DefaultStore.Get("bob"); user.Enabled {
		t.Fatal("login must not re-enable the account")
	}
}

func TestLocalAccountsWinAndSurviveDirectoryOutage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := useTestStore(authn.NewStore(filepath.Join(t.TempDir(), "pwd")))
	defer restore()
	directory := &fakeDirectory{identities: map[string]*external.Identity{
		// The directory knows an "admin" with another password.
		"admin/directory-pw": {Source: "ldap", Role: authn.RoleAdmin, Permissions: []authn.Permission{}},
	}}
	useExternal(t, directory)
	router := externalRouter()

	if _, code := loginCode(t, router, "admin", "directory-pw"); code == 0 {
		t.Fatal("directory credentials must not open a local account")
	}
	if len(directory.calls) != 0 {
		t.Fatalf("a local account name must never reach the directory: %v", directory.calls)
	}
	// CORP\admin normalizes to the local admin; the directory accepts it, but
	// the local account must not be taken over.
	if _, code := loginCode(t, router, `CORP\admin`, "directory-pw"); code == 0 {
		t.Fatal("a normalized directory name must not take over a local account")
	}
	if user, _ := authn.DefaultStore.Get("admin"); user.IsExternal() {
		t.Fatal("local account was converted")
	}

	directory.down = true
	if _, code := loginCode(t, router, "someone", "pw"); code != -3 {
		t.Fatalf("expected 'authentication unavailable', got %d", code)
	}
	loginCookie(t, router, "admin", "admin")
}

func TestExternalSettingsNeverExposeSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := useTestStore(authn.NewStore(filepath.Join(t.TempDir(), "pwd")))
	defer restore()
	store := useExternal(t, &fakeDirectory{})
	router := externalRouter()
	adminCookie := loginCookie(t, router, "admin", "admin")

	recorder := requestJSONRecorder(router, http.MethodGet, "/external", nil, adminCookie)
	if strings.Contains(recorder.Body.String(), `"secret":"secret"`) || !strings.Contains(recorder.Body.String(), `"hasSecret":true`) {
		t.Fatalf("secret leaked or not flagged: %s", recorder.Body.String())
	}

	// Saving without a secret keeps the stored one while the servers stay.
	conf := external.Default()
	conf.TACACS.Enabled = true
	conf.TACACS.Servers = []string{"127.0.0.1:49"}
	conf.TACACS.Secret = ""
	conf.TACACS.Timeout = 7
	recorder = requestJSONRecorder(router, http.MethodPut, "/external", conf, adminCookie)
	if !strings.Contains(recorder.Body.String(), `"code":0`) {
		t.Fatalf("save failed: %s", recorder.Body.String())
	}
	saved, _ := store.Get()
	if saved.TACACS.Secret != "secret" || saved.TACACS.Timeout != 7 {
		t.Fatalf("secret not kept: %+v", saved.TACACS)
	}

	// Pointing the settings at another server must not hand it the stored secret.
	conf.TACACS.Servers = []string{"203.0.113.66:49"}
	recorder = requestJSONRecorder(router, http.MethodPut, "/external", conf, adminCookie)
	if strings.Contains(recorder.Body.String(), `"code":0`) {
		t.Fatalf("a new server without a new secret must be refused: %s", recorder.Body.String())
	}
	if saved, _ = store.Get(); saved.TACACS.Servers[0] != "127.0.0.1:49" {
		t.Fatal("refused settings were stored")
	}

}
