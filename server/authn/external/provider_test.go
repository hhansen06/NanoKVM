package external

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"NanoKVM-Server/authn"
)

func TestNormalizeUsername(t *testing.T) {
	cases := map[string]string{
		"Alice":            "alice",
		`CORP\Alice`:       "alice",
		"alice@corp.local": "alice",
		"  bob.smith  ":    "bob.smith",
	}
	for raw, want := range cases {
		got, err := NormalizeUsername(raw)
		if err != nil || got != want {
			t.Fatalf("%q: got %q %v, want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "@corp", "a b", "x(y)", `CORP\`} {
		if _, err := NormalizeUsername(raw); err == nil {
			t.Fatalf("%q: expected error", raw)
		}
	}
}

func TestMatchGroups(t *testing.T) {
	mappings := []GroupMapping{
		{Group: "CN=KVM-Admins,OU=Groups,DC=example,DC=com", Mapping: Mapping{Role: "admin"}},
		{Group: "kvm-operators", Mapping: Mapping{Role: "user", Permissions: []string{"power"}}},
		{Group: "kvm-viewers", Mapping: Mapping{Role: "user", Permissions: []string{"console.view"}}},
	}
	groups := []string{"cn=kvm-admins, ou=groups, dc=example, dc=com"}
	matched, _ := matchGroups(mappings, groups)
	role, permissions, ok := resolve(matched, nil)
	if !ok || role != authn.RoleAdmin || len(permissions) != 0 {
		t.Fatalf("DN match: %v %v %v", role, permissions, ok)
	}

	groups = []string{"CN=KVM-Operators,OU=Groups,DC=example,DC=com", "CN=KVM-Viewers,OU=Other,DC=example,DC=com", "CN=Domain Users,DC=example,DC=com"}
	matched, names := matchGroups(mappings, groups)
	role, permissions, ok = resolve(matched, nil)
	if !ok || role != authn.RoleUser || !samePermissions(permissions, []authn.Permission{authn.PermPower, authn.PermConsoleView}) || len(names) != 2 {
		t.Fatalf("CN match: %v %v %v %v", role, permissions, ok, names)
	}

	matched, _ = matchGroups(mappings, []string{"CN=Domain Users,DC=example,DC=com"})
	if _, _, ok = resolve(matched, nil); ok {
		t.Fatal("no mapping must refuse the login")
	}
	if role, _, ok = resolve(matched, &Mapping{Role: "user"}); !ok || role != authn.RoleUser {
		t.Fatal("default mapping not applied")
	}
}

func TestMatchPrivLvl(t *testing.T) {
	mappings := []PrivLvlMapping{
		{MinPrivLvl: 15, Mapping: Mapping{Role: "admin"}},
		{MinPrivLvl: 1, Mapping: Mapping{Role: "user"}},
	}
	if m, ok := matchPrivLvl(mappings, 15); !ok || m.Role != "admin" {
		t.Fatal("15 must be admin")
	}
	if m, ok := matchPrivLvl(mappings, 7); !ok || m.Role != "user" {
		t.Fatal("7 must be user")
	}
	if _, ok := matchPrivLvl(mappings, 0); ok {
		t.Fatal("0 must not match")
	}
}

func TestParseAVPairs(t *testing.T) {
	values := parseAVPairs([]string{"Priv-Lvl=15", "nanokvm-perms*power, terminal", "priv-lvl=1", "junk"})
	if values["priv-lvl"] != "15" || values["nanokvm-perms"] != "power, terminal" || len(values) != 2 {
		t.Fatalf("got %v", values)
	}
}

func TestConfigValidate(t *testing.T) {
	conf := Default()
	if err := conf.Validate(); err != nil {
		t.Fatalf("default must validate: %v", err)
	}
	conf.LDAP.Enabled = true
	if err := conf.Validate(); err == nil {
		t.Fatal("enabled ldap without servers must fail")
	}
	conf.LDAP.URLs = []string{"ldaps://dc1.example.com"}
	conf.LDAP.BaseDN = "DC=example,DC=com"
	conf.LDAP.GroupMappings = []GroupMapping{{Group: "kvm", Mapping: Mapping{Role: "superuser"}}}
	if err := conf.Validate(); err == nil {
		t.Fatal("invalid role must fail")
	}
	conf.LDAP.GroupMappings[0].Role = "user"
	conf.LDAP.GroupMappings[0].Permissions = []string{"nope"}
	if err := conf.Validate(); err == nil {
		t.Fatal("invalid permission must fail")
	}
	conf.LDAP.GroupMappings[0].Permissions = []string{"power"}
	if err := conf.Validate(); err != nil {
		t.Fatal(err)
	}
	conf.LDAP.StartTLS = true
	if err := conf.Validate(); err == nil {
		t.Fatal("starttls with ldaps must fail")
	}
	conf.LDAP.StartTLS = false
	conf.TACACS.Enabled = true
	conf.TACACS.Servers = []string{"10.0.0.1"}
	if err := conf.Validate(); err == nil {
		t.Fatal("server without port must fail")
	}
	conf.TACACS.Servers = []string{"10.0.0.1:49"}
	if err := conf.Validate(); err == nil {
		t.Fatal("missing secret must fail")
	}
	conf.TACACS.Secret = "x"
	if err := conf.Validate(); err != nil {
		t.Fatal(err)
	}
	conf.Order = []string{"ldap", "ldap"}
	if err := conf.Validate(); err == nil {
		t.Fatal("duplicate order must fail")
	}
}

func TestConfigStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "external-auth.yaml")
	store := NewConfigStore(path)
	conf, err := store.Get()
	if err != nil || conf.Enabled() {
		t.Fatalf("missing file must load disabled defaults: %v", err)
	}
	conf.TACACS.Enabled = true
	conf.TACACS.Servers = []string{"10.0.0.1:49"}
	conf.TACACS.Secret = "secret"
	conf.TACACS.DefaultMapping = &Mapping{Role: "user", Permissions: []string{"console.view"}}
	if err = store.Save(conf); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config file must be 0600: %v %v", info.Mode(), err)
	}
	store.Reload()
	loaded, err := store.Get()
	if err != nil || !loaded.TACACS.Enabled || loaded.TACACS.Secret != "secret" || loaded.TACACS.DefaultMapping == nil {
		t.Fatalf("reload: %+v %v", loaded.TACACS, err)
	}
	// Changing the returned copy must not change the stored one.
	loaded.TACACS.Secret = "changed"
	again, _ := store.Get()
	if again.TACACS.Secret != "secret" {
		t.Fatal("Get must return a copy")
	}

	if err = os.WriteFile(path, []byte("tacacs: [broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.Reload()
	broken, err := store.Get()
	if err == nil || broken.Enabled() {
		t.Fatal("a broken file must report an error and leave external auth off")
	}
}

type stubProvider struct {
	name     string
	identity *Identity
	err      error
	calls    int
}

func (s *stubProvider) Name() string { return s.name }
func (s *stubProvider) Authenticate(ctx context.Context, req Request) (*Identity, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	copy := *s.identity
	return &copy, nil
}

func withProviders(t *testing.T, providers ...Provider) {
	t.Helper()
	previous := providerFactory
	providerFactory = func(*Config) []Provider { return providers }
	t.Cleanup(func() { providerFactory = previous })
}

func TestAuthenticateChain(t *testing.T) {
	ok := &Identity{Role: authn.RoleUser, Permissions: []authn.Permission{}}
	down := &stubProvider{name: "tacacs", err: unavailable("down")}
	reject := &stubProvider{name: "tacacs", err: invalid("nope")}
	accept := &stubProvider{name: "ldap", identity: ok}

	withProviders(t, down, accept)
	identity, err := Authenticate(context.Background(), Default(), Request{Username: `CORP\Bob`, Password: "pw"})
	if err != nil || identity.Username != "bob" || identity.Source != "ldap" {
		t.Fatalf("fallthrough: %+v %v", identity, err)
	}

	withProviders(t, reject, accept)
	if identity, err = Authenticate(context.Background(), Default(), Request{Username: "bob", Password: "pw"}); err != nil || identity.Source != "ldap" {
		t.Fatalf("a rejection by the first directory must still try the second: %v", err)
	}

	withProviders(t, reject, &stubProvider{name: "ldap", err: unavailable("down")})
	if _, err = Authenticate(context.Background(), Default(), Request{Username: "bob", Password: "pw"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("reject + unavailable must be a rejection, got %v", err)
	}

	withProviders(t, down)
	if _, err = Authenticate(context.Background(), Default(), Request{Username: "bob", Password: "pw"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}

	accept.calls = 0
	withProviders(t, accept)
	if _, err = Authenticate(context.Background(), Default(), Request{Username: "bob", Password: ""}); !errors.Is(err, ErrInvalidCredentials) || accept.calls != 0 {
		t.Fatal("an empty password must never reach a directory")
	}

	withProviders(t)
	if _, err = Authenticate(context.Background(), Default(), Request{Username: "bob", Password: "pw"}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected disabled, got %v", err)
	}
}
