package external

import (
	"context"
	"errors"
	"net"
	"testing"

	"NanoKVM-Server/authn"

	"github.com/nwaples/tacplus"
)

const testSecret = "s3cr3t"

// fakeTACACS answers like a tac_plus server with a fixed user base.
type fakeTACACS struct {
	users map[string]string   // username -> password
	args  map[string][]string // username -> authorization av-pairs; nil = denied
}

func (f *fakeTACACS) HandleAuthenStart(ctx context.Context, a *tacplus.AuthenStart, s *tacplus.ServerSession) *tacplus.AuthenReply {
	password := string(a.Data)
	if a.AuthenType == tacplus.AuthenTypeASCII {
		cont, err := s.GetPass(ctx, "Password: ")
		if err != nil || cont == nil {
			return nil
		}
		password = cont.Message
	}
	if want, ok := f.users[a.User]; ok && want == password {
		return &tacplus.AuthenReply{Status: tacplus.AuthenStatusPass}
	}
	return &tacplus.AuthenReply{Status: tacplus.AuthenStatusFail}
}

func (f *fakeTACACS) HandleAuthorRequest(ctx context.Context, a *tacplus.AuthorRequest, s *tacplus.ServerSession) *tacplus.AuthorResponse {
	if len(a.Arg) != 1 || a.Arg[0] != "service=nanokvm" {
		return &tacplus.AuthorResponse{Status: tacplus.AuthorStatusFail}
	}
	args, ok := f.args[a.User]
	if !ok {
		return &tacplus.AuthorResponse{Status: tacplus.AuthorStatusFail}
	}
	return &tacplus.AuthorResponse{Status: tacplus.AuthorStatusPassAdd, Arg: args}
}

func (f *fakeTACACS) HandleAcctRequest(ctx context.Context, a *tacplus.AcctRequest, s *tacplus.ServerSession) *tacplus.AcctReply {
	return &tacplus.AcctReply{Status: tacplus.AcctStatusSuccess}
}

func startTACACS(t *testing.T, handler *fakeTACACS, secret string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &tacplus.Server{ServeConn: (&tacplus.ServerConnHandler{
		Handler:    handler,
		ConnConfig: tacplus.ConnConfig{Secret: []byte(secret)},
	}).Serve}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

func newFake() *fakeTACACS {
	return &fakeTACACS{
		users: map[string]string{"alice": "alice-pw", "bob": "bob-pw", "carol": "carol-pw", "dave": "dave-pw", "eve": "eve-pw"},
		args: map[string][]string{
			"alice": {"nanokvm-role=admin"},
			"bob":   {"nanokvm-role=user", "nanokvm-perms=console.control,power"},
			"carol": {"priv-lvl=7"},
			"eve":   {"nanokvm-role=root"},
			// dave: authenticated, but service not authorized
		},
	}
}

func tacacsConfig(servers ...string) TACACSConfig {
	conf := Default().TACACS
	conf.Enabled = true
	conf.Servers = servers
	conf.Secret = testSecret
	conf.Timeout = 2
	conf.PrivLvlMappings = []PrivLvlMapping{
		{MinPrivLvl: 15, Mapping: Mapping{Role: "admin"}},
		{MinPrivLvl: 5, Mapping: Mapping{Role: "user", Permissions: []string{"console.view"}}},
	}
	return conf
}

func TestTACACSRoles(t *testing.T) {
	addr := startTACACS(t, newFake(), testSecret)
	for _, authenType := range []string{"pap", "ascii"} {
		conf := tacacsConfig(addr)
		conf.AuthenType = authenType
		provider := newTACACSProvider(conf)

		cases := []struct {
			user, password string
			role           authn.Role
			permissions    []authn.Permission
			err            error
		}{
			{"alice", "alice-pw", authn.RoleAdmin, []authn.Permission{}, nil},
			{"bob", "bob-pw", authn.RoleUser, []authn.Permission{authn.PermConsoleControl, authn.PermPower}, nil},
			{"carol", "carol-pw", authn.RoleUser, []authn.Permission{authn.PermConsoleView}, nil},
			{"alice", "wrong", "", nil, ErrInvalidCredentials},
			{"dave", "dave-pw", "", nil, ErrInvalidCredentials},
			{"eve", "eve-pw", "", nil, ErrInvalidCredentials},
			{"nobody", "x", "", nil, ErrInvalidCredentials},
		}
		for _, tc := range cases {
			identity, err := provider.Authenticate(context.Background(), Request{Username: tc.user, Password: tc.password, RemoteAddr: "192.0.2.1"})
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("%s/%s: expected %v, got %v", authenType, tc.user, tc.err, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s/%s: %v", authenType, tc.user, err)
			}
			if identity.Role != tc.role || !samePermissions(identity.Permissions, tc.permissions) {
				t.Fatalf("%s/%s: got %s %v", authenType, tc.user, identity.Role, identity.Permissions)
			}
		}
	}
}

func TestTACACSDefaultMappingWhenServiceDenied(t *testing.T) {
	addr := startTACACS(t, newFake(), testSecret)
	conf := tacacsConfig(addr)
	conf.DefaultMapping = &Mapping{Role: "user", Permissions: []string{"console.view"}}
	identity, err := newTACACSProvider(conf).Authenticate(context.Background(), Request{Username: "dave", Password: "dave-pw"})
	if err != nil || identity.Role != authn.RoleUser {
		t.Fatalf("expected default mapping, got %v %v", identity, err)
	}
}

func TestTACACSFailover(t *testing.T) {
	// A closed port first: the provider must move on to the working server.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()
	addr := startTACACS(t, newFake(), testSecret)

	identity, err := newTACACSProvider(tacacsConfig(deadAddr, addr)).Authenticate(context.Background(), Request{Username: "alice", Password: "alice-pw"})
	if err != nil || identity.Role != authn.RoleAdmin {
		t.Fatalf("failover: %v %v", identity, err)
	}

	_, err = newTACACSProvider(tacacsConfig(deadAddr)).Authenticate(context.Background(), Request{Username: "alice", Password: "alice-pw"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
}

func TestTACACSWrongSecretIsNotALogin(t *testing.T) {
	addr := startTACACS(t, newFake(), "other-secret")
	_, err := newTACACSProvider(tacacsConfig(addr)).Authenticate(context.Background(), Request{Username: "alice", Password: "alice-pw"})
	if err == nil {
		t.Fatal("login succeeded with a wrong shared secret")
	}
}

func TestTACACSEmptyPassword(t *testing.T) {
	addr := startTACACS(t, newFake(), testSecret)
	_, err := newTACACSProvider(tacacsConfig(addr)).Authenticate(context.Background(), Request{Username: "alice"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected rejection, got %v", err)
	}
}

func samePermissions(a, b []authn.Permission) bool {
	if len(a) != len(b) {
		return false
	}
	for _, p := range a {
		if !authn.Has(b, p) {
			return false
		}
	}
	return true
}
