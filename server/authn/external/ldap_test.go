package external

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"NanoKVM-Server/authn"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// fakeLDAP is a tiny LDAPv3 server: simple bind, subtree search with a
// substring match on the filter, unbind. Enough to exercise the provider over
// the real protocol.
type fakeLDAP struct {
	mutex     sync.Mutex
	passwords map[string]string              // dn -> password
	entries   map[string]map[string][]string // dn -> attributes
	binds     []string                       // every bind dn, in order
	filters   []string
}

const (
	serviceDN = "cn=svc-kvm,ou=service,dc=example,dc=com"
	aliceDN   = "cn=alice,ou=people,dc=example,dc=com"
	bobDN     = "cn=bob,ou=people,dc=example,dc=com"
	carolDN   = "cn=carol,ou=people,dc=example,dc=com"
)

func newFakeLDAP() *fakeLDAP {
	return &fakeLDAP{
		passwords: map[string]string{serviceDN: "svc-pw", aliceDN: "alice-pw", bobDN: "bob-pw", carolDN: "carol-pw"},
		entries: map[string]map[string][]string{
			aliceDN: {"sAMAccountName": {"alice"}, "memberOf": {"CN=KVM-Admins,OU=Groups,DC=example,DC=com"}},
			bobDN:   {"sAMAccountName": {"bob"}, "memberOf": {"CN=KVM-Operators,OU=Groups,DC=example,DC=com", "CN=Domain Users,DC=example,DC=com"}},
			carolDN: {"sAMAccountName": {"carol"}, "memberOf": {"CN=Domain Users,DC=example,DC=com"}},
			"cn=kvm-viewers,ou=groups,dc=example,dc=com": {"member": {carolDN}},
		},
	}
}

func (f *fakeLDAP) start(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return "ldap://" + listener.Addr().String()
}

func ldapResult(id int64, tag ber.Tag, code uint16) *ber.Packet {
	message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(code), ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	message.AppendChild(op)
	return message
}

func ldapEntry(id int64, dn string, attributes map[string][]string, wanted []string) *ber.Packet {
	message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	for _, name := range wanted {
		values, ok := attributes[name]
		if !ok {
			continue
		}
		attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		for _, value := range values {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
		}
		attribute.AppendChild(set)
		list.AppendChild(attribute)
	}
	op.AppendChild(list)
	message.AppendChild(op)
	return message
}

func (f *fakeLDAP) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil || len(packet.Children) < 2 {
			return
		}
		id, _ := packet.Children[0].Value.(int64)
		op := packet.Children[1]
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			dn, _ := op.Children[1].Value.(string)
			password := op.Children[2].Data.String()
			f.mutex.Lock()
			f.binds = append(f.binds, dn)
			want, exists := f.passwords[dn]
			f.mutex.Unlock()
			code := uint16(ldap.LDAPResultInvalidCredentials)
			if (dn == "" && password == "") || (exists && want == password) {
				code = ldap.LDAPResultSuccess
			}
			_, _ = conn.Write(ldapResult(id, ldap.ApplicationBindResponse, code).Bytes())
		case ldap.ApplicationSearchRequest:
			filter, _ := ldap.DecompileFilter(op.Children[6])
			wanted := []string{}
			for _, attribute := range op.Children[7].Children {
				name, _ := attribute.Value.(string)
				wanted = append(wanted, name)
			}
			f.mutex.Lock()
			f.filters = append(f.filters, filter)
			for dn, attributes := range f.entries {
				if entryMatches(filter, attributes) {
					_, _ = conn.Write(ldapEntry(id, dn, attributes, wanted).Bytes())
				}
			}
			f.mutex.Unlock()
			_, _ = conn.Write(ldapResult(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess).Bytes())
		case ldap.ApplicationUnbindRequest:
			return
		default:
			return
		}
	}
}

// entryMatches checks whether every (attr=value) equality in the filter holds,
// ignoring objectClass.
func entryMatches(filter string, attributes map[string][]string) bool {
	matchedAny := false
	for _, part := range strings.Split(filter, "(") {
		part = strings.TrimRight(part, ")")
		name, value, ok := strings.Cut(part, "=")
		if !ok || name == "objectClass" {
			continue
		}
		found := false
		for _, candidate := range attributes[name] {
			if strings.EqualFold(candidate, value) {
				found = true
			}
		}
		if !found {
			return false
		}
		matchedAny = true
	}
	return matchedAny
}

func ldapConfig(url string) LDAPConfig {
	conf := Default().LDAP
	conf.Enabled = true
	conf.URLs = []string{url}
	conf.BindDN = serviceDN
	conf.BindPassword = "svc-pw"
	conf.BaseDN = "dc=example,dc=com"
	conf.Timeout = 2
	conf.GroupMappings = []GroupMapping{
		{Group: "CN=KVM-Admins,OU=Groups,DC=example,DC=com", Mapping: Mapping{Role: "admin"}},
		{Group: "KVM-Operators", Mapping: Mapping{Role: "user", Permissions: []string{"console.control", "power"}}},
		{Group: "kvm-viewers", Mapping: Mapping{Role: "user", Permissions: []string{"console.view"}}},
	}
	return conf
}

func TestLDAPRoles(t *testing.T) {
	server := newFakeLDAP()
	provider := newLDAPProvider(ldapConfig(server.start(t)))

	identity, err := provider.Authenticate(context.Background(), Request{Username: "alice", Password: "alice-pw"})
	if err != nil || identity.Role != authn.RoleAdmin {
		t.Fatalf("alice: %+v %v", identity, err)
	}
	identity, err = provider.Authenticate(context.Background(), Request{Username: "bob", Password: "bob-pw"})
	if err != nil || identity.Role != authn.RoleUser ||
		!samePermissions(identity.Permissions, []authn.Permission{authn.PermConsoleControl, authn.PermPower}) {
		t.Fatalf("bob: %+v %v", identity, err)
	}
	if _, err = provider.Authenticate(context.Background(), Request{Username: "bob", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err = provider.Authenticate(context.Background(), Request{Username: "nobody", Password: "x"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
	// carol authenticates but is in no mapped group.
	if _, err = provider.Authenticate(context.Background(), Request{Username: "carol", Password: "carol-pw"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unmapped user: %v", err)
	}
}

func TestLDAPGroupSearch(t *testing.T) {
	server := newFakeLDAP()
	conf := ldapConfig(server.start(t))
	conf.GroupAttribute = ""
	conf.GroupSearchFilter = "(&(objectClass=group)(member=%d))"
	identity, err := newLDAPProvider(conf).Authenticate(context.Background(), Request{Username: "carol", Password: "carol-pw"})
	if err != nil || identity.Role != authn.RoleUser || !samePermissions(identity.Permissions, []authn.Permission{authn.PermConsoleView}) {
		t.Fatalf("group search: %+v %v", identity, err)
	}
	// The group search must run as the service account again.
	if last := server.binds[len(server.binds)-1]; last != serviceDN {
		t.Fatalf("group search ran as %q", last)
	}
}

func TestLDAPEmptyPasswordNeverBinds(t *testing.T) {
	server := newFakeLDAP()
	provider := newLDAPProvider(ldapConfig(server.start(t)))
	if _, err := provider.Authenticate(context.Background(), Request{Username: "alice", Password: ""}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected rejection, got %v", err)
	}
	if len(server.binds) != 0 {
		t.Fatalf("an empty password reached the server: %v", server.binds)
	}
}

func TestLDAPFilterInjection(t *testing.T) {
	server := newFakeLDAP()
	provider := newLDAPProvider(ldapConfig(server.start(t)))
	_, _ = provider.Authenticate(context.Background(), Request{Username: "*)(sAMAccountName=alice", Password: "alice-pw"})
	for _, filter := range server.filters {
		if strings.Contains(filter, "(sAMAccountName=alice)") {
			t.Fatalf("username was not escaped: %s", filter)
		}
	}
}

func TestLDAPWrongServiceAccountIsUnavailable(t *testing.T) {
	server := newFakeLDAP()
	conf := ldapConfig(server.start(t))
	conf.BindPassword = "wrong"
	if _, err := newLDAPProvider(conf).Authenticate(context.Background(), Request{Username: "alice", Password: "alice-pw"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
}

func TestLDAPFailover(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadURL := "ldap://" + dead.Addr().String()
	_ = dead.Close()
	server := newFakeLDAP()
	conf := ldapConfig(server.start(t))
	conf.URLs = append([]string{deadURL}, conf.URLs...)
	if identity, err := newLDAPProvider(conf).Authenticate(context.Background(), Request{Username: "alice", Password: "alice-pw"}); err != nil || identity.Role != authn.RoleAdmin {
		t.Fatalf("failover: %+v %v", identity, err)
	}
	conf.URLs = []string{deadURL}
	if _, err := newLDAPProvider(conf).Authenticate(context.Background(), Request{Username: "alice", Password: "alice-pw"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
}
