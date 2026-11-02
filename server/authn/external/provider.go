// Package external authenticates device accounts against LDAP directories and
// TACACS+ servers. A successful login yields an Identity (role and grants
// resolved from the directory's groups or attributes) that the caller records
// in the local account store, so sessions, revocation and permission checks
// work exactly as for local accounts.
package external

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"NanoKVM-Server/authn"

	log "github.com/sirupsen/logrus"
)

var (
	// ErrInvalidCredentials means a directory answered and rejected the login,
	// including a valid password whose account matches no mapping.
	ErrInvalidCredentials = errors.New("invalid username or password")
	// ErrUnavailable means no directory could give an answer.
	ErrUnavailable = errors.New("external authentication unavailable")
	// ErrDisabled means no directory is enabled.
	ErrDisabled = errors.New("external authentication is disabled")
)

// Request is one login attempt.
type Request struct {
	Username   string
	Password   string
	RemoteAddr string
}

// Identity is an account a directory has authenticated and authorized.
type Identity struct {
	Username    string
	Source      string
	Role        authn.Role
	Permissions []authn.Permission
	// Details lists what the decision was based on (matched groups or
	// attribute-value pairs). It is shown by the connection test only.
	Details []string
}

// Provider authenticates against one kind of directory.
type Provider interface {
	Name() string
	Authenticate(ctx context.Context, req Request) (*Identity, error)
}

// Providers builds the enabled providers in the configured order.
func Providers(conf *Config) []Provider {
	providers := make([]Provider, 0, 2)
	for _, name := range conf.Order {
		switch name {
		case SourceLDAP:
			if conf.LDAP.Enabled {
				providers = append(providers, newLDAPProvider(conf.LDAP))
			}
		case SourceTACACS:
			if conf.TACACS.Enabled {
				providers = append(providers, newTACACSProvider(conf.TACACS))
			}
		}
	}
	return providers
}

// providerFactory is replaced in tests.
var providerFactory = Providers

// Authenticate tries every enabled directory in order and returns the first
// identity. When none accepts the login, ErrInvalidCredentials is returned as
// soon as any directory rejected it (so an unreachable second server cannot be
// used to tell valid usernames apart), otherwise ErrUnavailable.
func Authenticate(ctx context.Context, conf *Config, req Request) (*Identity, error) {
	username, err := NormalizeUsername(req.Username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if req.Password == "" {
		return nil, ErrInvalidCredentials
	}
	req.Username = username

	providers := providerFactory(conf)
	if len(providers) == 0 {
		return nil, ErrDisabled
	}
	rejected := false
	for _, provider := range providers {
		identity, err := provider.Authenticate(ctx, req)
		switch {
		case err == nil:
			identity.Username = username
			identity.Source = provider.Name()
			return identity, nil
		case errors.Is(err, ErrInvalidCredentials):
			log.Infof("%s: login rejected for %q: %s", provider.Name(), username, err)
			rejected = true
		default:
			log.Warnf("%s: login for %q could not be checked: %s", provider.Name(), username, err)
		}
	}
	if rejected {
		return nil, ErrInvalidCredentials
	}
	return nil, ErrUnavailable
}

// TestProvider authenticates against one named directory only, for the
// connection test in the settings page. Errors carry the provider's detail.
func TestProvider(ctx context.Context, conf *Config, name string, req Request) (*Identity, error) {
	username, err := NormalizeUsername(req.Username)
	if err != nil {
		return nil, err
	}
	if req.Password == "" {
		return nil, errors.New("password is required")
	}
	req.Username = username
	var provider Provider
	switch name {
	case SourceLDAP:
		provider = newLDAPProvider(conf.LDAP)
	case SourceTACACS:
		provider = newTACACSProvider(conf.TACACS)
	default:
		return nil, fmt.Errorf("unknown directory %q", name)
	}
	identity, err := provider.Authenticate(ctx, req)
	if err != nil {
		return nil, err
	}
	identity.Username = username
	identity.Source = name
	return identity, nil
}

// NormalizeUsername turns "DOMAIN\user" and "user@domain" into "user" and
// lowercases it, so one person always maps to one device account. The result
// must be a valid device username.
func NormalizeUsername(raw string) (string, error) {
	username := strings.TrimSpace(raw)
	if index := strings.LastIndex(username, `\`); index >= 0 {
		username = username[index+1:]
	}
	if index := strings.Index(username, "@"); index >= 0 {
		username = username[:index]
	}
	username = strings.ToLower(username)
	if err := authn.ValidateUsername(username); err != nil {
		return "", err
	}
	return username, nil
}

// invalid wraps a rejection with its reason for the log and the test page.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidCredentials, fmt.Sprintf(format, args...))
}

// unavailable wraps an infrastructure failure.
func unavailable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnavailable, fmt.Sprintf(format, args...))
}
