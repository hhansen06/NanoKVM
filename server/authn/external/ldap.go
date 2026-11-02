package external

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type ldapProvider struct {
	conf LDAPConfig
}

func newLDAPProvider(conf LDAPConfig) *ldapProvider {
	return &ldapProvider{conf: conf}
}

func (p *ldapProvider) Name() string { return SourceLDAP }

func (p *ldapProvider) timeout() time.Duration {
	if p.conf.Timeout <= 0 {
		return defaultTimeout * time.Second
	}
	return time.Duration(p.conf.Timeout) * time.Second
}

func (p *ldapProvider) tlsConfig(host string) (*tls.Config, error) {
	config := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: p.conf.InsecureSkipVerify, //nolint:gosec // explicit administrator choice
	}
	if p.conf.CAFile != "" {
		pem, err := os.ReadFile(p.conf.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("caFile contains no PEM certificate")
		}
		config.RootCAs = pool
	}
	return config, nil
}

// dial connects to the first reachable server, in the configured order.
func (p *ldapProvider) dial(ctx context.Context) (*ldap.Conn, error) {
	var lastErr error
	for _, raw := range p.conf.URLs {
		if err := ctx.Err(); err != nil {
			return nil, unavailable("%s", err)
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			lastErr = err
			continue
		}
		tlsConfig, err := p.tlsConfig(parsed.Hostname())
		if err != nil {
			return nil, unavailable("%s", err)
		}
		dialer := &net.Dialer{Timeout: p.timeout()}
		conn, err := ldap.DialURL(raw, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConfig))
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", raw, err)
			continue
		}
		conn.SetTimeout(p.timeout())
		if p.conf.StartTLS && parsed.Scheme == "ldap" {
			if err = conn.StartTLS(tlsConfig); err != nil {
				_ = conn.Close()
				lastErr = fmt.Errorf("%s: starttls: %w", raw, err)
				continue
			}
		}
		return conn, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no server configured")
	}
	return nil, unavailable("%s", lastErr)
}

func (p *ldapProvider) serviceBind(conn *ldap.Conn) error {
	if p.conf.BindDN == "" {
		return nil
	}
	if err := conn.Bind(p.conf.BindDN, p.conf.BindPassword); err != nil {
		return unavailable("service account bind failed: %s", err)
	}
	return nil
}

func (p *ldapProvider) Authenticate(ctx context.Context, req Request) (*Identity, error) {
	// An empty password would turn the user bind into an unauthenticated bind,
	// which many servers accept. Never let it reach the server.
	if req.Password == "" {
		return nil, invalid("empty password")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*p.timeout())
	defer cancel()

	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if err = p.serviceBind(conn); err != nil {
		return nil, err
	}

	attributes := []string{"dn"}
	if p.conf.GroupAttribute != "" {
		attributes = append(attributes, p.conf.GroupAttribute)
	}
	filter := strings.ReplaceAll(p.conf.UserFilter, "%s", ldap.EscapeFilter(req.Username))
	result, err := conn.Search(ldap.NewSearchRequest(
		p.conf.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(p.timeout().Seconds()), false, filter, attributes, nil,
	))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, unavailable("user search failed: %s", err)
	}
	if result == nil || len(result.Entries) == 0 {
		return nil, invalid("user not found")
	}
	if len(result.Entries) > 1 {
		return nil, invalid("userFilter matches more than one entry")
	}
	entry := result.Entries[0]

	if err = conn.Bind(entry.DN, req.Password); err != nil {
		if isLDAPRejection(err) {
			return nil, invalid("bind as user rejected")
		}
		return nil, unavailable("bind as user failed: %s", err)
	}

	groups := []string{}
	if p.conf.GroupAttribute != "" {
		groups = append(groups, entry.GetAttributeValues(p.conf.GroupAttribute)...)
	}
	if p.conf.GroupSearchFilter != "" {
		found, searchErr := p.searchGroups(conn, entry.DN, req.Username)
		if searchErr != nil {
			return nil, searchErr
		}
		groups = append(groups, found...)
	}

	matched, names := matchGroups(p.conf.GroupMappings, groups)
	role, permissions, ok := resolve(matched, p.conf.DefaultMapping)
	if !ok {
		return nil, invalid("no group mapping matches (groups: %s)", strings.Join(groups, "; "))
	}
	details := make([]string, 0, len(names))
	for _, name := range names {
		details = append(details, "group: "+name)
	}
	if len(names) == 0 {
		details = append(details, "default mapping")
	}
	return &Identity{Role: role, Permissions: permissions, Details: details}, nil
}

// searchGroups finds group entries that list the user. The search runs as the
// service account again: the user itself may not be allowed to read groups.
func (p *ldapProvider) searchGroups(conn *ldap.Conn, userDN, username string) ([]string, error) {
	if err := p.serviceBind(conn); err != nil {
		return nil, err
	}
	base := p.conf.GroupSearchBaseDN
	if base == "" {
		base = p.conf.BaseDN
	}
	filter := strings.NewReplacer(
		"%u", ldap.EscapeFilter(username),
		"%d", ldap.EscapeFilter(userDN),
	).Replace(p.conf.GroupSearchFilter)
	result, err := conn.Search(ldap.NewSearchRequest(
		base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, int(p.timeout().Seconds()), false, filter, []string{"dn"}, nil,
	))
	if err != nil {
		return nil, unavailable("group search failed: %s", err)
	}
	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		groups = append(groups, entry.DN)
	}
	return groups, nil
}

// isLDAPRejection reports whether the server answered a bind with a refusal
// (wrong password, locked or expired account) instead of failing to answer.
func isLDAPRejection(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultInappropriateAuthentication) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation)
}
