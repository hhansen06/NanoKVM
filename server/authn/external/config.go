package external

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"NanoKVM-Server/authn"

	"gopkg.in/yaml.v3"
)

// ConfigFile holds the external authentication settings. It is kept apart from
// server.yaml because it carries the LDAP bind password and the TACACS+ shared
// secret, and is written with 0600.
const ConfigFile = "/etc/kvm/external-auth.yaml"

const (
	SourceLDAP   = "ldap"
	SourceTACACS = "tacacs"

	defaultTimeout         = 5
	defaultSessionDuration = 8 * 60 * 60
	maxTimeout             = 60
)

// Mapping is the role and grants an account receives when a rule matches.
// Grants only matter for the user role; administrators hold everything.
type Mapping struct {
	Role        string   `yaml:"role" json:"role"`
	Permissions []string `yaml:"permissions,omitempty" json:"permissions"`
}

type GroupMapping struct {
	// Group is either a full DN (compared as a DN) or a bare group name that is
	// compared against the first RDN value (usually the CN).
	Group   string `yaml:"group" json:"group"`
	Mapping `yaml:",inline"`
}

type PrivLvlMapping struct {
	MinPrivLvl int `yaml:"minPrivLvl" json:"minPrivLvl"`
	Mapping    `yaml:",inline"`
}

type LDAPConfig struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`
	URLs               []string `yaml:"urls" json:"urls"`
	StartTLS           bool     `yaml:"startTLS" json:"startTLS"`
	CAFile             string   `yaml:"caFile,omitempty" json:"caFile"`
	InsecureSkipVerify bool     `yaml:"insecureSkipVerify" json:"insecureSkipVerify"`
	BindDN             string   `yaml:"bindDN,omitempty" json:"bindDN"`
	BindPassword       string   `yaml:"bindPassword,omitempty" json:"bindPassword"`
	BaseDN             string   `yaml:"baseDN" json:"baseDN"`
	// UserFilter finds the account; %s is replaced by the escaped username.
	UserFilter string `yaml:"userFilter" json:"userFilter"`
	// GroupAttribute is read from the user entry (memberOf on AD and on
	// OpenLDAP with the memberof overlay).
	GroupAttribute string `yaml:"groupAttribute,omitempty" json:"groupAttribute"`
	// GroupSearchFilter optionally searches group entries instead, e.g.
	// (&(objectClass=posixGroup)(memberUid=%u)) or (member=%d).
	// %u is the escaped username, %d the escaped user DN.
	GroupSearchFilter string         `yaml:"groupSearchFilter,omitempty" json:"groupSearchFilter"`
	GroupSearchBaseDN string         `yaml:"groupSearchBaseDN,omitempty" json:"groupSearchBaseDN"`
	Timeout           int            `yaml:"timeout" json:"timeout"`
	GroupMappings     []GroupMapping `yaml:"groupMappings" json:"groupMappings"`
	DefaultMapping    *Mapping       `yaml:"defaultMapping,omitempty" json:"defaultMapping"`
}

type TACACSConfig struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Servers []string `yaml:"servers" json:"servers"`
	Secret  string   `yaml:"secret,omitempty" json:"secret"`
	Timeout int      `yaml:"timeout" json:"timeout"`
	// AuthenType is "pap" (default) or "ascii".
	AuthenType string `yaml:"authenType" json:"authenType"`
	// Service is sent as service=<Service> in the authorization request.
	Service              string           `yaml:"service" json:"service"`
	RoleAttribute        string           `yaml:"roleAttribute" json:"roleAttribute"`
	PermissionsAttribute string           `yaml:"permissionsAttribute" json:"permissionsAttribute"`
	PrivLvlMappings      []PrivLvlMapping `yaml:"privLvlMappings" json:"privLvlMappings"`
	DefaultMapping       *Mapping         `yaml:"defaultMapping,omitempty" json:"defaultMapping"`
}

type Config struct {
	// Order lists the directories tried after the local accounts.
	Order []string `yaml:"order" json:"order"`
	// SessionDuration is the login lifetime of external accounts in seconds.
	// It bounds how long a session outlives a change in the directory.
	SessionDuration int          `yaml:"sessionDuration" json:"sessionDuration"`
	LDAP            LDAPConfig   `yaml:"ldap" json:"ldap"`
	TACACS          TACACSConfig `yaml:"tacacs" json:"tacacs"`
}

// Default returns the disabled configuration with sensible presets.
func Default() *Config {
	return &Config{
		Order:           []string{SourceTACACS, SourceLDAP},
		SessionDuration: defaultSessionDuration,
		LDAP: LDAPConfig{
			UserFilter:     "(&(objectClass=user)(sAMAccountName=%s))",
			GroupAttribute: "memberOf",
			Timeout:        defaultTimeout,
			GroupMappings:  []GroupMapping{},
		},
		TACACS: TACACSConfig{
			Timeout:              defaultTimeout,
			AuthenType:           "pap",
			Service:              "nanokvm",
			RoleAttribute:        "nanokvm-role",
			PermissionsAttribute: "nanokvm-perms",
			PrivLvlMappings:      []PrivLvlMapping{},
		},
	}
}

// Enabled reports whether any directory is configured to be used.
func (c *Config) Enabled() bool {
	return c != nil && (c.LDAP.Enabled || c.TACACS.Enabled)
}

func (c *Config) applyDefaults() {
	def := Default()
	if len(c.Order) == 0 {
		c.Order = def.Order
	}
	if c.SessionDuration <= 0 {
		c.SessionDuration = def.SessionDuration
	}
	if c.LDAP.UserFilter == "" {
		c.LDAP.UserFilter = def.LDAP.UserFilter
	}
	if c.LDAP.GroupAttribute == "" && c.LDAP.GroupSearchFilter == "" {
		c.LDAP.GroupAttribute = def.LDAP.GroupAttribute
	}
	if c.LDAP.Timeout <= 0 {
		c.LDAP.Timeout = defaultTimeout
	}
	if c.TACACS.Timeout <= 0 {
		c.TACACS.Timeout = defaultTimeout
	}
	if c.TACACS.AuthenType == "" {
		c.TACACS.AuthenType = def.TACACS.AuthenType
	}
	if c.TACACS.Service == "" {
		c.TACACS.Service = def.TACACS.Service
	}
	if c.LDAP.GroupMappings == nil {
		c.LDAP.GroupMappings = []GroupMapping{}
	}
	if c.TACACS.PrivLvlMappings == nil {
		c.TACACS.PrivLvlMappings = []PrivLvlMapping{}
	}
}

// Validate checks the configuration. Disabled sections are only checked for
// values that would be rejected anyway once enabled, so a half-filled form can
// still be saved while the directory is switched off.
func (c *Config) Validate() error {
	seen := map[string]bool{}
	for _, name := range c.Order {
		if name != SourceLDAP && name != SourceTACACS {
			return fmt.Errorf("unknown directory %q in order", name)
		}
		if seen[name] {
			return fmt.Errorf("directory %q is listed twice in order", name)
		}
		seen[name] = true
	}
	if c.SessionDuration < 60 {
		return errors.New("sessionDuration must be at least 60 seconds")
	}
	if err := c.LDAP.validate(); err != nil {
		return fmt.Errorf("ldap: %w", err)
	}
	if err := c.TACACS.validate(); err != nil {
		return fmt.Errorf("tacacs: %w", err)
	}
	return nil
}

func (l *LDAPConfig) validate() error {
	if l.Timeout > maxTimeout {
		return fmt.Errorf("timeout must not exceed %d seconds", maxTimeout)
	}
	for _, raw := range l.URLs {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") {
			return fmt.Errorf("invalid server URL %q (expected ldap://host[:port] or ldaps://host[:port])", raw)
		}
		if parsed.Scheme == "ldaps" && l.StartTLS {
			return errors.New("startTLS cannot be combined with ldaps:// URLs")
		}
	}
	for _, mapping := range l.GroupMappings {
		if strings.TrimSpace(mapping.Group) == "" {
			return errors.New("group mapping without group")
		}
		if err := mapping.Mapping.validate(); err != nil {
			return fmt.Errorf("group %q: %w", mapping.Group, err)
		}
	}
	if l.DefaultMapping != nil {
		if err := l.DefaultMapping.validate(); err != nil {
			return fmt.Errorf("default mapping: %w", err)
		}
	}
	if !l.Enabled {
		return nil
	}
	if len(l.URLs) == 0 {
		return errors.New("at least one server URL is required")
	}
	if l.BaseDN == "" {
		return errors.New("baseDN is required")
	}
	if !strings.Contains(l.UserFilter, "%s") {
		return errors.New("userFilter must contain %s for the username")
	}
	if l.BindDN != "" && l.BindPassword == "" {
		return errors.New("bindPassword is required when bindDN is set")
	}
	if l.GroupAttribute == "" && l.GroupSearchFilter == "" {
		return errors.New("either groupAttribute or groupSearchFilter is required")
	}
	if len(l.GroupMappings) == 0 && l.DefaultMapping == nil {
		return errors.New("at least one group mapping (or a default mapping) is required")
	}
	if l.CAFile != "" {
		if _, err := os.Stat(l.CAFile); err != nil {
			return fmt.Errorf("caFile: %w", err)
		}
	}
	return nil
}

func (t *TACACSConfig) validate() error {
	if t.Timeout > maxTimeout {
		return fmt.Errorf("timeout must not exceed %d seconds", maxTimeout)
	}
	if t.AuthenType != "pap" && t.AuthenType != "ascii" {
		return errors.New("authenType must be pap or ascii")
	}
	for _, server := range t.Servers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			return fmt.Errorf("invalid server %q (expected host:port)", server)
		}
	}
	for _, mapping := range t.PrivLvlMappings {
		if mapping.MinPrivLvl < 0 || mapping.MinPrivLvl > 15 {
			return errors.New("minPrivLvl must be between 0 and 15")
		}
		if err := mapping.Mapping.validate(); err != nil {
			return fmt.Errorf("priv-lvl %d: %w", mapping.MinPrivLvl, err)
		}
	}
	if t.DefaultMapping != nil {
		if err := t.DefaultMapping.validate(); err != nil {
			return fmt.Errorf("default mapping: %w", err)
		}
	}
	if !t.Enabled {
		return nil
	}
	if len(t.Servers) == 0 {
		return errors.New("at least one server is required")
	}
	if t.Secret == "" {
		return errors.New("secret is required")
	}
	if t.RoleAttribute == "" && len(t.PrivLvlMappings) == 0 && t.DefaultMapping == nil {
		return errors.New("a role attribute, a priv-lvl mapping or a default mapping is required")
	}
	return nil
}

func (m *Mapping) validate() error {
	if !authn.IsValidRole(authn.Role(m.Role)) {
		return fmt.Errorf("invalid role %q", m.Role)
	}
	return authn.ValidatePermissions(toPermissions(m.Permissions))
}

func toPermissions(raw []string) []authn.Permission {
	permissions := make([]authn.Permission, 0, len(raw))
	for _, item := range raw {
		permissions = append(permissions, authn.Permission(item))
	}
	return permissions
}

// Clone returns a deep copy.
func (c *Config) Clone() *Config {
	data, err := yaml.Marshal(c)
	if err != nil {
		panic(err)
	}
	clone := &Config{}
	if err = yaml.Unmarshal(data, clone); err != nil {
		panic(err)
	}
	clone.applyDefaults()
	return clone
}

// Store loads and saves the configuration file and keeps the current copy.
type Store struct {
	path    string
	mutex   sync.RWMutex
	current *Config
}

var DefaultConfigStore = NewConfigStore(ConfigFile)

func NewConfigStore(path string) *Store {
	return &Store{path: path}
}

// Get returns a copy of the current configuration, loading it on first use. A
// missing file means external authentication is off; a broken file is
// reported and also leaves it off, so the local accounts keep working.
func (s *Store) Get() (*Config, error) {
	s.mutex.RLock()
	current := s.current
	s.mutex.RUnlock()
	if current != nil {
		return current.Clone(), nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.current == nil {
		conf, err := s.load()
		if err != nil {
			return Default(), err
		}
		s.current = conf
	}
	return s.current.Clone(), nil
}

func (s *Store) load() (*Config, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	conf := Default()
	if err = yaml.Unmarshal(data, conf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	conf.applyDefaults()
	if err = conf.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", s.path, err)
	}
	return conf, nil
}

// Reload drops the cached copy so the next Get reads the file again.
func (s *Store) Reload() {
	s.mutex.Lock()
	s.current = nil
	s.mutex.Unlock()
}

// Save validates and atomically writes the configuration with mode 0600.
func (s *Store) Save(conf *Config) error {
	conf = conf.Clone()
	if err := conf.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	directory := filepath.Dir(s.path)
	if err = os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".external-auth-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temporaryPath, s.path); err != nil {
		return err
	}
	s.current = conf
	return nil
}
