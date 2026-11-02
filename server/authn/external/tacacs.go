package external

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nwaples/tacplus"
	log "github.com/sirupsen/logrus"
)

const (
	tacacsPort      = "http"
	maxASCIIPrompts = 5
)

type tacacsProvider struct {
	conf TACACSConfig
}

func newTACACSProvider(conf TACACSConfig) *tacacsProvider {
	return &tacacsProvider{conf: conf}
}

func (p *tacacsProvider) Name() string { return SourceTACACS }

func (p *tacacsProvider) timeout() time.Duration {
	if p.conf.Timeout <= 0 {
		return defaultTimeout * time.Second
	}
	return time.Duration(p.conf.Timeout) * time.Second
}

func (p *tacacsProvider) authenType() uint8 {
	if p.conf.AuthenType == "ascii" {
		return tacplus.AuthenTypeASCII
	}
	return tacplus.AuthenTypePAP
}

// Authenticate tries the servers in order. The servers are expected to share
// one user base: a definite answer (pass or fail) from one of them is final,
// only a server that cannot be reached or reports an error passes the request
// on to the next.
func (p *tacacsProvider) Authenticate(ctx context.Context, req Request) (*Identity, error) {
	if req.Password == "" {
		return nil, invalid("empty password")
	}
	var lastErr error
	for _, server := range p.conf.Servers {
		identity, err := p.authenticateWith(ctx, server, req)
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			return identity, err
		}
		log.Debugf("tacacs: server %s: %s", server, err)
		lastErr = fmt.Errorf("%s: %w", server, err)
	}
	if lastErr == nil {
		lastErr = unavailable("no server configured")
	}
	return nil, lastErr
}

func (p *tacacsProvider) client(server string) *tacplus.Client {
	return &tacplus.Client{
		Addr: server,
		ConnConfig: tacplus.ConnConfig{
			Secret:       []byte(p.conf.Secret),
			ReadTimeout:  p.timeout(),
			WriteTimeout: p.timeout(),
			Log:          func(v ...interface{}) { log.Debug(append([]interface{}{"tacacs: "}, v...)...) },
		},
	}
}

func (p *tacacsProvider) authenticateWith(ctx context.Context, server string, req Request) (*Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*p.timeout())
	defer cancel()
	client := p.client(server)
	defer client.Close()

	start := &tacplus.AuthenStart{
		Action:        tacplus.AuthenActionLogin,
		PrivLvl:       1,
		AuthenType:    p.authenType(),
		AuthenService: tacplus.AuthenServiceLogin,
		User:          req.Username,
		Port:          tacacsPort,
		RemAddr:       req.RemoteAddr,
	}
	if start.AuthenType == tacplus.AuthenTypePAP {
		start.Data = []byte(req.Password)
	}
	reply, session, err := client.SendAuthenStart(ctx, start)
	if err != nil {
		return nil, unavailable("authentication request failed: %s", err)
	}
	if session != nil {
		defer session.Close()
	}
	// ASCII login is a dialogue: the server asks for what it is missing.
dialogue:
	for prompts := 0; session != nil && prompts < maxASCIIPrompts; prompts++ {
		var answer string
		switch reply.Status {
		case tacplus.AuthenStatusGetUser:
			answer = req.Username
		case tacplus.AuthenStatusGetPass, tacplus.AuthenStatusGetData:
			answer = req.Password
		default:
			break dialogue
		}
		if reply, err = session.Continue(ctx, answer); err != nil {
			return nil, unavailable("authentication dialogue failed: %s", err)
		}
	}
	switch reply.Status {
	case tacplus.AuthenStatusPass:
	case tacplus.AuthenStatusFail:
		return nil, invalid("server rejected the login")
	case tacplus.AuthenStatusError:
		return nil, unavailable("server reported an error: %s", reply.ServerMsg)
	default:
		return nil, unavailable("unexpected authentication status %d", reply.Status)
	}

	response, err := client.SendAuthorRequest(ctx, &tacplus.AuthorRequest{
		AuthenMethod:  tacplus.AuthenMethodTACACSPlus,
		PrivLvl:       1,
		AuthenType:    p.authenType(),
		AuthenService: tacplus.AuthenServiceLogin,
		User:          req.Username,
		Port:          tacacsPort,
		RemAddr:       req.RemoteAddr,
		Arg:           []string{"service=" + p.conf.Service},
	})
	if err != nil {
		return nil, unavailable("authorization request failed: %s", err)
	}
	var args []string
	switch response.Status {
	case tacplus.AuthorStatusPassAdd, tacplus.AuthorStatusPassRepl:
		args = response.Arg
	case tacplus.AuthorStatusFail:
		// The user exists but the service is not authorized for it. Only a
		// default mapping can still let it in.
		if p.conf.DefaultMapping == nil {
			return nil, invalid("authorization for service %q denied", p.conf.Service)
		}
	default:
		return nil, unavailable("authorization error: %s", response.ServerMsg)
	}
	return p.identityFromArgs(args)
}

// identityFromArgs resolves the role from the attribute-value pairs: an
// explicit role attribute wins, then priv-lvl mappings, then the default.
func (p *tacacsProvider) identityFromArgs(args []string) (*Identity, error) {
	values := parseAVPairs(args)
	details := make([]string, 0, len(args))
	for _, arg := range args {
		details = append(details, "av-pair: "+arg)
	}

	if p.conf.RoleAttribute != "" {
		if raw, ok := values[strings.ToLower(p.conf.RoleAttribute)]; ok {
			mapping := Mapping{Role: strings.ToLower(raw)}
			if p.conf.PermissionsAttribute != "" {
				mapping.Permissions = splitList(values[strings.ToLower(p.conf.PermissionsAttribute)])
			}
			if err := mapping.validate(); err != nil {
				return nil, invalid("server sent an invalid role or permission: %s", err)
			}
			role, permissions, _ := resolve([]Mapping{mapping}, nil)
			return &Identity{Role: role, Permissions: permissions, Details: details}, nil
		}
	}

	if raw, ok := values["priv-lvl"]; ok {
		if level, err := strconv.Atoi(raw); err == nil {
			if mapping, found := matchPrivLvl(p.conf.PrivLvlMappings, level); found {
				role, permissions, _ := resolve([]Mapping{*mapping}, nil)
				return &Identity{Role: role, Permissions: permissions, Details: details}, nil
			}
		}
	}

	role, permissions, ok := resolve(nil, p.conf.DefaultMapping)
	if !ok {
		return nil, invalid("no role attribute or priv-lvl mapping matches (av-pairs: %s)", strings.Join(args, ", "))
	}
	return &Identity{Role: role, Permissions: permissions, Details: append(details, "default mapping")}, nil
}

// parseAVPairs reads mandatory (a=b) and optional (a*b) pairs. Keys are
// lowercased; the first occurrence wins.
func parseAVPairs(args []string) map[string]string {
	values := make(map[string]string, len(args))
	for _, arg := range args {
		index := strings.IndexAny(arg, "=*")
		if index <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(arg[:index]))
		if _, exists := values[key]; !exists {
			values[key] = strings.TrimSpace(arg[index+1:])
		}
	}
	return values
}

func splitList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	permissions := make([]string, 0, len(fields))
	for _, field := range fields {
		permissions = append(permissions, strings.ToLower(field))
	}
	return permissions
}
