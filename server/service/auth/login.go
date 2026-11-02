package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"NanoKVM-Server/authn"
	"NanoKVM-Server/authn/external"
	"NanoKVM-Server/config"
	"NanoKVM-Server/middleware"
	"NanoKVM-Server/proto"
	"NanoKVM-Server/utils"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func (s *Service) Login(c *gin.Context) {
	var req proto.LoginReq
	var rsp proto.Response

	conf := config.GetInstance()
	if conf.Authentication == "disable" {
		rsp.OkRsp(c)
		return
	}

	clientIP := GetClientIP(c)
	if locked, code, msg := CheckLoginAttempt(clientIP); locked {
		time.Sleep(3 * time.Second)
		rsp.ErrRsp(c, code, msg)
		return
	}
	if err := proto.ParseFormRequest(c, &req); err != nil {
		time.Sleep(3 * time.Second)
		rsp.ErrRsp(c, -1, "invalid parameters")
		return
	}
	password, err := utils.DecodeDecrypt(req.Password)
	if err != nil || password == "" {
		s.loginFailed(c, clientIP, &rsp)
		return
	}
	user, sessionDuration, err := s.authenticate(c, req.Username, password, clientIP)
	if errors.Is(err, errLoginRejected) {
		s.loginFailed(c, clientIP, &rsp)
		return
	}
	if err != nil {
		log.Errorf("login for %q: %s", req.Username, err)
		// An unreachable directory still counts as a failed attempt, so taking
		// one server down cannot be used to try passwords without the lockout.
		RecordLoginFailure(clientIP)
		time.Sleep(2 * time.Second)
		rsp.ErrRsp(c, -3, "authentication unavailable")
		return
	}

	ClearLoginAttempt(clientIP)
	token, err := middleware.GenerateJWTWithDuration(user.Username, user.TokenVersion, sessionDuration)
	if err != nil {
		time.Sleep(time.Second)
		rsp.ErrRsp(c, -3, "generate token failed")
		return
	}
	setSessionCookie(c, token, int(sessionDuration.Seconds()))
	rsp.OkRsp(c)
	if user.IsExternal() {
		log.Infof("user logged in: %s (via %s)", user.Username, user.Source)
	} else {
		log.Infof("user logged in: %s", user.Username)
	}
}

var errLoginRejected = errors.New("login rejected")

// externalAuthenticate is replaced in tests.
var externalAuthenticate = external.Authenticate

// authenticate checks a login against the local accounts first and then the
// external directories. A local account always decides on its own: its name is
// never handed to a directory, so a directory account cannot shadow it and the
// device owner keeps working when every directory is down.
func (s *Service) authenticate(c *gin.Context, username, password, clientIP string) (*authn.User, time.Duration, error) {
	conf := config.GetInstance()
	localDuration := time.Duration(conf.JWT.RefreshTokenDuration) * time.Second

	existing, err := authn.DefaultStore.Get(username)
	if err != nil && !errors.Is(err, authn.ErrUserNotFound) {
		return nil, 0, fmt.Errorf("load account: %w", err)
	}
	if existing != nil && !existing.IsExternal() {
		user, ok, authErr := authn.DefaultStore.Authenticate(username, password)
		if authErr != nil {
			return nil, 0, fmt.Errorf("load account: %w", authErr)
		}
		if !ok {
			return nil, 0, errLoginRejected
		}
		return user, localDuration, nil
	}

	extConf, err := external.DefaultConfigStore.Get()
	if err != nil {
		log.Errorf("external authentication configuration: %s", err)
	}
	if !extConf.Enabled() {
		return nil, 0, errLoginRejected
	}
	identity, err := externalAuthenticate(c.Request.Context(), extConf, external.Request{
		Username:   username,
		Password:   password,
		RemoteAddr: clientIP,
	})
	switch {
	case err == nil:
	case errors.Is(err, external.ErrInvalidCredentials), errors.Is(err, external.ErrDisabled):
		return nil, 0, errLoginRejected
	default:
		return nil, 0, err
	}

	previous, user, err := authn.DefaultStore.UpsertExternal(identity.Username, identity.Source, identity.Role, identity.Permissions)
	if errors.Is(err, authn.ErrLocalAccount) {
		// "DOMAIN\\admin" normalizes to a local account's name; never log
		// into the local account with directory credentials.
		log.Warnf("%s: %q maps to the local account %q; login refused", identity.Source, username, identity.Username)
		return nil, 0, errLoginRejected
	}
	if err != nil {
		return nil, 0, fmt.Errorf("record external account: %w", err)
	}
	if !user.Enabled {
		log.Infof("%s: %q is disabled on this device; login refused", identity.Source, identity.Username)
		return nil, 0, errLoginRejected
	}
	refreshChangedGrants(previous, user)
	return user, time.Duration(extConf.SessionDuration) * time.Second, nil
}

// refreshChangedGrants applies a role or grant change that the directory
// reported at login to the account's other open sessions, exactly like an
// edit in the user management does.
func refreshChangedGrants(previous, updated *authn.User) {
	if previous == nil {
		return
	}
	changed := permissionsChanged(enabledPermissions(previous), enabledPermissions(updated))
	if (updated.Role != previous.Role || len(changed) > 0) && SessionNotifier != nil {
		go SessionNotifier(updated.Username, "auth", "refresh")
	}
	if channels := channelsForPermissions(changed); len(channels) > 0 {
		middleware.RefreshUserSessions(updated.Username, channels...)
	}
}

func (s *Service) loginFailed(c *gin.Context, clientIP string, rsp *proto.Response) {
	time.Sleep(2 * time.Second)
	if locked, code, msg := RecordLoginFailure(clientIP); locked {
		rsp.ErrRsp(c, code, msg)
		return
	}
	rsp.ErrRsp(c, -2, "invalid username or password")
}

func (s *Service) Logout(c *gin.Context) {
	var rsp proto.Response
	principal, ok := middleware.CurrentPrincipal(c)
	conf := config.GetInstance()
	if ok && conf.Authentication != "disable" && conf.JWT.RevokeTokensOnLogout {
		if _, err := authn.DefaultStore.Revoke(principal.Username); err != nil {
			rsp.ErrRsp(c, -1, "failed to revoke session")
			return
		}
		middleware.RevokeUserSessions(principal.Username)
		log.Infof("user logged out: %s", principal.Username)
	}
	clearSessionCookie(c)
	rsp.OkRsp(c)
}

func (s *Service) GetAccount(c *gin.Context) {
	var rsp proto.Response
	principal, ok := middleware.CurrentPrincipal(c)
	if !ok {
		rsp.ErrRsp(c, -1, "get account failed")
		return
	}
	rsp.OkRspWithData(c, &proto.GetAccountRsp{
		Username:    principal.Username,
		Role:        string(principal.Role),
		Permissions: permissionStrings(principal.Permissions),
		Source:      accountSource(principal.Username),
	})
}

func setSessionCookie(c *gin.Context, token string, maxAge int) {
	conf := config.GetInstance()
	secure := conf.Proto == "https" || c.Request.TLS != nil ||
		strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(
		middleware.CookieName,
		token,
		maxAge,
		"/",
		"",
		secure,
		true,
	)
}

func clearSessionCookie(c *gin.Context) {
	conf := config.GetInstance()
	secure := conf.Proto == "https" || c.Request.TLS != nil ||
		strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(middleware.CookieName, "", -1, "/", "", secure, true)
}

func accountSource(username string) string {
	if user, err := authn.DefaultStore.Get(username); err == nil {
		return user.Source
	}
	return ""
}
