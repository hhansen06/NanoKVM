package auth

import (
	"context"
	"errors"
	"slices"
	"time"

	"NanoKVM-Server/authn/external"
	"NanoKVM-Server/proto"
	"NanoKVM-Server/utils"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// GetExternalAuth returns the LDAP and TACACS+ settings. Secrets never leave
// the device; the response only says whether one is stored.
func (s *Service) GetExternalAuth(c *gin.Context) {
	var rsp proto.Response
	conf, err := external.DefaultConfigStore.Get()
	if err != nil {
		// A broken file is still shown, with defaults, so it can be repaired.
		log.Errorf("external authentication configuration: %s", err)
	}
	rsp.OkRspWithData(c, redactExternalConfig(conf, err))
}

func redactExternalConfig(conf *external.Config, loadErr error) *proto.ExternalAuthRsp {
	result := &proto.ExternalAuthRsp{
		Config:          conf,
		HasBindPassword: conf.LDAP.BindPassword != "",
		HasSecret:       conf.TACACS.Secret != "",
	}
	if loadErr != nil {
		result.LoadError = loadErr.Error()
	}
	conf.LDAP.BindPassword = ""
	conf.TACACS.Secret = ""
	return result
}

// SetExternalAuth stores the settings. An empty secret keeps the stored one,
// because the client never received it.
func (s *Service) SetExternalAuth(c *gin.Context) {
	var req external.Config
	var rsp proto.Response
	if err := c.ShouldBindJSON(&req); err != nil {
		rsp.ErrRsp(c, -1, "invalid parameters")
		return
	}
	merged, err := mergeExternalSecrets(&req)
	if err != nil {
		rsp.ErrRsp(c, -2, err.Error())
		return
	}
	if err = external.DefaultConfigStore.Save(merged); err != nil {
		rsp.ErrRsp(c, -3, err.Error())
		return
	}
	log.Infof("external authentication settings saved (ldap: %t, tacacs: %t)", merged.LDAP.Enabled, merged.TACACS.Enabled)
	rsp.OkRspWithData(c, redactExternalConfig(merged.Clone(), nil))
}

// mergeExternalSecrets fills in the stored secrets the client never received.
// A stored secret is only reused while it goes to the same servers (and, for
// LDAP, the same service account): otherwise pointing the settings at another
// host would hand it the stored credentials. A changed target needs the
// secret entered again.
func mergeExternalSecrets(req *external.Config) (*external.Config, error) {
	stored, _ := external.DefaultConfigStore.Get()
	merged := req.Clone()
	if req.LDAP.BindPassword == "" &&
		req.LDAP.BindDN == stored.LDAP.BindDN &&
		slices.Equal(req.LDAP.URLs, stored.LDAP.URLs) {
		merged.LDAP.BindPassword = stored.LDAP.BindPassword
	}
	if merged.LDAP.BindDN == "" {
		// Anonymous search: nothing to keep.
		merged.LDAP.BindPassword = ""
	}
	if req.TACACS.Secret == "" && slices.Equal(req.TACACS.Servers, stored.TACACS.Servers) {
		merged.TACACS.Secret = stored.TACACS.Secret
	}
	return merged, nil
}

// TestExternalAuth runs one login against one directory with the settings in
// the request (merged with the stored secrets), so an administrator can check
// a change before saving it. No account is created.
func (s *Service) TestExternalAuth(c *gin.Context) {
	var req proto.TestExternalAuthReq
	var rsp proto.Response
	if err := c.ShouldBindJSON(&req); err != nil || req.Config == nil {
		rsp.ErrRsp(c, -1, "invalid parameters")
		return
	}
	password, err := utils.DecodeDecrypt(req.Password)
	if err != nil || password == "" {
		rsp.ErrRsp(c, -1, "password is required")
		return
	}
	merged, err := mergeExternalSecrets(req.Config)
	if err != nil {
		rsp.ErrRsp(c, -2, err.Error())
		return
	}
	if err = merged.Validate(); err != nil {
		rsp.ErrRsp(c, -2, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	identity, err := external.TestProvider(ctx, merged, req.Source, external.Request{
		Username:   req.Username,
		Password:   password,
		RemoteAddr: GetClientIP(c),
	})
	if err != nil {
		result := &proto.TestExternalAuthRsp{Success: false, Error: err.Error()}
		if errors.Is(err, external.ErrUnavailable) {
			result.Unavailable = true
		}
		log.Infof("external authentication test (%s) for %q failed: %s", req.Source, req.Username, err)
		rsp.OkRspWithData(c, result)
		return
	}
	rsp.OkRspWithData(c, &proto.TestExternalAuthRsp{
		Success:     true,
		Username:    identity.Username,
		Role:        string(identity.Role),
		Permissions: permissionStrings(identity.Permissions),
		Details:     identity.Details,
	})
}
