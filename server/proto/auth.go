package proto

import "NanoKVM-Server/authn/external"

type LoginReq struct {
	Username string `validate:"required"`
	Password string `validate:"required"`
}

type GetAccountRsp struct {
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	Source      string   `json:"source,omitempty"`
}

type ChangePasswordReq struct {
	CurrentPassword string `json:"currentPassword"`
	Password        string `json:"password" validate:"required"`
}

type IsPasswordUpdatedRsp struct {
	IsUpdated bool `json:"isUpdated"`
}

type UserInfo struct {
	Username      string   `json:"username"`
	Role          string   `json:"role"`
	Enabled       bool     `json:"enabled"`
	Permissions   []string `json:"permissions"`
	SystemAccount bool     `json:"systemAccount,omitempty"`
	Source        string   `json:"source,omitempty"`
}

type ListPermissionsRsp struct {
	Permissions []PermissionInfo `json:"permissions"`
}

// PermissionInfo describes one grantable permission: the group it belongs to,
// how far it reaches, and the grants it implies. The client renders the editor
// from this catalog instead of keeping its own copy of the model.
type PermissionInfo struct {
	ID      string   `json:"id"`
	Group   string   `json:"group"`
	Risk    string   `json:"risk"`
	Implies []string `json:"implies,omitempty"`
}

type ListUsersRsp struct {
	Users []UserInfo `json:"users"`
}

type CreateUserReq struct {
	Username    string   `json:"username" validate:"required"`
	Password    string   `json:"password" validate:"required"`
	Role        string   `json:"role" validate:"required"`
	Permissions []string `json:"permissions"`
}

type UpdateUserReq struct {
	Role        *string   `json:"role"`
	Enabled     *bool     `json:"enabled"`
	Permissions *[]string `json:"permissions"`
	// RotateMcpKey asks to regenerate the device-wide MCP API key when this
	// change takes the mcp grant away. The administrator decides: rotating
	// disconnects every MCP client, keeping it leaves a copied key working.
	RotateMcpKey bool `json:"rotateMcpKey"`
}

// UpdateUserRsp says whether the change regenerated the MCP API key.
type UpdateUserRsp struct {
	McpKeyRotated bool `json:"mcpKeyRotated"`
}

// ExternalAuthRsp carries the LDAP/TACACS+ settings without their secrets.
type ExternalAuthRsp struct {
	Config          any    `json:"config"`
	HasBindPassword bool   `json:"hasBindPassword"`
	HasSecret       bool   `json:"hasSecret"`
	LoadError       string `json:"loadError,omitempty"`
}

// TestExternalAuthReq runs one login against one directory. Config is the
// (unsaved) form content; the password is encrypted like the login password.
type TestExternalAuthReq struct {
	Source   string           `json:"source"`
	Username string           `json:"username"`
	Password string           `json:"password"`
	Config   *external.Config `json:"config"`
}

type TestExternalAuthRsp struct {
	Success     bool     `json:"success"`
	Unavailable bool     `json:"unavailable,omitempty"`
	Error       string   `json:"error,omitempty"`
	Username    string   `json:"username,omitempty"`
	Role        string   `json:"role,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Details     []string `json:"details,omitempty"`
}
