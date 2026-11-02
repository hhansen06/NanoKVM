import { http } from '@/lib/http';

export type UserRole = 'admin' | 'user';

export type Permission =
  | 'console.view'
  | 'console.control'
  | 'power'
  | 'medium.attach'
  | 'library.read'
  | 'library.write'
  | 'terminal'
  | 'device'
  | 'network'
  | 'update'
  | 'tailscale';

// Group names the party a grant reaches: the console this account watches, the
// machine behind it, the media library on this device, the device itself, or
// the services that reach it on their own.
export type PermissionGroup = 'console' | 'target' | 'library' | 'host' | 'services';

// Risk states how far a grant reaches. There are two levels: a plain grant, and
// the grants that amount to full device control, which the editor marks and
// names before the grants are saved.
export type PermissionRisk = 'info' | 'warn';

// PermissionDescriptor is one catalog entry as the server serves it. The editor
// renders the catalog instead of keeping its own copy of the model, so labels,
// groups and implied grants cannot drift from what the server enforces.
export type PermissionDescriptor = {
  id: Permission;
  group: PermissionGroup;
  risk: PermissionRisk;
  implies?: Permission[];
};

// AccountSource names the directory that authenticates an external account.
// Local accounts have none.
export type AccountSource = 'ldap' | 'tacacs';

export type Account = {
  username: string;
  role: UserRole;
  // The effective grants: the stored set plus everything it implies.
  permissions: Permission[];
  source?: AccountSource;
};

export type User = Account & {
  enabled: boolean;
  systemAccount?: boolean;
};
export function login(username: string, password: string) {
  const data = {
    username,
    password
  };
  return http.post('/api/auth/login', data);
}

export function logout() {
  return http.post('/api/auth/logout');
}

export function getAccount() {
  return http.get('/api/auth/account');
}

export function changePassword(currentPassword: string, password: string) {
  return http.post('/api/auth/password', { currentPassword, password });
}

export function isPasswordUpdated() {
  return http.get('/api/auth/password');
}

export function getUsers() {
  return http.get('/api/auth/users');
}

export function getPermissions() {
  return http.get('/api/auth/permissions');
}

export function createUser(
  username: string,
  password: string,
  role: UserRole,
  permissions?: Permission[]
) {
  return http.post('/api/auth/users', { username, password, role, permissions });
}

export function updateUser(
  username: string,
  data: Partial<Pick<User, 'role' | 'enabled' | 'permissions'>>
) {
  return http.request({
    method: 'put',
    url: `/api/auth/users/${encodeURIComponent(username)}`,
    data
  });
}

export function deleteUser(username: string) {
  return http.request({
    method: 'delete',
    url: `/api/auth/users/${encodeURIComponent(username)}`
  });
}

export type ExternalMapping = {
  role: UserRole;
  permissions: Permission[];
};

export type GroupMapping = ExternalMapping & { group: string };

export type PrivLvlMapping = ExternalMapping & { minPrivLvl: number };

export type LDAPConfig = {
  enabled: boolean;
  urls: string[];
  startTLS: boolean;
  caFile: string;
  insecureSkipVerify: boolean;
  bindDN: string;
  // Never sent by the server; an empty value on save keeps the stored one.
  bindPassword: string;
  baseDN: string;
  userFilter: string;
  groupAttribute: string;
  groupSearchFilter: string;
  groupSearchBaseDN: string;
  timeout: number;
  groupMappings: GroupMapping[];
  defaultMapping: ExternalMapping | null;
};

export type TACACSConfig = {
  enabled: boolean;
  servers: string[];
  // Never sent by the server; an empty value on save keeps the stored one.
  secret: string;
  timeout: number;
  authenType: 'pap' | 'ascii';
  service: string;
  roleAttribute: string;
  permissionsAttribute: string;
  privLvlMappings: PrivLvlMapping[];
  defaultMapping: ExternalMapping | null;
};

export type ExternalAuthConfig = {
  order: AccountSource[];
  sessionDuration: number;
  ldap: LDAPConfig;
  tacacs: TACACSConfig;
};

export type ExternalAuthSettings = {
  config: ExternalAuthConfig;
  hasBindPassword: boolean;
  hasSecret: boolean;
  loadError?: string;
};

export type ExternalAuthTestResult = {
  success: boolean;
  unavailable?: boolean;
  error?: string;
  username?: string;
  role?: UserRole;
  permissions?: Permission[];
  details?: string[];
};

export function getExternalAuth() {
  return http.get('/api/auth/external');
}

export function setExternalAuth(config: ExternalAuthConfig) {
  return http.request({ method: 'put', url: '/api/auth/external', data: config });
}

// password must already be encrypted like the login password.
export function testExternalAuth(
  source: AccountSource,
  username: string,
  password: string,
  config: ExternalAuthConfig
) {
  return http.post('/api/auth/external/test', { source, username, password, config });
}

export function resetUserPassword(username: string, password: string) {
  return http.post(`/api/auth/users/${encodeURIComponent(username)}/password`, { password });
}
