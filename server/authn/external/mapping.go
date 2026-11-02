package external

import (
	"strings"

	"NanoKVM-Server/authn"

	"github.com/go-ldap/ldap/v3"
)

// resolve merges every matched mapping: the strongest role wins and the grants
// are the union. Without a match the default mapping applies; without one the
// login is refused.
func resolve(matched []Mapping, fallback *Mapping) (authn.Role, []authn.Permission, bool) {
	if len(matched) == 0 {
		if fallback == nil {
			return "", nil, false
		}
		matched = []Mapping{*fallback}
	}
	role := authn.RoleUser
	permissions := make([]authn.Permission, 0)
	for _, mapping := range matched {
		if authn.Role(mapping.Role) == authn.RoleAdmin {
			role = authn.RoleAdmin
		}
		for _, permission := range toPermissions(mapping.Permissions) {
			if !authn.Has(permissions, permission) {
				permissions = append(permissions, permission)
			}
		}
	}
	if role == authn.RoleAdmin {
		// Administrators hold the whole catalog; storing grants would only
		// confuse the editor.
		permissions = []authn.Permission{}
	}
	return role, permissions, true
}

// matchGroups returns the mappings whose group appears in groups. A mapping
// naming a DN is compared as a DN (case and spacing insensitive); a bare name
// is compared against the value of the group's first RDN.
func matchGroups(mappings []GroupMapping, groups []string) ([]Mapping, []string) {
	matched := make([]Mapping, 0)
	names := make([]string, 0)
	parsed := make([]*ldap.DN, len(groups))
	for index, group := range groups {
		if dn, err := ldap.ParseDN(group); err == nil {
			parsed[index] = dn
		}
	}
	for _, mapping := range mappings {
		want := strings.TrimSpace(mapping.Group)
		var wantDN *ldap.DN
		if strings.Contains(want, "=") {
			wantDN, _ = ldap.ParseDN(want)
		}
		for index, group := range groups {
			if groupMatches(want, wantDN, group, parsed[index]) {
				matched = append(matched, mapping.Mapping)
				names = append(names, group)
				break
			}
		}
	}
	return matched, names
}

func groupMatches(want string, wantDN *ldap.DN, group string, groupDN *ldap.DN) bool {
	if strings.EqualFold(want, strings.TrimSpace(group)) {
		return true
	}
	if groupDN == nil {
		return false
	}
	if wantDN != nil {
		return wantDN.EqualFold(groupDN)
	}
	if len(groupDN.RDNs) == 0 || len(groupDN.RDNs[0].Attributes) == 0 {
		return false
	}
	return strings.EqualFold(want, groupDN.RDNs[0].Attributes[0].Value)
}

// matchPrivLvl returns the mapping with the highest threshold not above the
// level, if any.
func matchPrivLvl(mappings []PrivLvlMapping, level int) (*Mapping, bool) {
	var best *PrivLvlMapping
	for index := range mappings {
		mapping := &mappings[index]
		if mapping.MinPrivLvl <= level && (best == nil || mapping.MinPrivLvl > best.MinPrivLvl) {
			best = mapping
		}
	}
	if best == nil {
		return nil, false
	}
	return &best.Mapping, true
}
