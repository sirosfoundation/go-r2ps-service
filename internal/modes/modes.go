// Package modes defines operating roles for the R2PS server binary.
//
// Roles can be combined via comma-separated list:
//
//	--mode=wscd              (WSCD only: keygen, sign, ECDH, 2FA)
//	--mode=wsca              (WSCA only: WKA, WIA, revoke, suspend, status lists)
//	--mode=admin             (admin API only)
//	--mode=all               (all roles — default)
//	--mode=wscd,wsca         (both, no admin)
package modes

import (
	"fmt"
	"sort"
	"strings"
)

// Role represents a single operating role.
type Role string

const (
	RoleWSCD  Role = "wscd"
	RoleWSCA  Role = "wsca"
	RoleAdmin Role = "admin"
)

// ValidRoles lists all valid operating roles.
var ValidRoles = []Role{RoleWSCD, RoleWSCA, RoleAdmin}

// IsValid checks if a role string is valid.
func (r Role) IsValid() bool {
	for _, valid := range ValidRoles {
		if r == valid {
			return true
		}
	}
	return false
}

// RoleSet represents a set of active roles.
type RoleSet struct {
	roles map[Role]bool
}

// NewRoleSet creates a new role set from a list of roles.
func NewRoleSet(roles []Role) *RoleSet {
	rs := &RoleSet{roles: make(map[Role]bool)}
	for _, r := range roles {
		rs.roles[r] = true
	}
	return rs
}

// Has checks if a role is in the set.
func (rs *RoleSet) Has(role Role) bool {
	return rs.roles[role]
}

// List returns the roles as a sorted slice.
func (rs *RoleSet) List() []Role {
	roles := make([]Role, 0, len(rs.roles))
	for r := range rs.roles {
		roles = append(roles, r)
	}
	sort.Slice(roles, func(i, j int) bool {
		return roles[i] < roles[j]
	})
	return roles
}

// Strings returns the roles as a sorted string slice.
func (rs *RoleSet) Strings() []string {
	roles := rs.List()
	strs := make([]string, len(roles))
	for i, r := range roles {
		strs[i] = string(r)
	}
	return strs
}

// ParseRoles parses a comma-separated mode string into a RoleSet.
// Supports "all" as a shorthand for all roles.
func ParseRoles(s string) (*RoleSet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("mode cannot be empty")
	}

	if s == "all" {
		return NewRoleSet(ValidRoles), nil
	}

	parts := strings.Split(s, ",")
	roles := make([]Role, 0, len(parts))
	seen := make(map[Role]bool)

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		if p == "all" {
			for _, r := range ValidRoles {
				if !seen[r] {
					roles = append(roles, r)
					seen[r] = true
				}
			}
			continue
		}

		role := Role(p)
		if !role.IsValid() {
			return nil, fmt.Errorf("invalid role %q, valid roles: %v", p, ValidRoles)
		}
		if !seen[role] {
			roles = append(roles, role)
			seen[role] = true
		}
	}

	if len(roles) == 0 {
		return nil, fmt.Errorf("no valid roles specified")
	}

	return NewRoleSet(roles), nil
}
