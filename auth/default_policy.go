package auth

import _ "embed"

// DefaultAuthzJSON is the raw content of the built-in default authorization
// policy file (authz.json). The init-full bootstrap flow uses it to generate
// <baseDir>/authz.json and load it, so m-superadmin certificates automatically
// carry full PrincipalAuthorization grants.
//
//go:embed authz.json
var DefaultAuthzJSON []byte
