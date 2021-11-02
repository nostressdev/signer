package signer

import (
	"fmt"
	"time"
)

type TokenPayload map[string]interface{}
type TokenAccessRules interface{}

type TokenProviderConfig struct {
	Expiration time.Duration
	SecretKey  []byte
}

type TokenProvider interface {
	CreateToken(payload TokenPayload, rules TokenAccessRules) (string, error)
	VerifyToken(token string) (TokenPayload, TokenAccessRules, error)
}

type AccessRulesProvider interface {
	CreateRules(whitelist []string, blacklist []string) TokenAccessRules
	CheckAccessRules(rules TokenAccessRules, rule string) error
}

var ErrPayloadExpired = fmt.Errorf("payload expired")
var ErrInvalidPayloadSignature = fmt.Errorf("payload has invalid signature")
var ErrInvalidPayload = fmt.Errorf("payload is invalid")
var ErrUnknown = fmt.Errorf("unknown error")
