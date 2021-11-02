package signer

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestTokenProviderJWT_CreateTokenAndVerify(t *testing.T) {
	const Access = "abc"
	const SecretKey = "12345678"
	provider := NewTokenProviderJWT(TokenProviderConfig{
		Expiration: time.Second * 60,
		SecretKey:  []byte(SecretKey),
	})
	token, err := provider.CreateToken(TokenPayload{}, Access)
	assert.NoError(t, err)
	_, access, err := provider.VerifyToken(token)
	assert.NoError(t, err)
	assert.Equal(t, Access, access)
}

func TestTokenProviderJWT_CreateTokenAndVerifyRulesJSON(t *testing.T) {
	whitelist := []string{"aa", "cc"}
	blacklist := []string{"aaa"}
	const SecretKey = "12345678"
	provider := NewTokenProviderJWT(TokenProviderConfig{
		Expiration: time.Second * 60,
		SecretKey:  []byte(SecretKey),
	})
	rulesProvider := NewAccessRulesProviderJSON()
	rules := rulesProvider.CreateRules(whitelist, blacklist)
	token, err := provider.CreateToken(TokenPayload{}, rules)
	assert.NoError(t, err)
	_, access, err := provider.VerifyToken(token)
	assert.NoError(t, err)
	for index, rule := range access.(map[string]interface{})["whitelist"].([]interface{}) {
		assert.Equal(t, whitelist[index], rule)
	}
	for index, rule := range access.(map[string]interface{})["blacklist"].([]interface{}) {
		assert.Equal(t, blacklist[index], rule)
	}
	assert.NoError(t, rulesProvider.CheckAccessRules(access, "aa"))
	assert.NoError(t, rulesProvider.CheckAccessRules(access, "cc"))
	assert.Error(t, rulesProvider.CheckAccessRules(access, "aaa"))
	assert.Error(t, rulesProvider.CheckAccessRules(access, "a"))
}
