package signer

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAccessRulesProviderJSON_CheckAccessRules(t *testing.T) {
	whitelist := []string{"aa", "bb", "cc"}
	blacklist := []string{"a", "bbb"}
	provider := NewAccessRulesProviderJSON()
	rules := provider.CreateRules(whitelist, blacklist)

	assert.Error(t, provider.CheckAccessRules(rules, "aaa"))
	assert.Error(t, provider.CheckAccessRules(rules, "aa"))
	assert.Error(t, provider.CheckAccessRules(rules, "a"))

	assert.Error(t, provider.CheckAccessRules(rules, "bbb"))
	assert.NoError(t, provider.CheckAccessRules(rules, "bb"))
	assert.Error(t, provider.CheckAccessRules(rules, "b"))

	assert.NoError(t, provider.CheckAccessRules(rules, "ccc"))
	assert.NoError(t, provider.CheckAccessRules(rules, "cc"))
	assert.Error(t, provider.CheckAccessRules(rules, "c"))

	assert.Error(t, provider.CheckAccessRules(rules, "d"))
}
