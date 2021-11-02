package signer

import (
	"fmt"
	"github.com/nostressdev/nerrors"
	"strings"
)

type accessRulesProviderJSON struct {
}

func NewAccessRulesProviderJSON() AccessRulesProvider {
	return &accessRulesProviderJSON{}
}

type rulesJSON struct {
	Whitelist []string `json:"whitelist"`
	Blacklist []string `json:"blacklist"`
}

func (rulesProvider *accessRulesProviderJSON) CreateRules(whitelist []string, blacklist []string) TokenAccessRules {
	return rulesJSON{
		Whitelist: whitelist,
		Blacklist: blacklist,
	}
}

func checkRules(rules rulesJSON, rule string) error {
	for _, ruleEntry := range rules.Blacklist {
		if strings.HasPrefix(rule, ruleEntry) {
			return nerrors.PermissionDenied.New(fmt.Sprintf("permission denied because %v is in blacklist", ruleEntry))
		}
	}
	for _, ruleEntry := range rules.Whitelist {
		if strings.HasPrefix(rule, ruleEntry) {
			return nil
		}
	}
	return nerrors.PermissionDenied.New("permission denied because no rule accepts this request")
}

func (rulesProvider *accessRulesProviderJSON) CheckAccessRules(rules TokenAccessRules, rule string) error {
	if parsedRules, ok := rules.(rulesJSON); ok {
		return checkRules(parsedRules, rule)
	} else if m, ok := rules.(map[string]interface{}); ok {
		parsedRules = rulesJSON{}
		if whitelistRaw, ok := m["whitelist"]; ok {
			if whitelist, ok := whitelistRaw.([]interface{}); ok {
				for _, entry := range whitelist {
					parsedRules.Whitelist = append(parsedRules.Whitelist, entry.(string))
				}
			}
		}
		if blacklistRaw, ok := m["blacklist"]; ok {
			if blacklist, ok := blacklistRaw.([]interface{}); ok {
				for _, entry := range blacklist {
					parsedRules.Blacklist = append(parsedRules.Blacklist, entry.(string))
				}
			}
		}
		return checkRules(parsedRules, rule)
	} else {
		return nerrors.Validation.New("parsing rules invalid type")
	}
}
