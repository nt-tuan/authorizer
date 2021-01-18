package main

import (
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"

	"google.golang.org/api/oauth2/v2"
	"gopkg.in/yaml.v2"
)

// Rule defined
type Rule struct {
	Path    string   `yaml:"path"`
	Methods []string `yaml:"methods"`
	Role    string   `yaml:"role"`
}

// Users defined
type Users map[string]struct {
	Roles []string `yaml:"roles"`
}

// Authorizer struct defined
type Authorizer struct {
	Rules []Rule `yaml:"rules"`
	Users Users  `yaml:"users"`
}

// NewAuthorizer init
func NewAuthorizer() Authorizer {
	configYAML, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	var authorizer Authorizer
	if err := yaml.Unmarshal(configYAML, &authorizer); err != nil {
		log.Fatal(err)
	}
	return authorizer
}

var httpClient = &http.Client{}

func verifyIDToken(idToken string) (*oauth2.Tokeninfo, error) {
	oauth2Service, err := oauth2.New(httpClient)
	tokenInfoCall := oauth2Service.Tokeninfo()
	tokenInfoCall = tokenInfoCall.AccessToken(idToken)
	tokenInfo, err := tokenInfoCall.Do()
	if err != nil {
		return nil, err
	}
	if tokenInfo.IssuedTo != os.Getenv("CLIENT_ID") {
		return nil, errors.New("invalid-client")
	}
	return tokenInfo, nil
}
func (a Authorizer) getMatchRule(method string, requestURI string) (*Rule, error) {
	for _, rule := range a.Rules {
		matched, err := regexp.MatchString(rule.Path, requestURI)
		if err != nil {
			return nil, err
		}
		if matched {
			for _, ruleMethod := range rule.Methods {
				if ruleMethod == method {
					return &rule, nil
				}
			}
		}
	}
	return nil, nil
}

// Authorize a request
func (a Authorizer) Authorize(token string, method string, requestURI string) (bool, *oauth2.Tokeninfo, error) {
	matchRule, err := a.getMatchRule(method, requestURI)
	if err != nil {
		return false, nil, err
	}
	if matchRule == nil {
		return true, nil, nil
	}
	tokenInfo, err := verifyIDToken(token)
	if err != nil {
		return false, nil, err
	}
	if !tokenInfo.VerifiedEmail {
		return false, nil, errors.New("email is not verified")
	}
	if matchRule.Role == "" {
		return true, tokenInfo, nil
	}
	user, ok := a.Users[tokenInfo.Email]
	if !ok {
		return false, nil, nil
	}
	for _, role := range user.Roles {
		if role == matchRule.Role {
			return true, tokenInfo, nil
		}
	}
	return false, nil, nil
}
