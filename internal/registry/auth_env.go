package registry

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type authPair struct{ user, pass string }

// envLookup matches the signature of os.LookupEnv so tests can inject values.
type envLookup func(key string) (string, bool)

// envKey builds a registry env key, appending "_<suffix>" for named registries.
func envKey(base, suffix string) string {
	if suffix == "" {
		return base
	}
	return base + "_" + suffix
}

// resolveCredentials returns the credentials configured for a registry and any
// warnings about values that were ignored, repaired, or malformed. Warnings
// name the offending env key but never include secret material.
//
// Precedence:
//  1. REGISTRY_AUTH[_<SUFFIX>]: base64("username:password")
//  2. REGISTRY_USERNAME[_<SUFFIX>] and REGISTRY_PASSWORD[_<SUFFIX>]: plain values
func resolveCredentials(lookup envLookup, suffix string) (*authPair, []string) {
	var warnings []string

	authKey := envKey("REGISTRY_AUTH", suffix)
	userKey := envKey("REGISTRY_USERNAME", suffix)
	passKey := envKey("REGISTRY_PASSWORD", suffix)

	encoded, hasEncoded := lookup(authKey)
	user, hasUser := lookup(userKey)
	pass, hasPass := lookup(passKey)
	hasEncoded = hasEncoded && strings.TrimSpace(encoded) != ""
	hasUser = hasUser && user != ""
	hasPass = hasPass && pass != ""

	if hasEncoded {
		if hasUser || hasPass {
			warnings = append(warnings, fmt.Sprintf(
				"%s is set, so %s and %s are ignored", authKey, userKey, passKey))
		}
		pair, decodeWarnings := decodeBasicAuth(authKey, encoded)
		return pair, append(warnings, decodeWarnings...)
	}

	switch {
	case hasUser && hasPass:
		return &authPair{user: user, pass: pass}, warnings
	case hasUser:
		warnings = append(warnings, fmt.Sprintf(
			"%s is set but %s is empty; requests will be unauthenticated", userKey, passKey))
	case hasPass:
		warnings = append(warnings, fmt.Sprintf(
			"%s is set but %s is empty; requests will be unauthenticated", passKey, userKey))
	}
	return nil, warnings
}

// decodeBasicAuth decodes base64("username:password"), tolerating the common
// formatting mistakes that otherwise produce a silent 401 from the registry.
func decodeBasicAuth(key, raw string) (*authPair, []string) {
	var warnings []string

	value := strings.TrimSpace(raw)
	if value != raw {
		warnings = append(warnings, key+" had surrounding whitespace; it was trimmed")
	}
	if unquoted, ok := stripMatchingQuotes(value); ok {
		value = unquoted
		warnings = append(warnings, key+" was wrapped in quotes; they were removed")
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		var rawErr error
		decoded, rawErr = base64.RawStdEncoding.DecodeString(value)
		if rawErr != nil {
			warnings = append(warnings, fmt.Sprintf(
				"%s is not valid base64 (%v); requests will be unauthenticated", key, err))
			return nil, warnings
		}
		warnings = append(warnings, key+" is missing base64 padding; decoded anyway")
	}

	text := string(decoded)
	if trimmed := strings.TrimRight(text, "\r\n"); trimmed != text {
		text = trimmed
		warnings = append(warnings, key+
			" decoded with a trailing newline (likely `echo` without -n); the newline was removed")
	}

	user, pass, ok := strings.Cut(text, ":")
	if !ok {
		warnings = append(warnings, key+
			" does not decode to username:password; requests will be unauthenticated")
		return nil, warnings
	}
	if user == "" || pass == "" {
		warnings = append(warnings, key+
			" decodes to an empty username or password; requests will be unauthenticated")
		return nil, warnings
	}
	return &authPair{user: user, pass: pass}, warnings
}

func stripMatchingQuotes(s string) (string, bool) {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' || first == '\'') && first == last {
			return s[1 : len(s)-1], true
		}
	}
	return s, false
}
