package registry

import (
	"encoding/base64"
	"strings"
	"testing"
)

func lookupFrom(m map[string]string) envLookup {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestResolveCredentials(t *testing.T) {
	tests := []struct {
		name         string
		env          map[string]string
		suffix       string
		wantUser     string
		wantPass     string
		wantNil      bool
		wantWarnings int
		warnContains string
	}{
		{
			name:     "valid REGISTRY_AUTH",
			env:      map[string]string{"REGISTRY_AUTH": b64("admin:s3cret")},
			wantUser: "admin", wantPass: "s3cret",
		},
		{
			name:     "password containing colons",
			env:      map[string]string{"REGISTRY_AUTH": b64("admin:a:b:c")},
			wantUser: "admin", wantPass: "a:b:c",
		},
		{
			name:     "echo without -n leaves trailing newline",
			env:      map[string]string{"REGISTRY_AUTH": b64("admin:s3cret\n")},
			wantUser: "admin", wantPass: "s3cret",
			wantWarnings: 1, warnContains: "trailing newline",
		},
		{
			name:     "env value with trailing newline and spaces",
			env:      map[string]string{"REGISTRY_AUTH": "  " + b64("admin:s3cret") + "\n"},
			wantUser: "admin", wantPass: "s3cret",
			wantWarnings: 1, warnContains: "whitespace",
		},
		{
			name:     "quoted value",
			env:      map[string]string{"REGISTRY_AUTH": `"` + b64("admin:s3cret") + `"`},
			wantUser: "admin", wantPass: "s3cret",
			wantWarnings: 1, warnContains: "quotes",
		},
		{
			name:     "missing padding",
			env:      map[string]string{"REGISTRY_AUTH": strings.TrimRight(b64("admin:pw"), "=")},
			wantUser: "admin", wantPass: "pw",
			wantWarnings: 1, warnContains: "padding",
		},
		{
			name:         "not base64",
			env:          map[string]string{"REGISTRY_AUTH": "admin:s3cret"},
			wantNil:      true,
			wantWarnings: 1, warnContains: "not valid base64",
		},
		{
			name:         "no colon",
			env:          map[string]string{"REGISTRY_AUTH": b64("adminonly")},
			wantNil:      true,
			wantWarnings: 1, warnContains: "username:password",
		},
		{
			name:     "plain username and password",
			env:      map[string]string{"REGISTRY_USERNAME": "admin", "REGISTRY_PASSWORD": "p$w:rd"},
			wantUser: "admin", wantPass: "p$w:rd",
		},
		{
			name: "REGISTRY_AUTH wins over plain values",
			env: map[string]string{
				"REGISTRY_AUTH":     b64("a:1"),
				"REGISTRY_USERNAME": "b", "REGISTRY_PASSWORD": "2",
			},
			wantUser: "a", wantPass: "1",
			wantWarnings: 1, warnContains: "ignored",
		},
		{
			name:         "username without password",
			env:          map[string]string{"REGISTRY_USERNAME": "admin"},
			wantNil:      true,
			wantWarnings: 1, warnContains: "REGISTRY_PASSWORD is empty",
		},
		{
			name:    "no credentials is not a warning",
			env:     map[string]string{},
			wantNil: true,
		},
		{
			name:     "named registry suffix",
			suffix:   "HOME",
			env:      map[string]string{"REGISTRY_USERNAME_HOME": "u", "REGISTRY_PASSWORD_HOME": "p", "REGISTRY_AUTH": b64("x:y")},
			wantUser: "u", wantPass: "p",
		},
		{
			name:     "secret never appears in warnings",
			env:      map[string]string{"REGISTRY_AUTH": `'` + b64("admin:topsecret\n") + `'`},
			wantUser: "admin", wantPass: "topsecret",
			wantWarnings: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, warnings := resolveCredentials(lookupFrom(tc.env), tc.suffix)

			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil credentials, got user=%q", got.user)
				}
			} else {
				if got == nil {
					t.Fatalf("expected credentials, got nil (warnings: %v)", warnings)
				}
				if got.user != tc.wantUser || got.pass != tc.wantPass {
					t.Fatalf("got %q/%q, want %q/%q", got.user, got.pass, tc.wantUser, tc.wantPass)
				}
			}

			if len(warnings) != tc.wantWarnings {
				t.Fatalf("got %d warnings %v, want %d", len(warnings), warnings, tc.wantWarnings)
			}
			if tc.warnContains != "" && !strings.Contains(strings.Join(warnings, "|"), tc.warnContains) {
				t.Fatalf("warnings %v do not contain %q", warnings, tc.warnContains)
			}
			for _, w := range warnings {
				if tc.wantPass != "" && strings.Contains(w, tc.wantPass) {
					t.Fatalf("warning leaks password: %q", w)
				}
			}
		})
	}
}
