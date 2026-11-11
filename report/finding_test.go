package report

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		findings []Finding
		redact   bool
	}{
		{
			redact: true,
			findings: []Finding{
				{
					Match:  "line containing secret",
					Secret: "secret",
				},
			}},
	}
	for _, test := range tests {
		for _, f := range test.findings {
			f.Redact(100)
			assert.Equal(t, "REDACTED", f.Secret)
			assert.Equal(t, "line containing REDACTED", f.Match)
		}
	}
}

func TestMask(t *testing.T) {

	tests := map[string]struct {
		finding Finding
		percent uint
		expect  Finding
	}{
		"normal secret": {
			finding: Finding{Match: "line containing secret", Secret: "secret"},
			expect:  Finding{Match: "line containing se...", Secret: "se..."},
			percent: 75,
		},
		"empty secret": {
			finding: Finding{Match: "line containing", Secret: ""},
			expect:  Finding{Match: "line containing", Secret: ""},
			percent: 75,
		},
		"short secret": {
			finding: Finding{Match: "line containing", Secret: "ss"},
			expect:  Finding{Match: "line containing", Secret: "..."},
			percent: 75,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := test.finding
			e := test.expect
			f.Redact(test.percent)
			assert.Equal(t, e.Secret, f.Secret)
			assert.Equal(t, e.Match, f.Match)
		})
	}
}

func TestMaskSecret(t *testing.T) {

	tests := map[string]struct {
		secret  string
		percent uint
		expect  string
	}{
		"normal masking":  {secret: "secret", percent: 75, expect: "se..."},
		"high masking":    {secret: "secret", percent: 90, expect: "s..."},
		"low masking":     {secret: "secret", percent: 10, expect: "secre..."},
		"invalid masking": {secret: "secret", percent: 1000, expect: "..."},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := maskSecret(test.secret, test.percent)
			assert.Equal(t, test.expect, got)
		})
	}
}

func TestHashSecret(t *testing.T) {
	// SHA-256 of "secret" is a well-known fixed digest.
	assert.Equal(t,
		"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b",
		HashSecret("secret"),
	)
	// Different inputs never collide for these fixtures.
	assert.NotEqual(t, HashSecret("secret"), HashSecret("rotated-secret"))
}

func TestSecretHashJSONSerialization(t *testing.T) {
	// Unredacted findings must keep the historical JSON shape: no SecretHash.
	plaintext := Finding{RuleID: "rule", Secret: "secret", Match: "secret"}
	raw, err := json.Marshal(plaintext)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "SecretHash")

	// Redacted findings expose the digest but never the plaintext secret.
	redacted := plaintext
	redacted.Redact(100)
	raw, err = json.Marshal(redacted)
	require.NoError(t, err)
	encoded := string(raw)
	assert.Contains(t, encoded, "SecretHash")
	assert.Contains(t, encoded, HashSecret("secret"))
	assert.NotContains(t, encoded, "secret")

	// Round-tripping a redacted finding preserves the digest.
	var decoded Finding
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, HashSecret("secret"), decoded.SecretHash)
	assert.Equal(t, "REDACTED", decoded.Secret)
}
