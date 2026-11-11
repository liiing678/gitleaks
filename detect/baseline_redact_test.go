package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

const redactBaselineDir = "../testdata/baseline/redact/"

const (
	redactBaselineOldSecret = "AKIALALEMEL33243OKIA"
	redactBaselineNewSecret = "AKIALALEMEL33243OLIA"
)

func newSimpleConfigDetector(t *testing.T) *Detector {
	t.Helper()
	viper.Reset()
	viper.AddConfigPath(configPath)
	viper.SetConfigName("simple")
	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadInConfig())

	var vc config.ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	return NewDetector(cfg)
}

func loadRedactBaseline(t *testing.T, name string) []report.Finding {
	t.Helper()
	baseline, err := LoadBaseline(filepath.Join(redactBaselineDir, name))
	require.NoError(t, err)
	return baseline
}

// detectPlaintext runs detection without applying any baseline. The returned
// findings carry the plaintext secret and the SecretHash that AddFinding sees
// before redaction, mirroring the real scan ordering.
func detectPlaintext(t *testing.T, fixture, filePath string) []report.Finding {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(redactBaselineDir, fixture))
	require.NoError(t, err)

	d := newSimpleConfigDetector(t)
	findings := d.Detect(Fragment{Raw: string(raw), FilePath: filePath})
	require.NotEmpty(t, findings)
	return findings
}

// runBaseline feeds the plaintext findings produced for fixture through
// AddFinding, which is the exact place baseline suppression happens.
func runBaseline(t *testing.T, redact uint, baseline []report.Finding, findings []report.Finding) []report.Finding {
	t.Helper()
	d := newSimpleConfigDetector(t)
	d.Redact = redact
	d.baseline = baseline
	for _, finding := range findings {
		d.AddFinding(finding)
	}
	return d.Findings()
}

// TestRedactedBaselineDetectsRotation drives fixed file fixtures through the
// real baseline suppression path. The redacted baseline never stores the
// plaintext secret, only a one-way SecretHash, yet it must still notice when
// the secret on the same rule, file and line is rotated.
func TestRedactedBaselineDetectsRotation(t *testing.T) {
	redactedBaseline := loadRedactBaseline(t, "baseline_redacted.json")
	legacyRedactedBaseline := loadRedactBaseline(t, "baseline_legacy_redacted.json")
	plaintextBaseline := loadRedactBaseline(t, "baseline_plaintext.json")

	require.Len(t, redactedBaseline, 1)
	assert.Equal(t, "REDACTED", redactedBaseline[0].Secret)
	assert.NotEmpty(t, redactedBaseline[0].SecretHash)
	assert.NotContains(t, redactedBaseline[0].Secret, "AKIA")
	assert.NotContains(t, redactedBaseline[0].Match, "AKIA")
	assert.Equal(t, report.HashSecret(redactBaselineOldSecret), redactedBaseline[0].SecretHash)

	unchangedFindings := detectPlaintext(t, "v1.txt", "secrets.txt")
	rotatedFindings := detectPlaintext(t, "v2_rotated.txt", "secrets.txt")

	tests := map[string]struct {
		redact   uint
		baseline []report.Finding
		findings []report.Finding
		wantNew  int
	}{
		// Rotated secret on the exact same rule, file and line hashes differently.
		"rotated secret on same line is new": {
			redact: 100, baseline: redactedBaseline, findings: rotatedFindings, wantNew: 1,
		},
		// Same secret on the same line stays suppressed by the redacted baseline.
		"unchanged secret on same line is skipped": {
			redact: 100, baseline: redactedBaseline, findings: unchangedFindings, wantNew: 0,
		},
		// A plaintext (unredacted) run still honors the redacted baseline.
		"plaintext run, rotated secret is new": {
			redact: 0, baseline: redactedBaseline, findings: rotatedFindings, wantNew: 1,
		},
		"plaintext run, unchanged secret is skipped": {
			redact: 0, baseline: redactedBaseline, findings: unchangedFindings, wantNew: 0,
		},
		// Legacy redacted baseline without SecretHash keeps historical behavior:
		// the value comparison is skipped and suppression is driven purely by
		// location/metadata, so an unchanged finding stays suppressed exactly as
		// it would have before SecretHash existed.
		"legacy redacted baseline stays compatible": {
			redact: 100, baseline: legacyRedactedBaseline, findings: unchangedFindings, wantNew: 0,
		},
		// Plaintext unredacted baseline still compares values directly.
		"plaintext baseline detects rotation": {
			redact: 0, baseline: plaintextBaseline, findings: rotatedFindings, wantNew: 1,
		},
		"plaintext baseline suppresses unchanged secret": {
			redact: 0, baseline: plaintextBaseline, findings: unchangedFindings, wantNew: 0,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			remaining := runBaseline(t, tt.redact, tt.baseline, tt.findings)
			assert.Len(t, remaining, tt.wantNew)
			if tt.wantNew > 0 {
				assert.Equal(t, "aws-access-key", remaining[0].RuleID)
				assert.Equal(t, 4, remaining[0].StartLine)
			}
		})
	}
}

// TestRedactedBaselineLineMovementAndCR guards against location regressions:
// ordinary line moves change StartLine so they no longer match the baseline,
// while a standalone carriage return in the body must not be treated as a line
// break and must keep the secret on its original line number.
func TestRedactedBaselineLineMovementAndCR(t *testing.T) {
	baseline := loadRedactBaseline(t, "baseline_redacted.json")

	t.Run("moved line produces a new finding with updated line number", func(t *testing.T) {
		findings := detectPlaintext(t, "v2_moved.txt", "secrets.txt")
		require.Len(t, findings, 1)
		assert.Equal(t, 5, findings[0].StartLine)

		remaining := runBaseline(t, 100, baseline, findings)
		require.Len(t, remaining, 1)
		assert.Equal(t, 5, remaining[0].StartLine)
	})

	t.Run("standalone carriage return does not shift line number", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(redactBaselineDir, "v2_cr.txt"))
		require.NoError(t, err)
		assert.Contains(t, string(raw), "\r")

		d := newSimpleConfigDetector(t)
		findings := d.Detect(Fragment{Raw: string(raw), FilePath: "secrets.txt"})
		require.Len(t, findings, 1)
		// The lone CR is not a line separator: the secret stays on line index 4
		// (line 5 in 1-based terms), identical to the v1 fixture.
		assert.Equal(t, 4, findings[0].StartLine)
		assert.Equal(t, redactBaselineOldSecret, findings[0].Secret)
	})
}

// TestRedactPopulatesSecretHashNotPlaintext ensures redacted output never
// carries the original secret while the hash is present for baselines, and
// unredacted output keeps the historical shape without a SecretHash field.
func TestRedactPopulatesSecretHashNotPlaintext(t *testing.T) {
	findings := detectPlaintext(t, "v1.txt", "secrets.txt")
	require.Len(t, findings, 1)
	// The unredacted detection result must not expose the hash field.
	assert.Empty(t, filter(findings, 0)[0].SecretHash)

	redacted := filter(findings, 100)
	require.Len(t, redacted, 1)
	finding := redacted[0]
	assert.Equal(t, "REDACTED", finding.Secret)
	assert.Equal(t, "REDACTED", finding.Match)
	assert.NotContains(t, finding.Line, redactBaselineOldSecret)
	assert.Equal(t, report.HashSecret(redactBaselineOldSecret), finding.SecretHash)
}
