package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zricethezav/gitleaks/v8/report"
)

func IsNew(finding report.Finding, redact uint, baseline []report.Finding) bool {
	// Explicitly testing each property as it gives significantly better performance in comparison to cmp.Equal(). Drawback is that
	// the code requires maintenance if/when the Finding struct changes
	for _, b := range baseline {
		if finding.RuleID == b.RuleID &&
			finding.Description == b.Description &&
			finding.StartLine == b.StartLine &&
			finding.EndLine == b.EndLine &&
			finding.StartColumn == b.StartColumn &&
			finding.EndColumn == b.EndColumn &&
			secretMatches(finding, redact, b) &&
			finding.File == b.File &&
			finding.Commit == b.Commit &&
			finding.Author == b.Author &&
			finding.Email == b.Email &&
			finding.Date == b.Date &&
			finding.Message == b.Message &&
			// Omit checking finding.Fingerprint - if the format of the fingerprint changes, the users will see unexpected behaviour
			finding.Entropy == b.Entropy {
			return false
		}
	}
	return true
}

// secretMatches reports whether the secret captured by finding is the same as
// the one recorded in a baseline entry.
//
// Baselines generated with --redact do not contain plaintext secrets, only a
// one-way SecretHash. When the baseline carries a hash it is authoritative: a
// rotated secret at the same rule, file and line hashes differently and is
// therefore treated as a new finding. Baselines produced before SecretHash
// existed (both redacted and unredacted) keep their legacy behavior so old
// baselines stay valid:
//   - redacted runs against old redacted baselines skip the value comparison,
//   - unredacted runs compare Match and Secret directly.
func secretMatches(finding report.Finding, redact uint, baseline report.Finding) bool {
	if baseline.SecretHash != "" {
		// A redacted finding already carries the digest of its original
		// plaintext secret. A plaintext finding has no SecretHash yet, so the
		// digest is computed on demand over the live secret. Either way the
		// baseline itself never needs to store plaintext.
		findingHash := finding.SecretHash
		if findingHash == "" {
			findingHash = report.HashSecret(finding.Secret)
		}
		return findingHash == baseline.SecretHash
	}
	// Legacy baselines (written before SecretHash existed) keep their exact
	// historical behavior: a redacted run has no plaintext to compare, so the
	// value check is skipped and only location/metadata must match. An
	// unredacted run compares Match and Secret directly.
	if redact > 0 {
		return true
	}
	return finding.Match == baseline.Match && finding.Secret == baseline.Secret
}

func LoadBaseline(baselinePath string) ([]report.Finding, error) {
	bytes, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", baselinePath)
	}

	var previousFindings []report.Finding
	err = json.Unmarshal(bytes, &previousFindings)
	if err != nil {
		return nil, fmt.Errorf("the format of the file %s is not supported", baselinePath)
	}

	return previousFindings, nil
}

func (d *Detector) AddBaseline(baselinePath string, source string) error {
	if baselinePath != "" {
		absoluteSource, err := filepath.Abs(source)
		if err != nil {
			return err
		}

		absoluteBaseline, err := filepath.Abs(baselinePath)
		if err != nil {
			return err
		}

		relativeBaseline, err := filepath.Rel(absoluteSource, absoluteBaseline)
		if err != nil {
			return err
		}

		baseline, err := LoadBaseline(baselinePath)
		if err != nil {
			return err
		}

		d.baseline = baseline
		baselinePath = relativeBaseline

	}

	d.baselinePath = baselinePath
	return nil
}
