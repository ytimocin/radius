package installer

import "regexp"

var (
	versionRe  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?$`)
	checksumRe = regexp.MustCompile(`^(?i:(sha256:)?[a-f0-9]{64})$`)
)

// IsValidVersion returns true if the version string is in a simple semver-like format.
func IsValidVersion(v string) bool {
	return versionRe.MatchString(v)
}

// IsValidChecksum returns true if the checksum string appears to be a sha256 hex string with optional prefix.
func IsValidChecksum(c string) bool {
	return checksumRe.MatchString(c)
}
