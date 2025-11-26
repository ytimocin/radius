package installer

import "testing"

func TestIsValidVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		valid   bool
	}{
		{name: "simple", version: "1.2.3", valid: true},
		{name: "pre", version: "1.2.3-beta.1", valid: true},
		{name: "build", version: "1.2.3+build", valid: true},
		{name: "missing patch", version: "1.2", valid: false},
		{name: "garbage", version: "abc", valid: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidVersion(tt.version); got != tt.valid {
				t.Fatalf("IsValidVersion(%q) = %v, want %v", tt.version, got, tt.valid)
			}
		})
	}
}

func TestIsValidChecksum(t *testing.T) {
	tests := []struct {
		name     string
		checksum string
		valid    bool
	}{
		{name: "prefixed sha", checksum: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", valid: true},
		{name: "bare sha", checksum: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", valid: true},
		{name: "wrong length", checksum: "abc", valid: false},
		{name: "wrong chars", checksum: "sha256:xyz123", valid: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidChecksum(tt.checksum); got != tt.valid {
				t.Fatalf("IsValidChecksum(%q) = %v, want %v", tt.checksum, got, tt.valid)
			}
		})
	}
}
