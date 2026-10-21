package crypto

import "testing"

func TestNormalizeFingerprint(t *testing.T) {
	for _, tt := range []struct{ name, input, want string }{
		{"uppercase with separators", "AB:CD", "abcd"},
		{"already normalized", "abcd", "abcd"},
		{"surrounding whitespace", " \tAB:cd\n", "abcd"},
		{"empty", "", ""},
		{"only whitespace", " \t", ""},
		{"only separators", ":", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeFingerprint(tt.input); got != tt.want {
				t.Errorf("NormalizeFingerprint(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
