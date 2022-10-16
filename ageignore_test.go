package agefs

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed test_ageignore
var testAgeignoreFileContent string

func TestReadIgnorePatterns(t *testing.T) {
	t.Run("hasContent", func(t *testing.T) {
		fn, err := readIgnorePatterns(strings.NewReader(testAgeignoreFileContent))
		if err != nil {
			t.Fatal(err)
		}

		testCases := []struct {
			input string
			want  bool
		}{
			{input: "letsencrypt/accounts/acme-v02.api.letsencrypt.org/admin@example.com/keys/admin@example.com.key", want: true},
			{input: "letsencrypt/certificates/www.example.com.crt", want: false},
			{input: "letsencrypt/certificates/www.example.com.issuer.crt", want: false},
			{input: "letsencrypt/certificates/www.example.com.key", want: true},
		}
		for _, tc := range testCases {
			got := fn(tc.input)
			if got != tc.want {
				t.Errorf("result mismatch for input=%s, got=%v, want=%v", tc.input, got, tc.want)
			}
		}
	})
	t.Run("noFile", func(t *testing.T) {
		fn, err := readIgnorePatterns(nil)
		if err != nil {
			t.Fatal(err)
		}
		input := "some_filename"
		if got, want := fn("some_filename"), true; got != want {
			t.Errorf("result mismatch for input=%s, got=%v, want=%v", input, got, want)
		}
	})
	t.Run("emptyFile", func(t *testing.T) {
		fn, err := readIgnorePatterns(strings.NewReader("# just comment line\n"))
		if err != nil {
			t.Fatal(err)
		}
		input := "some_filename"
		if got, want := fn("some_filename"), true; got != want {
			t.Errorf("result mismatch for input=%s, got=%v, want=%v", input, got, want)
		}
	})
}
