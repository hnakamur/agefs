package agefs

import (
	"bufio"
	"io"
	"os"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"go.uber.org/multierr"
)

const commentPrefix = "#"

func ReadIgnoreFile(filename string) (fn ShouldEncryptFunc, err error) {
	f, err := os.Open(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return readIgnorePatterns(nil)
	}
	defer func() {
		err = multierr.Append(err, f.Close())
	}()

	return readIgnorePatterns(f)
}

func readIgnorePatterns(r io.Reader) (fn ShouldEncryptFunc, err error) {
	var ps []gitignore.Pattern
	if r != nil {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			s := scanner.Text()
			if !strings.HasPrefix(s, commentPrefix) && len(strings.TrimSpace(s)) > 0 {
				ps = append(ps, gitignore.ParsePattern(s, nil))
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	if len(ps) == 0 {
		return func(relPath string) bool {
			return true
		}, nil
	}

	m := gitignore.NewMatcher(ps)
	return func(relPath string) bool {
		pathComponents := strings.Split(relPath, string(os.PathSeparator))
		return !m.Match(pathComponents, false)
	}, nil
}
