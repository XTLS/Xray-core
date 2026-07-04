// Package names generates display names for Telemost peers.
package names

import (
	"bufio"
	"crypto/rand"
	_ "embed"
	"fmt"
	"math/big"
	"os"
	"strings"
)

//go:embed data/names
var embeddedNames string

//go:embed data/surnames
var embeddedSurnames string

var (
	firstNames = parseEmbedded(embeddedNames) //nolint:gochecknoglobals // package-level state intentional
	lastNames  = parseEmbedded(embeddedSurnames) //nolint:gochecknoglobals // package-level state intentional
)

func parseEmbedded(raw string) []string {
	var names []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			names = append(names, line)
		}
	}

	return names
}

func loadNames(path string) ([]string, error) {
	file, err := os.Open(path) //nolint:gosec // G304: opens internal asset bundled with the binary
	if err != nil {
		return nil, fmt.Errorf("open names file %q: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	var names []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			names = append(names, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan names file %q: %w", path, err)
	}

	return names, nil
}

// LoadNameFiles overrides embedded name dictionaries from local files when they are present.
func LoadNameFiles(firstPath, lastPath string) error {
	if names, err := loadNames(firstPath); err == nil && len(names) > 0 {
		firstNames = names
	}

	if names, err := loadNames(lastPath); err == nil && len(names) > 0 {
		lastNames = names
	}

	return nil
}

// Generate returns a random display name assembled from the currently loaded dictionaries.
func Generate() string {
	if len(firstNames) == 0 || len(lastNames) == 0 {
		return "anonymous user"
	}

	return firstNames[randomIndex(len(firstNames))] + " " + lastNames[randomIndex(len(lastNames))]
}

func randomIndex(limit int) int {
	if limit <= 1 {
		return 0
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0
	}

	return int(n.Int64())
}
