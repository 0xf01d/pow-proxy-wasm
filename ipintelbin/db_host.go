//go:build !wasip1

package ipintel

import "os"

// Open opens and validates a database from a file path.
func Open(path string) (*DB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return openBytes(b)
}

// OpenInMemory reads the whole database file into memory. (Kept for API
// compatibility; equivalent to Open since the file is read fully.)
func OpenInMemory(path string) (*DB, error) {
	return Open(path)
}

func open(path string, inMemory bool) (*DB, error) {
	return Open(path)
}
