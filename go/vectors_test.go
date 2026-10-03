package cryptopq_test

import (
	"encoding/hex"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type fields map[string]string

type record struct {
	header fields
	values fields
}

// A file under vectors/: [key = value] header lines persist until replaced, records are
// key = value lines separated by blank lines, and # starts a comment. Every line that starts
// with field must belong to a parsed record, so that a parser slip cannot skip vectors.
func records(t *testing.T, name, field string) []record {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "vectors", filepath.FromSlash(name)))

	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	header := fields{}

	values := fields{}

	var found []record

	for _, raw := range append(lines, "") {
		line := strings.TrimSpace(raw)

		key, value, hasValue := strings.Cut(line, "=")

		switch {
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			key, value, _ = strings.Cut(line[1:len(line)-1], "=")

			header = maps.Clone(header)

			header[strings.TrimSpace(key)] = strings.TrimSpace(value)
		case hasValue && !strings.HasPrefix(line, "#"):
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		case len(values) > 0:
			found = append(found, record{header, values})

			values = fields{}
		}
	}

	expected, parsed := 0, 0

	for _, line := range lines {
		if strings.HasPrefix(line, field+" =") {
			expected++
		}
	}

	for _, r := range found {
		if _, ok := r.values[field]; ok {
			parsed++
		}
	}

	if expected == 0 || parsed != expected {
		t.Fatalf("%s: parsed %d records, expected %d", name, parsed, expected)
	}

	return found
}

func decode(t *testing.T, text string) []byte {
	t.Helper()

	data, err := hex.DecodeString(text)

	if err != nil {
		t.Fatal(err)
	}

	return data
}

func number(t *testing.T, text string) int {
	t.Helper()

	n, err := strconv.Atoi(text)

	if err != nil {
		t.Fatal(err)
	}

	return n
}

// A minimal DER writer, so that tests can build encodings the library itself never produces.
func der(tag byte, parts ...[]byte) []byte {
	var content []byte

	for _, part := range parts {
		content = append(content, part...)
	}

	length := len(content)

	if length < 0x80 {
		return append([]byte{tag, byte(length)}, content...)
	}

	var size []byte

	for ; length > 0; length >>= 8 {
		size = append([]byte{byte(length)}, size...)
	}

	return append(append([]byte{tag, 0x80 | byte(len(size))}, size...), content...)
}
