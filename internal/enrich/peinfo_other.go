//go:build !windows

package enrich

// originalFileName is only available for Windows PE files.
func originalFileName(string) string { return "" }
