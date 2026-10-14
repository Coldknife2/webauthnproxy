package main

import "os"

func writeFile(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
