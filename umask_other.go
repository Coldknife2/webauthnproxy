//go:build !unix

package main

func umaskRestrictive() func() { return func() {} }
