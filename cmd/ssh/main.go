// Package main provides the SSH remote plugin executable for Titan.
package main

import "github.com/datadatdat/remote-sdk-go/remote"

func main() {
	remote.Serve("ssh")
}
