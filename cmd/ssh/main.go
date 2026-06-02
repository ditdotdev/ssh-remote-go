// Package main provides the SSH remote plugin executable for Dit.
package main

import "github.com/ditdotdev/remote-sdk-go/remote"

func main() {
	remote.Serve("ssh")
}
