// Copyright Dit 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

/*
 * Copyright Dit.
 */

// Package ssh integration tests exercise the real runCommand against a live
// sshd. Unit-test runs (without the `integration` build tag) skip this file
// entirely so they stay hermetic.
//
// Run with:
//
//	docker run -d --rm --name ssh-remote-go-itest -p 12200:22 \
//	    ditdotdev/ssh-test-server:latest
//	go test -tags=integration ./ssh/ -run TestRunCommandIntegration
//	docker rm -f ssh-remote-go-itest
//
// Override the target with SSH_TEST_HOST / SSH_TEST_PORT / SSH_TEST_USER /
// SSH_TEST_PASSWORD if you have a different sshd available.
package ssh

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}

func dialIntegrationSSH(t *testing.T) *ssh.Client {
	t.Helper()

	host := envOr("SSH_TEST_HOST", "127.0.0.1")
	port := envOr("SSH_TEST_PORT", "12200")
	user := envOr("SSH_TEST_USER", "root")
	password := envOr("SSH_TEST_PASSWORD", "root")

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		//nolint:gosec // G106: integration test against a disposable container — host key pinning is out of scope here.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", host+":"+port, config)
	if err != nil {
		// CI spins up ditdotdev/ssh-test-server as a service container in the Integration Tests
		// job, so this skip should never fire there. Locally, run
		//   docker run -d --rm --name ssh-remote-go-itest -p 12200:22 ditdotdev/ssh-test-server:latest
		// before invoking `go test -tags=integration`. Skip gracefully when unreachable so the same
		// test file works on developer laptops without docker too.
		t.Skipf("ssh-test-server not reachable at %s:%s (%v); skipping integration test", host, port, err)
	}

	return client
}

func TestRunCommandIntegrationEcho(t *testing.T) {
	client := dialIntegrationSSH(t)
	defer func() { _ = client.Close() }()

	out, err := runCommand(client, "echo hello-d3")
	require.NoError(t, err)
	assert.Equal(t, "hello-d3", strings.TrimSpace(string(out)))
}

func TestRunCommandIntegrationCommandFailure(t *testing.T) {
	client := dialIntegrationSSH(t)
	defer func() { _ = client.Close() }()

	// `false` exits non-zero, exercising the error branch of runCommand.
	_, err := runCommand(client, "false")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to execute 'false'")
}

func TestRunCommandIntegrationNewSessionFailure(t *testing.T) {
	// Close the connection before requesting a session so NewSession fails.
	client := dialIntegrationSSH(t)
	require.NoError(t, client.Close())

	_, err := runCommand(client, "echo never")
	require.Error(t, err)
}
