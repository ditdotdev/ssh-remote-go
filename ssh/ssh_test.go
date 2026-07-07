// Copyright Dit 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ditdotdev/remote-sdk-go/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// newTestClient returns a *sshClient pre-wired with no-op defaults that fail
// loudly if exercised in the wrong direction. Tests that need a specific
// collaborator (e.g., a fake dial, a stub run) override just that field on
// the returned struct. This replaces the legacy pattern of mutating
// package-level vars, which was incompatible with t.Parallel() and -race.
func newTestClient() *sshClient {
	return &sshClient{
		dial: func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
			return nil, errors.New("dial not configured for this test")
		},
		run: func(_ *ssh.Client, _ string) ([]byte, error) {
			return nil, errors.New("run not configured for this test")
		},
		readPassword: func(_ int) ([]byte, error) {
			return nil, errors.New("readPassword not configured for this test")
		},
		fmtPrintf: func(_ string, _ ...interface{}) (int, error) {
			return 0, nil
		},
		fmtFprintf: func(_ io.Writer, _ string, _ ...interface{}) (int, error) {
			return 0, nil
		},
	}
}

const (
	testPath    = "/path"
	testBar     = "bar"
	testKeyFile = "/keyfile"
	testFoo     = "foo"
	testHost    = "host"
	testLsPath  = "ls -1 \"" + testPath + "\""
)

func TestRegistered(t *testing.T) {
	r, _ := remote.Get("ssh")

	ret, err := r.Type()
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh", ret)
	}
}

func TestFromURL(t *testing.T) {
	r, _ := remote.Get("ssh")

	props, err := r.FromURL("ssh://user:pass@host:8022/path", map[string]string{})
	if assert.NoError(t, err) {
		assert.Equal(t, "user", props[propUsername])
		assert.Equal(t, "pass", props[propPassword])
		assert.Equal(t, testHost, props[propAddress])
		assert.Equal(t, 8022, props[propPort])
		assert.Equal(t, testPath, props[propPath])
		assert.Nil(t, props[propKeyFile])
	}
}

func TestSimple(t *testing.T) {
	r, _ := remote.Get("ssh")

	props, err := r.FromURL("ssh://user@host/path", map[string]string{})
	if assert.NoError(t, err) {
		assert.Equal(t, "user", props[propUsername])
		assert.Nil(t, props[propPassword])
		assert.Equal(t, testHost, props[propAddress])
		assert.Nil(t, props[propPort])
		assert.Equal(t, testPath, props[propPath])
		assert.Nil(t, props[propKeyFile])
	}
}

func TestKeyFile(t *testing.T) {
	r, _ := remote.Get("ssh")

	props, err := r.FromURL("ssh://user@host/path", map[string]string{propKeyFile: "~/.ssh/id_dsa"})
	if assert.NoError(t, err) {
		assert.Equal(t, "~/.ssh/id_dsa", props[propKeyFile])
	}
}

func TestRelativePath(t *testing.T) {
	r, _ := remote.Get("ssh")

	props, err := r.FromURL("ssh://user@host/~/relative/path", map[string]string{})
	if assert.NoError(t, err) {
		assert.Equal(t, "relative/path", props[propPath])
	}
}

func TestBadUrl(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("ssh://host\nname", map[string]string{})
	assert.Error(t, err)
}

func TestBadScheme(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("foo://user:pass@host:8022/path", map[string]string{})
	assert.Error(t, err)
}

func TestBadPasswordAndKeyFile(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("ssh://user:password@host/path", map[string]string{propKeyFile: "~/.ssh/id_dsa"})
	assert.Error(t, err)
}

func TestBadProperty(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("ssh://user@host/path", map[string]string{testFoo: testBar})
	assert.Error(t, err)
}

func TestBadMissingHost(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("ssh:///path", map[string]string{})
	assert.Error(t, err)
}

func TestBadSchemeOnly(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("ssh", map[string]string{})
	assert.Error(t, err)
}

func TestBadMissingUsername(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("ssh://host/path", map[string]string{})
	assert.Error(t, err)
}

func TestBadPort(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("ssh://user@host:29348529384572398457932847539/path", map[string]string{})
	assert.Error(t, err)
}

func TestBadMissingPath(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("ssh://user@host", map[string]string{})
	assert.Error(t, err)
}

func TestBadMissingHostWithUser(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("ssh://user@/path", map[string]string{})
	assert.Error(t, err)
}

func TestToURL(t *testing.T) {
	r, _ := remote.Get("ssh")

	u, props, err := r.ToURL(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host/path", u)
		assert.Empty(t, props)
	}
}

func TestToPassword(t *testing.T) {
	r, _ := remote.Get("ssh")

	u, props, err := r.ToURL(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath, propPassword: "pass"})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username:*****@host/path", u)
		assert.Empty(t, props)
	}
}

func TestToPort(t *testing.T) {
	r, _ := remote.Get("ssh")

	u, props, err := r.ToURL(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath, propPort: 812})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host:812/path", u)
		assert.Empty(t, props)
	}
}

func TestToBadPort(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, _, err := r.ToURL(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath, propPort: "812"})
	assert.Error(t, err)
}

func TestToRelativePath(t *testing.T) {
	r, _ := remote.Get("ssh")

	u, props, err := r.ToURL(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: propPath})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host/~/path", u)
		assert.Empty(t, props)
	}
}

func TestToKeyFile(t *testing.T) {
	r, _ := remote.Get("ssh")

	u, props, err := r.ToURL(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath, propKeyFile: "keyfile"})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host/path", u)
		assert.Len(t, props, 1)
		assert.Equal(t, "keyfile", props[propKeyFile])
	}
}

func TestToPortFloat(t *testing.T) {
	p := float32(812)
	r, _ := remote.Get("ssh")

	u, props, err := r.ToURL(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath, propPort: p})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host:812/path", u)
		assert.Empty(t, props)
	}
}

func TestToPortDouble(t *testing.T) {
	r, _ := remote.Get("ssh")

	u, props, err := r.ToURL(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath, propPort: 812.0})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host:812/path", u)
		assert.Empty(t, props)
	}
}

func TestGetParameters(t *testing.T) {
	r, _ := remote.Get("ssh")

	props, err := r.GetParameters(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath, propPassword: "pass"})
	if assert.NoError(t, err) {
		assert.Empty(t, props)
	}
}

func TestKeyFileParameters(t *testing.T) {
	r, _ := remote.Get("ssh")

	file, err := os.CreateTemp("", "ssh.test")
	if !assert.NoError(t, err) {
		return
	}

	defer func() { _ = os.Remove(file.Name()) }()

	path, err := filepath.Abs(file.Name())
	if !assert.NoError(t, err) {
		return
	}

	err = os.WriteFile(path, []byte("KEY"), 0600)
	if !assert.NoError(t, err) {
		return
	}

	props, err := r.GetParameters(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath, propKeyFile: path})
	if assert.NoError(t, err) {
		assert.Nil(t, props[propPassword])
		assert.Equal(t, "KEY", props[propKey])
	}
}

func TestBadKeyFileParameters(t *testing.T) {
	r, _ := remote.Get("ssh")

	file, err := os.CreateTemp("", "ssh.test")
	if !assert.NoError(t, err) {
		return
	}

	path, err := filepath.Abs(file.Name())
	if !assert.NoError(t, err) {
		return
	}

	err = file.Close()
	if !assert.NoError(t, err) {
		return
	}

	err = os.Remove(path)
	if assert.NoError(t, err) {
		_, err = r.GetParameters(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
			propPath: testPath, propKeyFile: path})
		assert.Error(t, err)
	}
}

func TestPasswordPrompt(t *testing.T) {
	c := newTestClient()
	c.readPassword = func(_ int) ([]byte, error) {
		return []byte("pass"), nil
	}

	props, err := c.GetParameters(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath})
	if assert.NoError(t, err) {
		assert.Nil(t, props[propKey])
		assert.Equal(t, "pass", props[propPassword])
	}
}

func TestBadPasswordPrompt(t *testing.T) {
	c := newTestClient()
	c.readPassword = func(_ int) ([]byte, error) {
		return []byte{}, errors.New("error")
	}

	_, err := c.GetParameters(map[string]interface{}{propUsername: propUsername, propAddress: testHost,
		propPath: testPath})
	assert.Error(t, err)
}

func TestValidateRemoteRequiredOnly(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{propUsername: propUsername, propAddress: testHost, propPath: testPath})
	assert.NoError(t, err)
}

func TestValidateRemoteAllOptional(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{propUsername: propUsername, propAddress: testHost, propPath: testPath,
		propKeyFile: testKeyFile, propPassword: propPassword, propPort: 8022})
	assert.NoError(t, err)
}

func TestValidateRemoteBadPort(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{propUsername: propUsername, propAddress: testHost, propPath: testPath,
		propKeyFile: testKeyFile, propPassword: propPassword, propPort: testFoo})
	assert.Error(t, err)
}

func TestValidateRemoteBadPortNegative(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{propUsername: propUsername, propAddress: testHost, propPath: testPath,
		propKeyFile: testKeyFile, propPassword: propPassword, propPort: -1})
	assert.Error(t, err)
}

func TestValidateRemotePortFloat(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{propUsername: propUsername, propAddress: testHost, propPath: testPath,
		propKeyFile: testKeyFile, propPassword: propPassword, propPort: 22.0})
	assert.NoError(t, err)
}

func TestValidateRemotePortFloat32(t *testing.T) {
	r, _ := remote.Get("ssh")

	var p float32 = 22.0

	err := r.ValidateRemote(map[string]interface{}{propUsername: propUsername, propAddress: testHost, propPath: testPath,
		propKeyFile: testKeyFile, propPassword: propPassword, propPort: p})
	assert.NoError(t, err)
}

func TestValidateRemoteMissingRequired(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{propUsername: propUsername, propAddress: testHost})
	assert.Error(t, err)
}

func TestValidateRemoteExtraProperty(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{propUsername: propUsername, propAddress: testHost, propPath: testPath,
		testFoo: testBar})
	assert.Error(t, err)
}

func TestValidateParametersEmpty(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateParameters(map[string]interface{}{})
	assert.NoError(t, err)
}

func TestValidateParametersAllOptional(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateParameters(map[string]interface{}{propKey: propKey, propPassword: propPassword})
	assert.NoError(t, err)
}

func TestValidateParametersUnknown(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateParameters(map[string]interface{}{testFoo: testBar})
	assert.Error(t, err)
}

func TestGetAuthBoth(t *testing.T) {
	_, _, err := getAuth(map[string]interface{}{propPassword: propPassword}, map[string]interface{}{propPassword: propPassword,
		propKey: propKey})
	assert.Error(t, err)
}

func TestGetAuthKey(t *testing.T) {
	pass, key, err := getAuth(map[string]interface{}{propPassword: propPassword}, map[string]interface{}{propKey: propKey})
	assert.NoError(t, err)
	assert.Empty(t, pass)
	assert.NotEmpty(t, key)
}

func TestGetAuthParamPassword(t *testing.T) {
	pass, key, err := getAuth(map[string]interface{}{propPassword: "one"}, map[string]interface{}{propPassword: "two"})
	assert.NoError(t, err)
	assert.Equal(t, "two", pass)
	assert.Empty(t, key)
}

func TestGetAuthRemotePassword(t *testing.T) {
	pass, key, err := getAuth(map[string]interface{}{propPassword: "one"}, map[string]interface{}{})
	assert.NoError(t, err)
	assert.Equal(t, "one", pass)
	assert.Empty(t, key)
}

func TestGetAuthMissing(t *testing.T) {
	_, _, err := getAuth(map[string]interface{}{}, map[string]interface{}{})
	assert.Error(t, err)
}

func TestGetConnBadAuth(t *testing.T) {
	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, nil
	}

	_, err := c.getConnection(map[string]interface{}{}, map[string]interface{}{})
	assert.Error(t, err)
}

func TestGetConnPassword(t *testing.T) {
	host := ""

	var config *ssh.ClientConfig

	c := newTestClient()
	c.dial = func(_ string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		host = addr
		config = cfg

		return nil, nil
	}

	_, err := c.getConnection(map[string]interface{}{propUsername: propUsername, propAddress: propAddress},
		map[string]interface{}{propPassword: propPassword})
	if assert.NoError(t, err) {
		assert.Equal(t, propAddress, host)
		assert.Equal(t, propUsername, config.User)
	}
}

func TestGetConnKey(t *testing.T) {
	// Generate a throwaway RSA key at runtime rather than embedding key
	// material in the source: even test-only keys trip secret scanners in
	// a public repository.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	}))
	host := ""

	var config *ssh.ClientConfig

	c := newTestClient()
	c.dial = func(_ string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		host = addr
		config = cfg

		return nil, nil
	}

	_, err = c.getConnection(map[string]interface{}{propUsername: propUsername, propAddress: propAddress},
		map[string]interface{}{propKey: key})
	if assert.NoError(t, err) {
		assert.Equal(t, propAddress, host)
		assert.Equal(t, propUsername, config.User)
	}
}

func TestGetConnBadKey(t *testing.T) {
	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, nil
	}

	_, err := c.getConnection(map[string]interface{}{propUsername: propUsername, propAddress: propAddress},
		map[string]interface{}{propKey: "notakey"})
	assert.Error(t, err)
}

func TestGetCommit(t *testing.T) {
	remoteCommand := ""
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, command string) ([]byte, error) {
		remoteCommand = command
		return []byte("{\"a\": \"b\", \"c\": {\"d\": \"e\"}}"), nil
	}

	commit, err := c.GetCommit(map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword}, "id")
	if assert.NoError(t, err) {
		assert.Equal(t, "cat \"/path/id/metadata.json\"", remoteCommand)
		assert.Equal(t, "id", commit.ID)
		assert.Equal(t, "b", commit.Properties["a"])
		props := commit.Properties["c"].(map[string]interface{})
		assert.Equal(t, "e", props["d"])
	}
}

func TestGetCommitBadJson(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, _ string) ([]byte, error) {
		return []byte(testFoo), nil
	}

	_, err := c.GetCommit(map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword}, "id")
	assert.Error(t, err)
}

func TestGetCommitRunFail(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, _ string) ([]byte, error) {
		return nil, errors.New("error")
	}

	_, err := c.GetCommit(map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword}, "id")
	assert.Error(t, err)
}

func TestGetCommitBadConn(t *testing.T) {
	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, errors.New("error")
	}

	_, err := c.GetCommit(map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword}, "id")
	assert.Error(t, err)
}

func TestListCommitsBadConn(t *testing.T) {
	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, errors.New("error")
	}

	_, err := c.ListCommits(map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword}, []remote.Tag{})
	assert.Error(t, err)
}

func TestListCommitsRunFail(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, _ string) ([]byte, error) {
		return nil, errors.New("error")
	}

	_, err := c.ListCommits(map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword}, []remote.Tag{})
	assert.Error(t, err)
}

func TestListCommits(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, command string) ([]byte, error) {
		if command == testLsPath {
			return []byte("one\ntwo\n"), nil
		}

		if command == "cat \"/path/one/metadata.json\"" {
			return []byte("{\"timestamp\": \"2019-09-20T13:45:36Z\"}"), nil
		}

		if command == "cat \"/path/two/metadata.json\"" {
			return []byte("{\"timestamp\": \"2019-09-20T13:45:37Z\"}"), nil
		}

		return nil, errors.New("error")
	}

	commits, err := c.ListCommits(map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword}, []remote.Tag{})
	if assert.NoError(t, err) {
		assert.Len(t, commits, 2)
		assert.Equal(t, "two", commits[0].ID)
		assert.Equal(t, "one", commits[1].ID)
	}
}

func TestListCommitsTags(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, command string) ([]byte, error) {
		if command == testLsPath {
			return []byte("one\ntwo\n"), nil
		}

		if command == "cat \"/path/one/metadata.json\"" {
			return []byte("{\"timestamp\": \"2019-09-20T13:45:36Z\", \"tags\": {\"a\": \"b\"}}"), nil
		}

		if command == "cat \"/path/two/metadata.json\"" {
			return []byte("{\"timestamp\": \"2019-09-20T13:45:37Z\", \"tags\": {\"c\": \"d\"}}"), nil
		}

		return nil, errors.New("error")
	}

	commits, err := c.ListCommits(map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword}, []remote.Tag{{Key: "a"}})
	if assert.NoError(t, err) {
		assert.Len(t, commits, 1)
		assert.Equal(t, "one", commits[0].ID)
	}
}

// --- Issue #1: command injection via unvalidated commitID ---

func TestGetCommitRejectsMaliciousCommitID(t *testing.T) {
	// The malicious commitID must never reach the `run` shim. If it does,
	// it would execute arbitrary shell commands on the remote host.
	runCalled := false
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, _ string) ([]byte, error) {
		runCalled = true
		return []byte("{}"), nil
	}

	_, err := c.GetCommit(
		map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword},
		`id"; cat /etc/passwd; echo "`,
	)
	assert.Error(t, err)
	assert.False(t, runCalled, "malicious commitID must not reach the run shim")
}

func TestListCommitsRejectsMaliciousCommitID(t *testing.T) {
	// ListCommits parses `ls -1` output as commit IDs; an attacker who controls
	// the remote filesystem could plant a directory name with shell metacharacters
	// which would then be interpolated into the `cat` command. readCommit must
	// reject those before they reach `run`.
	commands := []string{}
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, command string) ([]byte, error) {
		commands = append(commands, command)
		if command == testLsPath {
			// First entry is malicious, second is legitimate.
			return []byte("evil\"; rm -rf /; echo \"\nlegit\n"), nil
		}

		if command == "cat \"/path/legit/metadata.json\"" {
			return []byte("{\"timestamp\": \"2019-09-20T13:45:36Z\"}"), nil
		}

		return nil, errors.New("unexpected command")
	}

	commits, err := c.ListCommits(
		map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword},
		[]remote.Tag{},
	)
	if assert.NoError(t, err) {
		assert.Len(t, commits, 1)
		assert.Equal(t, "legit", commits[0].ID)
	}

	for _, cmd := range commands {
		assert.NotContains(t, cmd, "rm -rf", "malicious commitID reached the shell command")
		assert.NotContains(t, cmd, "evil", "malicious commitID reached the shell command")
	}
}

func TestGetCommitValidCommitIDCharacters(t *testing.T) {
	// Valid commit IDs use [A-Za-z0-9._-]. Verify the allowlist accepts a
	// realistic ID containing all of those.
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, _ string) ([]byte, error) {
		return []byte("{}"), nil
	}

	_, err := c.GetCommit(
		map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword},
		"abc123.DEF_456-789",
	)
	assert.NoError(t, err)
}

func TestGetCommitEmptyCommitIDRejected(t *testing.T) {
	runCalled := false
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, _ string) ([]byte, error) {
		runCalled = true
		return []byte("{}"), nil
	}

	_, err := c.GetCommit(
		map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword},
		"",
	)
	assert.Error(t, err)
	assert.False(t, runCalled, "empty commitID must not reach the run shim")
}

// --- Issue #2: unchecked .(string) type assertions ---

func TestToURLWithWrongPathType(t *testing.T) {
	r, _ := remote.Get("ssh")
	assert.NotPanics(t, func() {
		_, _, err := r.ToURL(map[string]interface{}{
			propUsername: propUsername,
			propAddress:  testHost,
			propPath:     123, // wrong type: int, not string
		})
		assert.Error(t, err)
	})
}

func TestToURLWithWrongKeyFileType(t *testing.T) {
	r, _ := remote.Get("ssh")
	assert.NotPanics(t, func() {
		_, _, err := r.ToURL(map[string]interface{}{
			propUsername: propUsername,
			propAddress:  testHost,
			propPath:     testPath,
			propKeyFile:  42, // wrong type: int, not string
		})
		assert.Error(t, err)
	})
}

func TestGetParametersWithWrongKeyFileType(t *testing.T) {
	r, _ := remote.Get("ssh")
	assert.NotPanics(t, func() {
		_, err := r.GetParameters(map[string]interface{}{
			propUsername: propUsername,
			propAddress:  testHost,
			propPath:     testPath,
			propKeyFile:  3.14, // wrong type: float, not string
		})
		assert.Error(t, err)
	})
}

// --- Issue #8: typo in error message ---

func TestFromURLErrorUsesCorrectSpelling(t *testing.T) {
	r, _ := remote.Get("ssh")
	_, err := r.FromURL("ssh://user@host/path", map[string]string{testFoo: testBar})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "remote")
		assert.NotContains(t, err.Error(), "rmeote")
	}
}

// --- stringOrError: missing-key branch ---

func TestToURLMissingPath(t *testing.T) {
	r, _ := remote.Get("ssh")
	assert.NotPanics(t, func() {
		_, _, err := r.ToURL(map[string]interface{}{
			propUsername: propUsername,
			propAddress:  testHost,
			// propPath intentionally absent
		})
		assert.Error(t, err)
	})
}

// --- ListCommits: empty line in directory listing is skipped silently ---

func TestListCommitsSkipsBlankLines(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)

	c := newTestClient()
	c.dial = func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	c.run = func(_ *ssh.Client, command string) ([]byte, error) {
		if command == testLsPath {
			return []byte("\n\nrealid\n\n"), nil
		}

		if command == "cat \"/path/realid/metadata.json\"" {
			return []byte("{\"timestamp\": \"2019-09-20T13:45:36Z\"}"), nil
		}

		return nil, errors.New("unexpected command")
	}

	commits, err := c.ListCommits(
		map[string]interface{}{propUsername: propUsername, propAddress: propAddress, propPath: testPath},
		map[string]interface{}{propPassword: propPassword},
		[]remote.Tag{},
	)
	if assert.NoError(t, err) {
		assert.Len(t, commits, 1)
		assert.Equal(t, "realid", commits[0].ID)
	}
}
