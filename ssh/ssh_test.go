/*
 * Copyright The Titan Project Contributors.
 */
package ssh

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/titan-data/remote-sdk-go/remote"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistered(t *testing.T) {
	r := remote.Get("ssh")
	ret, err := r.Type()
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh", ret)
	}
}

func TestFromURL(t *testing.T) {
	r := remote.Get("ssh")
	props, err := r.FromURL("ssh://user:pass@host:8022/path", map[string]string{})
	if assert.NoError(t, err) {
		assert.Equal(t, "user", props["username"])
		assert.Equal(t, "pass", props["password"])
		assert.Equal(t, "host", props["address"])
		assert.Equal(t, 8022, props["port"])
		assert.Equal(t, "/path", props["path"])
		assert.Nil(t, props["keyFile"])
	}
}

func TestSimple(t *testing.T) {
	r := remote.Get("ssh")
	props, err := r.FromURL("ssh://user@host/path", map[string]string{})
	if assert.NoError(t, err) {
		assert.Equal(t, "user", props["username"])
		assert.Nil(t, props["password"])
		assert.Equal(t, "host", props["address"])
		assert.Nil(t, props["port"])
		assert.Equal(t, "/path", props["path"])
		assert.Nil(t, props["keyFile"])
	}
}

func TestKeyFile(t *testing.T) {
	r := remote.Get("ssh")
	props, err := r.FromURL("ssh://user@host/path", map[string]string{"keyFile": "~/.ssh/id_dsa"})
	if assert.NoError(t, err) {
		assert.Equal(t, "~/.ssh/id_dsa", props["keyFile"])
	}
}

func TestRelativePath(t *testing.T) {
	r := remote.Get("ssh")
	props, err := r.FromURL("ssh://user@host/~/relative/path", map[string]string{})
	if assert.NoError(t, err) {
		assert.Equal(t, "relative/path", props["path"])
	}
}

func TestBadUrl(t *testing.T) {
	r := remote.Get("ssh")
	_, err := r.FromURL("ssh://host\nname", map[string]string{})
	assert.Error(t, err)
}

func TestBadScheme(t *testing.T) {
	r := remote.Get("ssh")
	_, err := r.FromURL("foo://user:pass@host:8022/path", map[string]string{})
	assert.Error(t, err)
}

func TestBadPasswordAndKeyFile(t *testing.T) {
	r := remote.Get("ssh")
	_, err := r.FromURL("ssh://user:password@host/path", map[string]string{"keyFile": "~/.ssh/id_dsa"})
	assert.Error(t, err)
}

func TestBadProperty(t *testing.T) {
	r := remote.Get("ssh")
	_, err := r.FromURL("ssh://user@host/path", map[string]string{"foo": "bar"})
	assert.Error(t, err)
}

func TestBadMissingHost(t *testing.T) {
	r := remote.Get("ssh")
	_, err := r.FromURL("ssh:///path", map[string]string{})
	assert.Error(t, err)
}

func TestBadSchemeOnly(t *testing.T) {
	r := remote.Get("ssh")
	_, err := r.FromURL("ssh", map[string]string{})
	assert.Error(t, err)
}

func TestBadMissingUsername(t *testing.T) {
	r := remote.Get("ssh")
	_, err := r.FromURL("ssh://host/path", map[string]string{})
	assert.Error(t, err)
}

func TestBadPort(t *testing.T) {
	r := remote.Get("ssh")
	_, err := r.FromURL("ssh://user@host:29348529384572398457932847539/path", map[string]string{})
	assert.Error(t, err)
}

func TestBadMissingPath(t *testing.T) {
	r := remote.Get("ssh")
	_, err := r.FromURL("ssh://user@host", map[string]string{})
	assert.Error(t, err)
}

func TestBadMissingHostWithUser(t *testing.T) {
	r := remote.Get("ssh")
	_, err := r.FromURL("ssh://user@/path", map[string]string{})
	assert.Error(t, err)
}

func TestToURL(t *testing.T) {
	r := remote.Get("ssh")
	u, props, err := r.ToURL(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path"})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host/path", u)
		assert.Empty(t, props)
	}
}

func TestToPassword(t *testing.T) {
	r := remote.Get("ssh")
	u, props, err := r.ToURL(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path", "password": "pass"})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username:*****@host/path", u)
		assert.Empty(t, props)
	}
}

func TestToPort(t *testing.T) {
	r := remote.Get("ssh")
	u, props, err := r.ToURL(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path", "port": 812})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host:812/path", u)
		assert.Empty(t, props)
	}
}

func TestToBadPort(t *testing.T) {
	r := remote.Get("ssh")
	_, _, err := r.ToURL(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path", "port": "812"})
	assert.Error(t, err)
}

func TestToRelativePath(t *testing.T) {
	r := remote.Get("ssh")
	u, props, err := r.ToURL(map[string]interface{}{"username": "username", "address": "host",
		"path": "path"})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host/~/path", u)
		assert.Empty(t, props)
	}
}

func TestToKeyFile(t *testing.T) {
	r := remote.Get("ssh")
	u, props, err := r.ToURL(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path", "keyFile": "keyfile"})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host/path", u)
		assert.Len(t, props, 1)
		assert.Equal(t, "keyfile", props["keyFile"])
	}
}

func TestToPortFloat(t *testing.T) {
	p := float32(812)
	r := remote.Get("ssh")
	u, props, err := r.ToURL(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path", "port": p})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host:812/path", u)
		assert.Empty(t, props)
	}
}

func TestToPortDouble(t *testing.T) {
	r := remote.Get("ssh")
	u, props, err := r.ToURL(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path", "port": 812.0})
	if assert.NoError(t, err) {
		assert.Equal(t, "ssh://username@host:812/path", u)
		assert.Empty(t, props)
	}
}

func TestGetParameters(t *testing.T) {
	r := remote.Get("ssh")
	props, err := r.GetParameters(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path", "password": "pass"})
	if assert.NoError(t, err) {
		assert.Empty(t, props)
	}
}

func TestKeyFileParameters(t *testing.T) {
	r := remote.Get("ssh")
	file, err := ioutil.TempFile("", "ssh.test")
	if !assert.NoError(t, err) {
		return
	}
	defer os.Remove(file.Name())
	path, err := filepath.Abs(file.Name())
	if !assert.NoError(t, err) {
		return
	}

	err = ioutil.WriteFile(path, []byte("KEY"), 0600)
	if !assert.NoError(t, err) {
		return
	}

	props, err := r.GetParameters(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path", "keyFile": path})
	if assert.NoError(t, err) {
		assert.Nil(t, props["password"])
		assert.Equal(t, "KEY", props["key"])
	}
}

func TestBadKeyFileParameters(t *testing.T) {
	r := remote.Get("ssh")
	file, err := ioutil.TempFile("", "ssh.test")
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
		_, err = r.GetParameters(map[string]interface{}{"username": "username", "address": "host",
			"path": "/path", "keyFile": path})
		assert.Error(t, err)
	}
}

func TestPasswordPrompt(t *testing.T) {
	r := remote.Get("ssh")
	readPassword = func(fd int) (bytes []byte, err error) {
		return []byte("pass"), nil
	}
	fmtPrintf = func(format string, a ...interface{}) (n int, err error) {
		return 0, nil
	}
	props, err := r.GetParameters(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path"})
	if assert.NoError(t, err) {
		readPassword = terminal.ReadPassword
		fmtPrintf = fmt.Printf

		assert.Nil(t, props["key"])
		assert.Equal(t, "pass", props["password"])
	}
}

func TestBadPasswordPrompt(t *testing.T) {
	r := remote.Get("ssh")
	readPassword = func(fd int) (bytes []byte, err error) {
		return []byte{}, errors.New("error")
	}
	fmtPrintf = func(format string, a ...interface{}) (n int, err error) {
		return 0, nil
	}
	_, err := r.GetParameters(map[string]interface{}{"username": "username", "address": "host",
		"path": "/path"})
	readPassword = terminal.ReadPassword
	fmtPrintf = fmt.Printf

	assert.Error(t, err)
}

func TestValidateRemoteRequiredOnly(t *testing.T) {
	r := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{"username": "username", "address": "host", "path": "/path"})
	assert.NoError(t, err)
}

func TestValidateRemoteAllOptional(t *testing.T) {
	r := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{"username": "username", "address": "host", "path": "/path",
		"keyFile": "/keyfile", "password": "password", "port": 8022})
	assert.NoError(t, err)
}

func TestValidateRemoteBadPort(t *testing.T) {
	r := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{"username": "username", "address": "host", "path": "/path",
		"keyFile": "/keyfile", "password": "password", "port": "foo"})
	assert.Error(t, err)
}

func TestValidateRemoteBadPortNegative(t *testing.T) {
	r := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{"username": "username", "address": "host", "path": "/path",
		"keyFile": "/keyfile", "password": "password", "port": -1})
	assert.Error(t, err)
}

func TestValidateRemotePortFloat(t *testing.T) {
	r := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{"username": "username", "address": "host", "path": "/path",
		"keyFile": "/keyfile", "password": "password", "port": 22.0})
	assert.NoError(t, err)
}

func TestValidateRemotePortFloat32(t *testing.T) {
	r := remote.Get("ssh")
	var p float32 = 22.0
	err := r.ValidateRemote(map[string]interface{}{"username": "username", "address": "host", "path": "/path",
		"keyFile": "/keyfile", "password": "password", "port": p})
	assert.NoError(t, err)
}

func TestValidateRemoteMissingRequired(t *testing.T) {
	r := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{"username": "username", "address": "host"})
	assert.Error(t, err)
}

func TestValidateRemoteExtraProperty(t *testing.T) {
	r := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{"username": "username", "address": "host", "path": "/path",
		"foo": "bar"})
	assert.Error(t, err)
}

func TestValidateParametersEmpty(t *testing.T) {
	r := remote.Get("ssh")
	err := r.ValidateParameters(map[string]interface{}{})
	assert.NoError(t, err)
}

func TestValidateParametersAllOptional(t *testing.T) {
	r := remote.Get("ssh")
	err := r.ValidateParameters(map[string]interface{}{"key": "key", "password": "password"})
	assert.NoError(t, err)
}

func TestValidateParametersUnknown(t *testing.T) {
	r := remote.Get("ssh")
	err := r.ValidateParameters(map[string]interface{}{"foo": "bar"})
	assert.Error(t, err)
}

func TestGetAuthBoth(t *testing.T) {
	_, _, err := getAuth(map[string]interface{}{"password": "password"}, map[string]interface{}{"password": "password",
		"key": "key"})
	assert.Error(t, err)
}

func TestGetAuthKey(t *testing.T) {
	pass, key, err := getAuth(map[string]interface{}{"password": "password"}, map[string]interface{}{"key": "key"})
	assert.NoError(t, err)
	assert.Empty(t, pass)
	assert.NotEmpty(t, key)
}

func TestGetAuthParamPassword(t *testing.T) {
	pass, key, err := getAuth(map[string]interface{}{"password": "one"}, map[string]interface{}{"password": "two"})
	assert.NoError(t, err)
	assert.Equal(t, "two", pass)
	assert.Empty(t, key)
}

func TestGetAuthRemotePassword(t *testing.T) {
	pass, key, err := getAuth(map[string]interface{}{"password": "one"}, map[string]interface{}{})
	assert.NoError(t, err)
	assert.Equal(t, "one", pass)
	assert.Empty(t, key)
}

func TestGetAuthMissing(t *testing.T) {
	_, _, err := getAuth(map[string]interface{}{}, map[string]interface{}{})
	assert.Error(t, err)
}

func TestGetConnBadAuth(t *testing.T) {
	dial = func(network string, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, nil
	}
	_, err := getConnection(map[string]interface{}{}, map[string]interface{}{})
	dial = ssh.Dial
	assert.Error(t, err)
}

func TestGetConnPassword(t *testing.T) {
	host := ""
	var config *ssh.ClientConfig = nil
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		host = addr
		config = cfg
		return nil, nil
	}
	_, err := getConnection(map[string]interface{}{"username": "username", "address": "address"},
		map[string]interface{}{"password": "password"})
	if assert.NoError(t, err) {
		assert.Equal(t, "address", host)
		assert.Equal(t, "username", config.User)
	}
	dial = ssh.Dial
}

func TestGetConnKey(t *testing.T) {
	key := `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsXU8SiL4eLBupbLEF9XAy+60Dr5+TPSUm8c27WCUfYOF5Yly
DWZcTS86coEGjgfqDFM6o3wXgadugt/XYi7M2k0QVsmX1577088/SixrNnX8HQyX
f3S4tLGDLX/d48A2Xi6FmJUpHqyPzKzVU1THQPOKoxZUV4qZmbRrR0FO8WmZMQTl
KNNopq4fvEPZw0oNPONS8e28zvCu0qqka06+mB5pIc5+OhXoQK4xPgPr/gW5Cruv
R5IgBt4gdLMSpBp2JB3hFj6U0c+7wmGaZYt5R92/b8tetn/jMhIt7720mJJPfq1d
1W1UpERZjUTMvFzNBLdCtgT59qxqL+Tv4QA6AQIDAQABAoIBAE7EvQgjUaswlUyT
dxslVDixMddBkwpRng0vdiATuJWl5a8nPSrZfqr8BbOBtgkhVjA2WVbr4/s2+IS7
Gv2HzIIxpsj/HpklBp7T5UHlSYmZAVlbl3uJsdry2Ek/8pv/W6Kef8pkmyX0brfp
F5+vh+o6sBUH+lQJP3jMbrnoMURSX9jFSPg/+J1zb1Nf/SulBro4+Pb4t+i97FUk
mWqMI1jvCkAnQJ0oYQ9CeYBJjvXeENyN7HQ+RM6OEdsHi64EMfJCwrZGMAHIo2Ty
87AQhgoHEKfNC+XotnkPaKmS5qaP2ggPe2Ol63k3FbR6VHlqJny0VR48pbzyQyr2
feENXWECgYEA2naSDRVCwiAdZAIvMa0cDjpwOYIfLJelc0hljCOaLQeye2oT+hAQ
pCVO7+maD4VbZ1Xmc70LGFSWktVlByJU9UOBY5rq7DTgXoEMoOtf2uUcJupnLLix
we7Fn9TFaM3RWKbbg3G0OjucepB7yVZ2qSVDGPQ8Bl/IKq2hfKsqy3UCgYEAz/L9
PU0gzxmZlF1rea1d3clNoounW/J1qHXl2nT11RaIzPhct1fKde/wIt/D7gqwI3ba
wBJhNv/a4kDvnJwV3iyEKFs7qqeqaZ1KsLCkaQ0erdhl8LzfE25MWKlTthqjY9yT
f8ohD0r57y8NVInwfXhBKIUZr3qXBA+d0krfft0CgYACgbnLTKMndxbfPucrusDH
qQQApO2WpWbQm9QOd5odSilSITV5eRW3zHXLavLJms4hsWqjiVfHP7E6nhg6rLos
1kl1yyFG9JRegTyT3B+Nc3OPPsFQUg44G3VJEDfzq+jrC38ZUwSuZmC1R1MkTEmw
Ry0t7B+EMzUoyDVCKPSkwQKBgQC+roMWdiYSodfZWzyVK6r6F4AP/90sDA1ltw5Z
HozZo7s3sLpcCK2HLchWQjfIjJZtPqxiGbh5FW3hsEfHpLzMqKda1iXFW8+A3xHB
KYjpJ3WtVdRMRvSLPcXWOxae0phmlrnOIUvlWQwMDmo7zezvMJkXDc26wj++Io/G
aI++JQKBgQDYBW6xXOYHFbCazz7euPRXaV0BX9Pt+ylrQvqDWwa6fk9FDGOrhRW8
1ywiam3Z+Nup2JNE8PjwP0qQisLbzAbG60HMg2Yx0C6yclIZLUDEwmrjmBVCiP81
qXdXtd+SfLRrfCd1KJRp8NFIPFsk0T3iy8hxZJZSHtM6/nwM3p2rHw==
-----END RSA PRIVATE KEY-----`
	host := ""
	var config *ssh.ClientConfig = nil
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		host = addr
		config = cfg
		return nil, nil
	}
	_, err := getConnection(map[string]interface{}{"username": "username", "address": "address"},
		map[string]interface{}{"key": key})
	if assert.NoError(t, err) {
		assert.Equal(t, "address", host)
		assert.Equal(t, "username", config.User)
	}
	dial = ssh.Dial
}

func TestGetConnBadKey(t *testing.T) {
	key := "notakey"
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, nil
	}
	_, err := getConnection(map[string]interface{}{"username": "username", "address": "address"},
		map[string]interface{}{"key": key})
	assert.Error(t, err)
	dial = ssh.Dial
}

func TestGetCommit(t *testing.T) {
	remoteCommand := ""
	conn := new(MockConn)
	conn.On("Close").Return(nil)
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	run = func(conn *ssh.Client, command string) (bytes []byte, err error) {
		remoteCommand = command
		return []byte("{\"a\": \"b\", \"c\": {\"d\": \"e\"}}"), nil
	}
	r := remote.Get("ssh")
	commit, err := r.GetCommit(map[string]interface{}{"username": "username", "address": "address", "path": "/path"},
		map[string]interface{}{"password": "password"}, "id")
	if assert.NoError(t, err) {
		assert.Equal(t, "cat \"/path/id/metadata.json\"", remoteCommand)
		assert.Equal(t, "id", commit.Id)
		assert.Equal(t, "b", commit.Properties["a"])
		props := commit.Properties["c"].(map[string]interface{})
		assert.Equal(t, "e", props["d"])
	}

	run = runCommand
	dial = ssh.Dial
}

func TestGetCommitBadJson(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	run = func(conn *ssh.Client, command string) (bytes []byte, err error) {
		return []byte("foo"), nil
	}
	r := remote.Get("ssh")
	_, err := r.GetCommit(map[string]interface{}{"username": "username", "address": "address", "path": "/path"},
		map[string]interface{}{"password": "password"}, "id")
	assert.Error(t, err)

	run = runCommand
	dial = ssh.Dial
}

func TestGetCommitRunFail(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	run = func(conn *ssh.Client, command string) (bytes []byte, err error) {
		return nil, errors.New("error")
	}
	r := remote.Get("ssh")
	_, err := r.GetCommit(map[string]interface{}{"username": "username", "address": "address", "path": "/path"},
		map[string]interface{}{"password": "password"}, "id")
	assert.Error(t, err)

	run = runCommand
	dial = ssh.Dial
}

func TestGetCommitBadConn(t *testing.T) {
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, errors.New("error")
	}
	r := remote.Get("ssh")
	_, err := r.GetCommit(map[string]interface{}{"username": "username", "address": "address", "path": "/path"},
		map[string]interface{}{"password": "password"}, "id")
	assert.Error(t, err)
	dial = ssh.Dial
}

func TestListCommitsBadConn(t *testing.T) {
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, errors.New("error")
	}
	r := remote.Get("ssh")
	_, err := r.ListCommits(map[string]interface{}{"username": "username", "address": "address", "path": "/path"},
		map[string]interface{}{"password": "password"}, []remote.Tag{})
	assert.Error(t, err)
	dial = ssh.Dial
}

func TestListCommitsRunFail(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	run = func(conn *ssh.Client, command string) (bytes []byte, err error) {
		return nil, errors.New("error")
	}
	r := remote.Get("ssh")
	_, err := r.ListCommits(map[string]interface{}{"username": "username", "address": "address", "path": "/path"},
		map[string]interface{}{"password": "password"}, []remote.Tag{})
	assert.Error(t, err)

	run = runCommand
	dial = ssh.Dial
}

func TestListCommits(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	run = func(conn *ssh.Client, command string) (bytes []byte, err error) {
		if command == "ls -1 \"/path\"" {
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
	r := remote.Get("ssh")
	commits, err := r.ListCommits(map[string]interface{}{"username": "username", "address": "address", "path": "/path"},
		map[string]interface{}{"password": "password"}, []remote.Tag{})
	if assert.NoError(t, err) {
		assert.Len(t, commits, 2)
		assert.Equal(t, "two", commits[0].Id)
		assert.Equal(t, "one", commits[1].Id)
	}
	run = runCommand
	dial = ssh.Dial
}

func TestListCommitsTags(t *testing.T) {
	conn := new(MockConn)
	conn.On("Close").Return(nil)
	dial = func(network string, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return &ssh.Client{Conn: conn}, nil
	}
	run = func(conn *ssh.Client, command string) (bytes []byte, err error) {
		if command == "ls -1 \"/path\"" {
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
	r := remote.Get("ssh")
	commits, err := r.ListCommits(map[string]interface{}{"username": "username", "address": "address", "path": "/path"},
		map[string]interface{}{"password": "password"}, []remote.Tag{{Key: "a"}})
	if assert.NoError(t, err) {
		assert.Len(t, commits, 1)
		assert.Equal(t, "one", commits[0].Id)
	}
	run = runCommand
	dial = ssh.Dial
}
