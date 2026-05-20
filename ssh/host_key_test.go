/*
 * Copyright Datadatdat.
 */
package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/datadatdat/remote-sdk-go/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	testLocalhost     = "127.0.0.1"
	testLocalhostAddr = "127.0.0.1:22"
	testRemoteHost    = "remote.example.com"
	testWildcardAddr  = "1.2.3.4:22"
	testStrTrue       = "true"
	testStrFalse      = "false"
)

// generateTestHostKey returns an ssh.PublicKey suitable for populating a
// known_hosts fixture in unit tests. RSA-2048 is large enough to be accepted
// by golang.org/x/crypto/ssh without warnings while still being fast enough
// for tests.
func generateTestHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return pub
}

// writeKnownHostsFile writes a known_hosts file containing a single entry for
// the supplied address and key, and returns its absolute path. The address is
// expected to be a "host:port" pair (matching what dial passes to the
// HostKeyCallback).
func writeKnownHostsFile(t *testing.T, addr string, key ssh.PublicKey) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)
	require.NoError(t, os.WriteFile(path, []byte(line+"\n"), 0600))
	return path
}

// fakeAddr implements net.Addr so we can hand the HostKeyCallback a deterministic
// remote address. golang.org/x/crypto/ssh always supplies a net.Addr, never nil.
type fakeAddr struct{ s string }

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return f.s }

// --- buildHostKeyCallback policy: secure by default ---

func TestBuildHostKeyCallbackAcceptsKnownHost(t *testing.T) {
	key := generateTestHostKey(t)
	khPath := writeKnownHostsFile(t, testLocalhostAddr, key)

	cb, err := buildHostKeyCallback(map[string]interface{}{
		propAddress:        testLocalhost,
		propKnownHostsFile: khPath,
	})
	require.NoError(t, err)
	require.NotNil(t, cb)

	err = cb(testLocalhostAddr, fakeAddr{s: testLocalhostAddr}, key)
	assert.NoError(t, err, "key matching known_hosts entry must be accepted")
}

func TestBuildHostKeyCallbackRejectsUnknownHostWithGuidance(t *testing.T) {
	key := generateTestHostKey(t)
	// Empty known_hosts file: host will not be found.
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	require.NoError(t, os.WriteFile(khPath, []byte(""), 0600))

	cb, err := buildHostKeyCallback(map[string]interface{}{
		propAddress:        testRemoteHost,
		propKnownHostsFile: khPath,
	})
	require.NoError(t, err)

	err = cb(testRemoteHost+":22", fakeAddr{s: "203.0.113.5:22"}, key)
	require.Error(t, err)
	msg := err.Error()
	// The error must name the host, point at the known_hosts path, suggest
	// ssh-keyscan, and tell the operator how to opt out.
	assert.Contains(t, msg, testRemoteHost, "error must name the host")
	assert.Contains(t, msg, khPath, "error must reference the known_hosts file")
	assert.Contains(t, msg, "ssh-keyscan", "error must mention ssh-keyscan recovery")
	assert.Contains(t, msg, "skip_host_check", "error must mention the opt-out knob")
}

func TestBuildHostKeyCallbackSkipHostCheckBool(t *testing.T) {
	cb, err := buildHostKeyCallback(map[string]interface{}{
		propAddress:       testRemoteHost,
		propSkipHostCheck: true,
	})
	require.NoError(t, err)
	require.NotNil(t, cb)

	// With skip enabled, ANY key on ANY host is accepted (the legacy behavior).
	anyKey := generateTestHostKey(t)
	err = cb("anything", fakeAddr{s: testWildcardAddr}, anyKey)
	assert.NoError(t, err, "skip_host_check=true must accept any host key")
}

func TestBuildHostKeyCallbackSkipHostCheckStringTrue(t *testing.T) {
	cb, err := buildHostKeyCallback(map[string]interface{}{
		propAddress:       testRemoteHost,
		propSkipHostCheck: testStrTrue,
	})
	require.NoError(t, err)

	anyKey := generateTestHostKey(t)
	err = cb("anything", fakeAddr{s: testWildcardAddr}, anyKey)
	assert.NoError(t, err, "skip_host_check=\"true\" string must be coerced to bool true")
}

func TestBuildHostKeyCallbackSkipHostCheckStringFalseIsSecure(t *testing.T) {
	key := generateTestHostKey(t)
	khPath := writeKnownHostsFile(t, testLocalhostAddr, key)

	cb, err := buildHostKeyCallback(map[string]interface{}{
		propAddress:        testLocalhost,
		propKnownHostsFile: khPath,
		propSkipHostCheck:  testStrFalse,
	})
	require.NoError(t, err)

	// "false" string must NOT disable verification: a wrong key is rejected.
	wrong := generateTestHostKey(t)
	err = cb(testLocalhostAddr, fakeAddr{s: testLocalhostAddr}, wrong)
	assert.Error(t, err, "skip_host_check=\"false\" must keep verification on")
}

func TestBuildHostKeyCallbackCustomKnownHostsFile(t *testing.T) {
	key := generateTestHostKey(t)
	addr := "host.test:22"
	khPath := writeKnownHostsFile(t, addr, key)

	cb, err := buildHostKeyCallback(map[string]interface{}{
		propAddress:        "host.test",
		propKnownHostsFile: khPath,
	})
	require.NoError(t, err)

	err = cb("host.test:22", fakeAddr{s: addr}, key)
	assert.NoError(t, err)
}

func TestBuildHostKeyCallbackMissingKnownHostsFile(t *testing.T) {
	cb, err := buildHostKeyCallback(map[string]interface{}{
		propAddress:        testRemoteHost,
		propKnownHostsFile: "/does/not/exist/known_hosts",
	})
	require.NoError(t, err, "missing known_hosts file is treated as empty, not a configuration error")
	require.NotNil(t, cb)

	// A missing file behaves like an empty file: the host is unknown.
	key := generateTestHostKey(t)
	err = cb(testRemoteHost+":22", fakeAddr{s: "10.0.0.1:22"}, key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/does/not/exist/known_hosts")
}

func TestBuildHostKeyCallbackRejectsGarbageSkipHostCheck(t *testing.T) {
	// Garbage value at the buildHostKeyCallback layer is also caught (defense
	// in depth: ValidateRemote catches it earlier, but a misuse of the
	// internal API still gets a clean error rather than a security regression).
	_, err := buildHostKeyCallback(map[string]interface{}{
		propAddress:       testRemoteHost,
		propSkipHostCheck: 42,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), propSkipHostCheck)
}

func TestBuildHostKeyCallbackRejectsGarbageKnownHostsFile(t *testing.T) {
	_, err := buildHostKeyCallback(map[string]interface{}{
		propAddress:        testRemoteHost,
		propKnownHostsFile: 42,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), propKnownHostsFile)
}

func TestBuildHostKeyCallbackUsesDefaultKnownHostsPath(t *testing.T) {
	// When propKnownHostsFile is absent, the callback must consult
	// defaultKnownHostsFile(). We verify by overriding HOME to a tempdir
	// that contains no known_hosts file and observing that the rejection
	// error references that path.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	// Windows uses USERPROFILE; set both so the test works cross-platform.
	t.Setenv("USERPROFILE", tmpHome)

	cb, err := buildHostKeyCallback(map[string]interface{}{
		propAddress: testRemoteHost,
	})
	require.NoError(t, err)

	key := generateTestHostKey(t)
	cbErr := cb(testRemoteHost+":22", fakeAddr{s: "10.0.0.1:22"}, key)
	require.Error(t, cbErr)
	// The default path is HOME/.ssh/known_hosts. The error should include
	// that path so the operator knows where to write the keyscan output.
	assert.Contains(t, cbErr.Error(), filepath.Join(tmpHome, ".ssh", "known_hosts"))
}

func TestFormatHostKeyErrorFallsBackToHostname(t *testing.T) {
	// When the configured address is empty (e.g., the callback was reached
	// via a code path that didn't populate propAddress), the hostname passed
	// by ssh.Dial is used in the error message instead.
	err := formatHostKeyError("", "fallback.example.com:22", "/dev/null", assert.AnError)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fallback.example.com:22")
}

// --- validateRemote: accepts skip_host_check + known_hosts_file ---

func TestValidateRemoteAcceptsSkipHostCheckBool(t *testing.T) {
	r, _ := remote.Get("ssh")
	for _, v := range []interface{}{true, false} {
		err := r.ValidateRemote(map[string]interface{}{
			propUsername:      propUsername,
			propAddress:       testHost,
			propPath:          testPath,
			propSkipHostCheck: v,
		})
		assert.NoError(t, err, "skip_host_check=%v must be accepted", v)
	}
}

func TestValidateRemoteAcceptsSkipHostCheckString(t *testing.T) {
	r, _ := remote.Get("ssh")
	for _, v := range []string{testStrTrue, testStrFalse, "TRUE", "False"} {
		err := r.ValidateRemote(map[string]interface{}{
			propUsername:      propUsername,
			propAddress:       testHost,
			propPath:          testPath,
			propSkipHostCheck: v,
		})
		assert.NoError(t, err, "skip_host_check=%q must be accepted", v)
	}
}

func TestValidateRemoteRejectsSkipHostCheckGarbage(t *testing.T) {
	r, _ := remote.Get("ssh")
	// Int, garbage string, and float must all be rejected so a typo cannot
	// silently disable a security control.
	cases := []interface{}{42, "yes", 1.5, "maybe"}
	for _, v := range cases {
		err := r.ValidateRemote(map[string]interface{}{
			propUsername:      propUsername,
			propAddress:       testHost,
			propPath:          testPath,
			propSkipHostCheck: v,
		})
		assert.Error(t, err, "skip_host_check=%v (type %T) must be rejected", v, v)
		if err != nil {
			assert.Contains(t, strings.ToLower(err.Error()), "skip_host_check")
		}
	}
}

func TestValidateRemoteAcceptsKnownHostsFile(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{
		propUsername:       propUsername,
		propAddress:        testHost,
		propPath:           testPath,
		propKnownHostsFile: "/etc/ssh/known_hosts",
	})
	assert.NoError(t, err)
}

func TestValidateRemoteRejectsKnownHostsFileNonString(t *testing.T) {
	r, _ := remote.Get("ssh")
	err := r.ValidateRemote(map[string]interface{}{
		propUsername:       propUsername,
		propAddress:        testHost,
		propPath:           testPath,
		propKnownHostsFile: 42,
	})
	assert.Error(t, err)
}

// --- coerceBoolean ---

func TestCoerceBooleanAcceptedValues(t *testing.T) {
	for _, c := range []struct {
		in   interface{}
		want bool
	}{
		{true, true},
		{false, false},
		{"true", true},
		{"false", false},
		{"TRUE", true},
		{"False", false},
	} {
		got, err := coerceBoolean("p", c.in)
		assert.NoError(t, err, "input %v", c.in)
		assert.Equal(t, c.want, got, "input %v", c.in)
	}
}

func TestCoerceBooleanRejectsBadValues(t *testing.T) {
	for _, in := range []interface{}{42, "yes", 1.5, nil, []string{"true"}} {
		_, err := coerceBoolean("p", in)
		assert.Error(t, err, "input %v (type %T) must be rejected", in, in)
	}
}

// --- getConnection wires the callback into the config ---

func TestGetConnectionUsesSecureCallbackByDefault(t *testing.T) {
	// Use an empty known_hosts so the default-secure callback rejects.
	emptyKH := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(emptyKH, []byte(""), 0600))

	var capturedCfg *ssh.ClientConfig

	c := newTestClient()
	c.dial = func(_ string, _ string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		capturedCfg = cfg
		return nil, nil
	}

	_, err := c.getConnection(
		map[string]interface{}{
			propUsername:       propUsername,
			propAddress:        testLocalhost,
			propKnownHostsFile: emptyKH,
		},
		map[string]interface{}{propPassword: propPassword},
	)
	require.NoError(t, err)
	require.NotNil(t, capturedCfg)
	require.NotNil(t, capturedCfg.HostKeyCallback)

	// The default callback MUST reject an unknown host (i.e., it's not
	// InsecureIgnoreHostKey). We invoke it with a generated key and expect
	// an error because known_hosts is empty.
	key := generateTestHostKey(t)
	cbErr := capturedCfg.HostKeyCallback(testLocalhostAddr, fakeAddr{s: testLocalhostAddr}, key)
	assert.Error(t, cbErr, "default HostKeyCallback must verify, not silently accept")
}

func TestGetConnectionUsesInsecureCallbackWhenSkipHostCheck(t *testing.T) {
	var capturedCfg *ssh.ClientConfig

	c := newTestClient()
	c.dial = func(_ string, _ string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		capturedCfg = cfg
		return nil, nil
	}

	_, err := c.getConnection(
		map[string]interface{}{
			propUsername:      propUsername,
			propAddress:       testLocalhost,
			propSkipHostCheck: true,
		},
		map[string]interface{}{propPassword: propPassword},
	)
	require.NoError(t, err)
	require.NotNil(t, capturedCfg)

	// With opt-out, the callback must accept any host key (matching the
	// legacy InsecureIgnoreHostKey behavior).
	key := generateTestHostKey(t)
	cbErr := capturedCfg.HostKeyCallback("anything", fakeAddr{s: testWildcardAddr}, key)
	assert.NoError(t, cbErr, "skip_host_check=true must accept any host key")
}
