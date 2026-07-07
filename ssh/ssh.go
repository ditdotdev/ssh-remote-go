// Copyright Dit 2026
// SPDX-License-Identifier: BUSL-1.1

// Package ssh provides SSH remote backend functionality for Dit data storage.
package ssh

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/ditdotdev/remote-sdk-go/remote"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// commitIDPattern restricts commit identifiers to characters that are safe to
// interpolate into a remote shell command. Anything else risks command injection
// through the unquoted `commitID` argument used in `cat "<path>/<id>/..."`.
var commitIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// validateCommitID returns an error if the supplied commit ID contains any
// character outside the allowlist defined by commitIDPattern. The check guards
// against attackers who control the remote filesystem (or MITM the SSH
// connection) injecting shell metacharacters via crafted directory names.
func validateCommitID(commitID string) error {
	if commitID == "" {
		return errors.New("commitID is required")
	}

	if !commitIDPattern.MatchString(commitID) {
		return fmt.Errorf("invalid commitID %q: must match %s", commitID, commitIDPattern)
	}

	return nil
}

// stringOrError extracts a string-typed map entry safely. ValidateRemote should
// guarantee the type at the SDK boundary, but the type system gives no
// compile-time enforcement, so any unchecked `.(string)` would panic on
// misconfigured callers. Callers should propagate the returned error.
func stringOrError(m map[string]interface{}, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("missing key %q", key)
	}

	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("key %q: expected string, got %T", key, v)
	}

	return s, nil
}

const (
	propKeyFile  = "keyFile"
	propUsername = "username"
	propAddress  = "address"
	propPath     = "path"
	propPort     = "port"
	propPassword = "password"
	propKey      = "key"
	// camelCase to match the rest of the ecosystem (keyFile above, the Kotlin
	// ssh-remote server, and the CLI). These properties are stored on the
	// remote by the server, so the names must agree across the Go/Kotlin
	// boundary or the opt-out is silently ignored.
	propKnownHostsFile = "knownHostsFile"
	propSkipHostCheck  = "skipHostCheck"
)

// sshClient is the SSH remote provider with all its side-effecting collaborators
// (network dial, SSH command execution, password prompt I/O, error reporting)
// injected as function values. Tests construct an sshClient with their own
// mocks; production code uses newSSHClient() which wires the real
// implementations. This replaces the package-level mutable vars
// (`dial`, `run`, `readPassword`, `fmtPrintf`, `fmtFprintf`) the legacy test
// suite used for mocking — those were incompatible with t.Parallel() and -race.
type sshClient struct {
	// dial opens a TCP+SSH connection. Defaults to ssh.Dial.
	dial func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error)
	// run executes a single command over an established SSH connection.
	// Defaults to runCommand.
	run func(conn *ssh.Client, command string) ([]byte, error)
	// readPassword reads a password from a terminal fd without echoing.
	// Defaults to term.ReadPassword.
	readPassword func(fd int) ([]byte, error)
	// fmtPrintf writes a prompt to stdout. Defaults to fmt.Printf.
	fmtPrintf func(format string, a ...interface{}) (int, error)
	// fmtFprintf is used to surface per-entry ListCommits errors on stderr.
	// Defaults to fmt.Fprintf.
	fmtFprintf func(w io.Writer, format string, a ...interface{}) (int, error)
}

// newSSHClient returns an sshClient wired with production defaults.
func newSSHClient() *sshClient {
	return &sshClient{
		dial:         ssh.Dial,
		run:          runCommand,
		readPassword: term.ReadPassword,
		fmtPrintf:    fmt.Printf,
		fmtFprintf:   fmt.Fprintf,
	}
}

func (s *sshClient) Type() (string, error) {
	return "ssh", nil
}

func (s *sshClient) FromURL(rawURL string, additionalProperties map[string]string) (map[string]interface{}, error) {
	url, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	if url.Scheme != "ssh" {
		return nil, errors.New("invalid remote scheme")
	}

	if url.Path == "" {
		return nil, errors.New("missing remote path")
	}

	if url.Hostname() == "" {
		return nil, errors.New("missing remote host")
	}

	if url.User == nil || url.User.Username() == "" {
		return nil, errors.New("missing remote username")
	}

	path := url.Path
	if strings.Index(path, "/~/") == 0 {
		path = path[3:]
	}

	keyFile := additionalProperties[propKeyFile]

	password, passwordSet := url.User.Password()
	if keyFile != "" && passwordSet {
		return nil, errors.New("both remote password and key file cannot be specified")
	}

	for k := range additionalProperties {
		switch k {
		case propKeyFile, propSkipHostCheck, propKnownHostsFile:
			// allowed
		default:
			return nil, fmt.Errorf("invalid remote property '%s'", k)
		}
	}

	result := map[string]interface{}{
		propUsername: url.User.Username(),
		propAddress:  url.Hostname(),
		propPath:     path,
	}

	if password != "" {
		result[propPassword] = password
	}

	if url.Port() != "" {
		port, err := strconv.Atoi(url.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port '%s': %w", url.Port(), err)
		}

		result[propPort] = port
	}

	if keyFile != "" {
		result[propKeyFile] = keyFile
	}

	// Forward host-key options to the server, which stores them on the remote
	// and honors them on push/pull. Values stay as supplied (e.g. the string
	// "true"); validateRemote/the server coerce skipHostCheck to a Boolean.
	if v, ok := additionalProperties[propSkipHostCheck]; ok {
		result[propSkipHostCheck] = v
	}

	if v, ok := additionalProperties[propKnownHostsFile]; ok {
		result[propKnownHostsFile] = v
	}

	return result, nil
}

func getPort(port interface{}) (int, error) {
	portval := 0

	if p, ok := port.(int); ok {
		portval = p
	}

	if p, ok := port.(float32); ok {
		portval = int(p)
	}

	if p, ok := port.(float64); ok {
		portval = int(p)
	}

	if portval <= 0 || portval > 65535 {
		return 0, errors.New("invalid port")
	}

	return portval, nil
}

func (s *sshClient) ToURL(properties map[string]interface{}) (string, map[string]string, error) {
	u := fmt.Sprintf("ssh://%s", properties[propUsername])
	if properties[propPassword] != nil {
		u += ":*****"
	}

	u += fmt.Sprintf("@%s", properties[propAddress])
	if port, ok := properties[propPort]; ok {
		portval, err := getPort(port)
		if err != nil {
			return "", nil, err
		}

		u += fmt.Sprintf(":%d", portval)
	}

	path, err := stringOrError(properties, propPath)
	if err != nil {
		return "", nil, err
	}

	if !strings.HasPrefix(path, "/") {
		u += "/~/"
	}

	u += path

	retProps := map[string]string{}
	if properties[propKeyFile] != nil {
		keyFile, err := stringOrError(properties, propKeyFile)
		if err != nil {
			return "", nil, err
		}

		retProps[propKeyFile] = keyFile
	}

	return u, retProps, nil
}

func (s *sshClient) GetParameters(remoteProperties map[string]interface{}) (map[string]interface{}, error) {
	result := map[string]interface{}{}

	if remoteProperties[propKeyFile] != nil {
		keyFile, err := stringOrError(remoteProperties, propKeyFile)
		if err != nil {
			return nil, err
		}

		content, err := os.ReadFile(keyFile) // #nosec G304 -- keyFile is supplied as a remote property by the operator and validated as a string above.
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", keyFile, err)
		}

		result[propKey] = string(content)
	}

	if remoteProperties[propPassword] == nil && remoteProperties[propKeyFile] == nil {
		_, _ = s.fmtPrintf("password: ")

		pw, err := s.readPassword(0)
		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}

		result[propPassword] = string(pw)
	}

	return result, nil
}

func (s *sshClient) ValidateRemote(properties map[string]interface{}) error {
	err := remote.ValidateFields(
		properties,
		[]string{propUsername, propAddress, propPath},
		[]string{propPassword, propPort, propKeyFile, propKnownHostsFile, propSkipHostCheck},
	)
	if err != nil {
		return err
	}

	if port, ok := properties[propPort]; ok {
		if _, err := getPort(port); err != nil {
			return err
		}
	}

	if v, ok := properties[propSkipHostCheck]; ok {
		if _, err := coerceBoolean(propSkipHostCheck, v); err != nil {
			return err
		}
	}

	if v, ok := properties[propKnownHostsFile]; ok {
		if _, err := coerceString(propKnownHostsFile, v); err != nil {
			return err
		}
	}

	return nil
}

func (s *sshClient) ValidateParameters(parameters map[string]interface{}) error {
	return remote.ValidateFields(parameters, []string{}, []string{propPassword, propKey})
}

/*
 * This method will parse the remote configuration and parameters to determine if we should use password
 * authentication or key-based authentication. It returns a pair where exactly one element must be set, either
 * the first (password) or second (key).
 */
func getAuth(properties map[string]interface{}, parameters map[string]interface{}) (string, string, error) {
	paramsPassword, paramsPasswordOk := parameters[propPassword]
	paramsKey, paramsKeyOk := parameters[propKey]
	remotePassword, remotePasswordOk := properties[propPassword]

	if paramsPasswordOk && paramsKeyOk {
		return "", "", errors.New("only one of password or key can be specified")
	}

	if paramsKeyOk {
		return "", paramsKey.(string), nil
	}

	if paramsPasswordOk {
		return paramsPassword.(string), "", nil
	}

	if remotePasswordOk {
		return remotePassword.(string), "", nil
	}

	return "", "", errors.New("one of password or key must be specified")
}

const (
	boolTrue  = "true"
	boolFalse = "false"
)

// coerceBoolean turns a JSON-deserialized value into a bool. Map[string]any
// payloads can carry either a real bool (most parsers) or the literal strings
// "true"/"false" (some serializers). Anything else is rejected so a typo like
// "yes" cannot silently disable a security control.
func coerceBoolean(name string, v interface{}) (bool, error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	case string:
		switch strings.ToLower(t) {
		case boolTrue:
			return true, nil
		case boolFalse:
			return false, nil
		default:
			return false, fmt.Errorf("'%s' must be a boolean (true/false), got %q", name, t)
		}
	default:
		return false, fmt.Errorf("'%s' must be a boolean, got %T", name, v)
	}
}

// defaultKnownHostsFile returns the OpenSSH default location for the
// known_hosts file. Resolving the path at call time (not package init) lets
// tests that override HOME continue to work.
func defaultKnownHostsFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// Fall back to a literal that will fail open-for-read with a clear
		// message in the rejection path.
		home = "~"
	}

	return filepath.Join(home, ".ssh", "known_hosts")
}

// buildHostKeyCallback resolves the host-key verification policy for a given
// remote. The default is to verify against a known_hosts file (OpenSSH default
// or the path supplied via propKnownHostsFile); the opt-out via
// propSkipHostCheck preserves the legacy InsecureIgnoreHostKey behavior for
// deployments on trusted networks where TOFU is acceptable.
func buildHostKeyCallback(properties map[string]interface{}) (ssh.HostKeyCallback, error) {
	if raw, ok := properties[propSkipHostCheck]; ok {
		skip, err := coerceBoolean(propSkipHostCheck, raw)
		if err != nil {
			return nil, err
		}

		if skip {
			// #nosec G106 -- explicit opt-out; documented escape hatch.
			return ssh.InsecureIgnoreHostKey(), nil
		}
	}

	knownHostsPath := defaultKnownHostsFile()
	if raw, ok := properties[propKnownHostsFile]; ok {
		s, err := coerceString(propKnownHostsFile, raw)
		if err != nil {
			return nil, err
		}

		knownHostsPath = s
	}

	addr, _ := properties[propAddress].(string)

	return func(hostname string, remoteAddr net.Addr, key ssh.PublicKey) error {
		cb, err := knownhosts.New(knownHostsPath)
		if err != nil {
			// A missing file is treated as "empty known_hosts": the host is
			// unknown, so reject with the actionable guidance below.
			if os.IsNotExist(err) {
				return formatHostKeyError(addr, hostname, knownHostsPath, fmt.Errorf("known_hosts file %q not found", knownHostsPath))
			}

			return formatHostKeyError(addr, hostname, knownHostsPath, err)
		}

		if cbErr := cb(hostname, remoteAddr, key); cbErr != nil {
			return formatHostKeyError(addr, hostname, knownHostsPath, cbErr)
		}

		return nil
	}, nil
}

// coerceString is a typed-getter helper used at config parse time. The SDK's
// ValidateFields only enforces key presence; we enforce string type here so a
// bad caller sees a clean error instead of a runtime panic.
func coerceString(name string, v interface{}) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string, got %T", name, v)
	}

	return s, nil
}

// formatHostKeyError wraps the underlying verification failure in a message
// that tells the operator exactly how to recover (ssh-keyscan command, the
// known_hosts path) and how to opt out for trusted networks.
func formatHostKeyError(configuredAddr, hostname, knownHostsPath string, underlying error) error {
	displayHost := configuredAddr
	if displayHost == "" {
		displayHost = hostname
	}

	guidance := fmt.Sprintf(
		"host key verification failed for %s\n\n"+
			"Host '%s' is not in %s (or its key has changed)\n"+
			"To accept the host, run:\n"+
			"    ssh-keyscan -H '%s' >> '%s'\n"+
			"Then verify the fingerprint out-of-band before retrying\n"+
			"To skip host-key checking entirely (NOT recommended outside trusted networks), set `%s: true` on the remote",
		displayHost, displayHost, knownHostsPath, displayHost, knownHostsPath, propSkipHostCheck,
	)

	return fmt.Errorf("%s: %w", guidance, underlying)
}

func (s *sshClient) getConnection(properties map[string]interface{}, parameters map[string]interface{}) (*ssh.Client, error) {
	password, key, err := getAuth(properties, parameters)
	if err != nil {
		return nil, err
	}

	hostKeyCallback, err := buildHostKeyCallback(properties)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:            properties[propUsername].(string),
		HostKeyCallback: hostKeyCallback,
	}

	if key != "" {
		parsed, err := ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, err
		}

		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(parsed)}
	} else {
		config.Auth = []ssh.AuthMethod{ssh.Password(password)}
	}

	return s.dial("tcp", properties[propAddress].(string), config)
}

func runCommand(conn *ssh.Client, command string) ([]byte, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return nil, err
	}

	defer func() { _ = sess.Close() }()

	output, err := sess.CombinedOutput(command)
	if err != nil {
		return nil, fmt.Errorf("failed to execute '%s': %w\n%s", command, err, string(output))
	}

	return output, nil
}

func (s *sshClient) readCommit(conn *ssh.Client, properties map[string]interface{}, commitID string) (*remote.Commit, error) {
	if err := validateCommitID(commitID); err != nil {
		return nil, err
	}

	output, err := s.run(conn, fmt.Sprintf("cat \"%s/%s/metadata.json\"", properties[propPath], commitID))
	if err != nil {
		return nil, err
	}

	commit := map[string]interface{}{}

	err = json.Unmarshal(output, &commit)
	if err != nil {
		return nil, err
	}

	return &remote.Commit{ID: commitID, Properties: commit}, nil
}

func (s *sshClient) ListCommits(properties map[string]interface{}, parameters map[string]interface{}, tags []remote.Tag) ([]remote.Commit, error) {
	conn, err := s.getConnection(properties, parameters)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	output, err := s.run(conn, fmt.Sprintf("ls -1 \"%s\"", properties[propPath]))
	if err != nil {
		return nil, err
	}

	var ret []remote.Commit

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		commitID := strings.TrimSpace(scanner.Text())
		if commitID == "" {
			continue
		}

		commit, err := s.readCommit(conn, properties, commitID)
		if err != nil {
			// A single bad entry shouldn't abort the listing (the directory may
			// contain unrelated files), but the failure shouldn't be silent
			// either — surface it via stderr so operators can investigate.
			_, _ = s.fmtFprintf(os.Stderr, "ssh remote: skipping commit %q: %v\n", commitID, err)
			continue
		}

		if remote.MatchTags(commit.Properties, tags) {
			ret = append(ret, remote.Commit{ID: commit.ID, Properties: commit.Properties})
		}
	}

	remote.SortCommits(ret)

	return ret, nil
}

func (s *sshClient) GetCommit(properties map[string]interface{}, parameters map[string]interface{}, commitID string) (*remote.Commit, error) {
	conn, err := s.getConnection(properties, parameters)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	return s.readCommit(conn, properties, commitID)
}

func init() {
	remote.Register(newSSHClient())
}
