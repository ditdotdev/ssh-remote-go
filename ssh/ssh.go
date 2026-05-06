/*
 * Copyright Datadatdat.
 */

// Package ssh provides SSH remote backend functionality for Datadatdat data storage.
package ssh

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/datadatdat/remote-sdk-go/remote"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	propKeyFile  = "keyFile"
	propUsername = "username"
	propAddress  = "address"
	propPath     = "path"
	propPort     = "port"
	propPassword = "password"
	propKey      = "key"
)

type sshRemote struct {
}

func (s sshRemote) Type() (string, error) {
	return "ssh", nil
}

func (s sshRemote) FromURL(rawURL string, additionalProperties map[string]string) (map[string]interface{}, error) {
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
		if k != propKeyFile {
			return nil, fmt.Errorf("invalid rmeote property '%s'", k)
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

func (s sshRemote) ToURL(properties map[string]interface{}) (string, map[string]string, error) {
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

	if properties[propPath].(string)[0:1] != "/" {
		u += "/~/"
	}

	u += properties[propPath].(string)

	retProps := map[string]string{}
	if properties[propKeyFile] != nil {
		retProps[propKeyFile] = properties[propKeyFile].(string)
	}

	return u, retProps, nil
}

var readPassword = term.ReadPassword
var fmtPrintf = fmt.Printf

func (s sshRemote) GetParameters(remoteProperties map[string]interface{}) (map[string]interface{}, error) {
	result := map[string]interface{}{}

	if remoteProperties[propKeyFile] != nil {
		content, err := os.ReadFile(remoteProperties[propKeyFile].(string))
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", remoteProperties[propKeyFile], err)
		}

		result[propKey] = string(content)
	}

	if remoteProperties[propPassword] == nil && remoteProperties[propKeyFile] == nil {
		_, _ = fmtPrintf("password: ")

		pw, err := readPassword(0)
		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}

		result[propPassword] = string(pw)
	}

	return result, nil
}

func (s sshRemote) ValidateRemote(properties map[string]interface{}) error {
	err := remote.ValidateFields(properties, []string{propUsername, propAddress, propPath}, []string{propPassword, propPort, propKeyFile})
	if err != nil {
		return err
	}

	if port, ok := properties[propPort]; ok {
		_, err := getPort(port)
		return err
	}

	return nil
}

func (s sshRemote) ValidateParameters(parameters map[string]interface{}) error {
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

var dial = ssh.Dial

func getConnection(properties map[string]interface{}, parameters map[string]interface{}) (*ssh.Client, error) {
	password, key, err := getAuth(properties, parameters)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:            properties[propUsername].(string),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- Intentional for testing
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

	return dial("tcp", properties[propAddress].(string), config)
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

var run = runCommand

func readCommit(conn *ssh.Client, properties map[string]interface{}, commitID string) (*remote.Commit, error) {
	output, err := run(conn, fmt.Sprintf("cat \"%s/%s/metadata.json\"", properties[propPath], commitID))
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

func (s sshRemote) ListCommits(properties map[string]interface{}, parameters map[string]interface{}, tags []remote.Tag) ([]remote.Commit, error) {
	conn, err := getConnection(properties, parameters)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	output, err := run(conn, fmt.Sprintf("ls -1 \"%s\"", properties[propPath]))
	if err != nil {
		return nil, err
	}

	var ret []remote.Commit

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		commitID := strings.TrimSpace(scanner.Text())

		commit, err := readCommit(conn, properties, commitID)
		if err == nil && remote.MatchTags(commit.Properties, tags) {
			ret = append(ret, remote.Commit{ID: commit.ID, Properties: commit.Properties})
		}
	}

	remote.SortCommits(ret)

	return ret, nil
}

func (s sshRemote) GetCommit(properties map[string]interface{}, parameters map[string]interface{}, commitID string) (*remote.Commit, error) {
	conn, err := getConnection(properties, parameters)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	return readCommit(conn, properties, commitID)
}

func init() {
	remote.Register(sshRemote{})
}
