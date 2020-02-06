/*
 * Copyright The Titan Project Contributors.
 */
package ssh

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/titan-data/remote-sdk-go/remote"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"
)

type sshRemote struct {
}

func (s sshRemote) Type() (string, error) {
	return "ssh", nil
}

func (s sshRemote) FromURL(rawUrl string, additionalProperties map[string]string) (map[string]interface{}, error) {
	url, err := url.Parse(rawUrl)
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

	keyFile := additionalProperties["keyFile"]
	password, passwordSet := url.User.Password()
	if keyFile != "" && passwordSet {
		return nil, errors.New("both remote password and key file cannot be specified")
	}

	for k := range additionalProperties {
		if k != "keyFile" {
			return nil, errors.New(fmt.Sprintf("invalid rmeote property '%s'", k))
		}
	}

	result := map[string]interface{}{
		"username": url.User.Username(),
		"address":  url.Hostname(),
		"path":     path,
	}

	if password != "" {
		result["password"] = password
	}
	if url.Port() != "" {
		port, err := strconv.Atoi(url.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port '%s': %w", url.Port(), err)
		}
		result["port"] = port
	}
	if keyFile != "" {
		result["keyFile"] = keyFile
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
	u := fmt.Sprintf("ssh://%s", properties["username"])
	if properties["password"] != nil {
		u += ":*****"
	}
	u += fmt.Sprintf("@%s", properties["address"])
	if port, ok := properties["port"]; ok {
		portval, err := getPort(port)
		if err != nil {
			return "", nil, err
		}
		u += fmt.Sprintf(":%d", portval)
	}
	if properties["path"].(string)[0:1] != "/" {
		u += "/~/"
	}
	u += properties["path"].(string)

	retProps := map[string]string{}
	if properties["keyFile"] != nil {
		retProps["keyFile"] = properties["keyFile"].(string)
	}

	return u, retProps, nil
}

var readPassword = terminal.ReadPassword
var fmtPrintf = fmt.Printf

func (s sshRemote) GetParameters(remoteProperties map[string]interface{}) (map[string]interface{}, error) {
	result := map[string]interface{}{}

	if remoteProperties["keyFile"] != nil {
		content, err := ioutil.ReadFile(remoteProperties["keyFile"].(string))
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", remoteProperties["keyFile"], err)
		}
		result["key"] = string(content)
	}

	if remoteProperties["password"] == nil && remoteProperties["keyFile"] == nil {
		fmtPrintf("password: ")
		pw, err := readPassword(0)
		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
		result["password"] = string(pw)
	}

	return result, nil
}

func (s sshRemote) ValidateRemote(properties map[string]interface{}) error {
	err := remote.ValidateFields(properties, []string{"username", "address", "path"}, []string{"password", "port", "keyFile"})
	if err != nil {
		return err
	}
	if port, ok := properties["port"]; ok {
		_, err := getPort(port)
		return err
	}
	return nil
}

func (s sshRemote) ValidateParameters(parameters map[string]interface{}) error {
	return remote.ValidateFields(parameters, []string{}, []string{"password", "key"})
}

/*
 * This method will parse the remote configuration and parameters to determine if we should use password
 * authentication or key-based authentication. It returns a pair where exactly one element must be set, either
 * the first (password) or second (key).
 */
func getAuth(properties map[string]interface{}, parameters map[string]interface{}) (string, string, error) {
	paramsPassword, paramsPasswordOk := parameters["password"]
	paramsKey, paramsKeyOk := parameters["key"]
	remotePassword, remotePasswordOk := properties["password"]
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
		User:            properties["username"].(string),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

	return dial("tcp", properties["address"].(string), config)
}

func runCommand(conn *ssh.Client, command string) ([]byte, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	output, err := sess.CombinedOutput(command)
	if err != nil {
		return nil, fmt.Errorf("failed to execute '%s': %w\n%s", command, err, string(output))
	}
	return output, nil
}

var run = runCommand

func readCommit(conn *ssh.Client, properties map[string]interface{}, commitId string) (*remote.Commit, error) {
	output, err := run(conn, fmt.Sprintf("cat \"%s/%s/metadata.json\"", properties["path"], commitId))
	if err != nil {
		return nil, err
	}

	commit := map[string]interface{}{}
	err = json.Unmarshal(output, &commit)
	if err != nil {
		return nil, err
	}

	return &remote.Commit{Id: commitId, Properties: commit}, nil
}

func (s sshRemote) ListCommits(properties map[string]interface{}, parameters map[string]interface{}, tags []remote.Tag) ([]remote.Commit, error) {
	conn, err := getConnection(properties, parameters)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	output, err := run(conn, fmt.Sprintf("ls -1 \"%s\"", properties["path"]))
	if err != nil {
		return nil, err
	}

	var ret []remote.Commit
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		commitId := strings.TrimSpace(scanner.Text())
		commit, err := readCommit(conn, properties, commitId)
		if err == nil && remote.MatchTags(commit.Properties, tags) {
			ret = append(ret, remote.Commit{Id: commit.Id, Properties: commit.Properties})
		}
	}

	remote.SortCommits(ret)

	return ret, nil
}

func (s sshRemote) GetCommit(properties map[string]interface{}, parameters map[string]interface{}, commitId string) (*remote.Commit, error) {
	conn, err := getConnection(properties, parameters)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return readCommit(conn, properties, commitId)
}

func init() {
	remote.Register(sshRemote{})
}
