# Project Development

For general information about contributing changes, see the
[Contributor Guidelines](https://github.com/datadatdat/.github/blob/master/CONTRIBUTING.md).

## How it Works

The provider uses the Datadatdat `remote-sdk-go` to provide interfaces for
Datadatdat to use.

## Building

Run `go build -v ./...`.

## Testing

Run `go test -v ./...` for the hermetic unit suite.

### Integration tests

`runCommand` issues a real SSH session, so it cannot be exercised by the unit
suite (which mocks the `run` shim). Files tagged `//go:build integration` cover
the function against a live sshd.

Start the test server, run the suite, then clean up:

```bash
docker run -d --rm --name ssh-remote-go-itest -p 12200:22 \
    datadatdat/ssh-test-server:latest
go test -tags=integration ./ssh/
docker rm -f ssh-remote-go-itest
```

Override `SSH_TEST_HOST`, `SSH_TEST_PORT`, `SSH_TEST_USER`, or
`SSH_TEST_PASSWORD` to target a different sshd. Defaults are
`127.0.0.1:12200` with `root` / `root`.

## Releasing

Push a tag of the form `v<X>.<Y>.<Z>`, and publish the draft release in GitHub.
