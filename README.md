# Dit SSH Provider

This is a basic Dit SSH provider. For more information on how it works,
consult the dit documentation.

## Remote configuration

The SSH provider accepts the following remote properties:

| Property           | Type          | Required | Description |
|--------------------|---------------|----------|-------------|
| `username`         | string        | yes      | SSH user on the remote host. |
| `address`          | string        | yes      | Hostname or IP of the remote host. |
| `path`             | string        | yes      | Path on the remote host used to store commits. |
| `port`             | int           | no       | SSH port (defaults to 22). |
| `password`         | string        | no       | Password baked into the remote (prefer `parameters.password` for credentials). |
| `keyFile`          | string        | no       | Path to a private-key file on the local host. |
| `known_hosts_file` | string        | no       | Path to a `known_hosts` file used for host-key verification. Defaults to `~/.ssh/known_hosts`. |
| `skip_host_check`  | bool / string | no       | Disable host-key verification. **Default: `false`.** See below. |

### Host-key verification

Starting in `v1.0.0`, the SSH provider verifies the remote host against a
`known_hosts` file by default. Connections to hosts whose keys are not in
`known_hosts` fail with an actionable error that points the operator at
`ssh-keyscan`:

```
host key verification failed for remote.example.com

Host 'remote.example.com' is not in /home/<user>/.ssh/known_hosts (or its key has changed)
To accept the host, run:
    ssh-keyscan -H 'remote.example.com' >> '/home/<user>/.ssh/known_hosts'
Then verify the fingerprint out-of-band before retrying
To skip host-key checking entirely (NOT recommended outside trusted networks), set `skip_host_check: true` on the remote
```

**Before connecting to a new host, populate `known_hosts` and verify the
fingerprint out-of-band:**

```bash
ssh-keyscan -H remote.example.com >> ~/.ssh/known_hosts
ssh-keygen -lf ~/.ssh/known_hosts | grep remote.example.com
# Compare the fingerprint against a trusted source (the host operator,
# a configuration management system, etc.) before proceeding.
```

To override the file location for a single remote, set `known_hosts_file` to
the desired absolute path.

### Opting out (`skip_host_check`)

For deployments where host-key verification is impractical — short-lived CI
runners, trusted private networks, ephemeral test hosts — set
`skip_host_check: true` on the remote. This restores the legacy behavior of
accepting any host key on every connection.

The property accepts either booleans (`true` / `false`) or the case-insensitive
string literals `"true"` / `"false"` so JSON payloads serialized by either
convention work unchanged. Any other value is rejected at `ValidateRemote`
time so a typo like `"yes"` cannot silently disable a security control.

### Migrating from earlier versions

Before `v1.0.0`, the provider unconditionally disabled host-key checking on
every SSH connection. To upgrade without service interruption:

1. **Preferred:** populate `~/.ssh/known_hosts` (or a custom `known_hosts_file`)
   on every machine that runs the d3 CLI against an SSH remote, then upgrade.
   No configuration change required.
2. **Bridge:** add `skip_host_check: true` to existing remotes to preserve the
   old behavior, then incrementally migrate hosts onto `known_hosts` and remove
   the flag.

This change mirrors the policy shipped in the Kotlin provider
([ssh-remote#62](https://github.com/ditdotdev/ssh-remote/pull/62)).

## CI/CD Pipeline

This repository includes a comprehensive Pull Request 2 workflow with:
- Cross-platform testing (Ubuntu, Windows, macOS)
- Multi-version Go support (1.21, 1.22, 1.23)
- Security scanning and code quality checks
- Coverage reporting and performance benchmarks

## Contributing

This project follows the Dit community best practices:

  * [Contributing](https://github.com/ditdotdev/.github/blob/master/CONTRIBUTING.md)
  * [Code of Conduct](https://github.com/ditdotdev/.github/blob/master/CODE_OF_CONDUCT.md)
  * [Community Support](https://github.com/ditdotdev/.github/blob/master/SUPPORT.md)

It is maintained by the [Dit community maintainers](https://github.com/ditdotdev/.github/blob/master/MAINTAINERS.md)

For more information on how it works, and how to build and release new versions,
see the [Development Guidelines](DEVELOPING.md).


## License

This project is licensed under the Business Source License 1.1 (BUSL-1.1).
On the Change Date (four years from the publication of each version), the
license for that version converts to the Mozilla Public License 2.0
(MPL-2.0). See [LICENSE](LICENSE) for the full terms.
