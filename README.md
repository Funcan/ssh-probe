ssh-probe
=========

A scriptable SSH client for checking the configuration of SSH servers.

Usage:

```
ssh-probe version <host>
ssh-probe supports-password <user@host>
ssh-probe auth-methods <user@host>
ssh-probe first-auth-method <user@host>
ssh-probe try-passwords [--method password|keyboard-interactive] <user@host> <password1> [ <password2> ... ]
```

`try-passwords` tries each password in turn and prints the first the server
accepts (exiting non-zero if none are). Like a normal `ssh` client typing
several passwords at the prompt, it submits them over a single connection,
reconnecting to continue only if the server closes the connection after its
per-connection attempt limit.

Its `--method` switch selects how each password is submitted:

* `password` (default) uses the RFC 4252 "password" method, which is what most
  servers complete password authentication with.
* `keyboard-interactive` answers the server's PAM prompts instead, matching
  servers that drive password entry through keyboard-interactive challenges.

Note that these are different authentication methods on the wire, so a server
may accept one and not the other.

Commands that take a `<user@host>` need the username to drive the
authentication exchange. Commands that take only a `<host>` also accept a
`user@` leader for convenience and ignore it. A `host` may include a port as
`host:port`; otherwise port 22 is assumed.

Note that many SSH servers rate-limit repeated failed authentications from a
single source (for example OpenSSH's `PerSourcePenalties`), which can affect
`try-passwords` against a live server.

## Building and testing

A `Makefile` provides the common tasks:

```
make build             # build the ssh-probe binary
make test              # run unit tests
make integration-test  # run integration tests (requires Docker)
make format            # format the code with gofmt
make lint              # gofmt check + go vet
make clean             # remove build artifacts
```

The integration tests start a throwaway SSH server in a Docker container and
run the compiled tool against it, so Docker must be available. They are guarded
by a build tag and run only via `make integration-test` (or
`go test -tags integration ./...`); if Docker is not present they are skipped.

