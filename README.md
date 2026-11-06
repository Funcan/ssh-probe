ssh-probe
=========

A scriptable SSH client for checking the configuration of SSH servers.

Usage:

```
ssh-probe version <host>
ssh-probe supports-password <user@host>
ssh-probe auth-methods <user@host>
ssh-probe first-auth-method <user@host>
ssh-probe try-passwords <user@host> <password1> [ <password2> ... ]
```

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

