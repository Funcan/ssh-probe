package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const defaultPort = "22"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "version":
		err = cmdVersion(args)
	case "supports-password":
		err = cmdSupportsPassword(args)
	case "auth-methods":
		err = cmdAuthMethods(args)
	case "first-auth-method":
		err = cmdFirstAuthMethod(args)
	case "try-passwords":
		err = cmdTryPasswords(args)
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "ssh-probe:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ssh-probe - a scriptable SSH client for checking SSH server configuration

Usage:
  ssh-probe version <host>
  ssh-probe supports-password <user@host>
  ssh-probe auth-methods <user@host>
  ssh-probe first-auth-method <user@host>
  ssh-probe try-passwords [--method password|keyboard-interactive] <user@host> <password1> [ <password2> ... ]
`)
}

// cmdVersion reads and prints the server's SSH identification string, which is
// sent in cleartext as the first line of the connection before any handshake.
func cmdVersion(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: ssh-probe version <host>")
	}

	addr := withDefaultPort(stripUser(args[0]))

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading identification string: %w", err)
	}

	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "SSH-") {
		return fmt.Errorf("unexpected identification string: %q", line)
	}

	fmt.Println(line)
	return nil
}

func cmdSupportsPassword(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: ssh-probe supports-password <user@host>")
	}

	user, addr, err := splitUserHost(args[0])
	if err != nil {
		return err
	}

	methods, err := offeredAuthMethods(user, addr)
	if err != nil {
		return err
	}

	if slices.Contains(methods, "password") {
		fmt.Println("yes")
	} else {
		fmt.Println("no")
	}
	return nil
}

// cmdAuthMethods prints every authentication method the server offers, one per
// line, in the server's order.
func cmdAuthMethods(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: ssh-probe auth-methods <user@host>")
	}

	user, addr, err := splitUserHost(args[0])
	if err != nil {
		return err
	}

	methods, err := offeredAuthMethods(user, addr)
	if err != nil {
		return err
	}

	for _, m := range methods {
		fmt.Println(m)
	}
	return nil
}

func cmdFirstAuthMethod(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: ssh-probe first-auth-method <user@host>")
	}

	user, addr, err := splitUserHost(args[0])
	if err != nil {
		return err
	}

	methods, err := offeredAuthMethods(user, addr)
	if err != nil {
		return err
	}
	if len(methods) == 0 {
		return fmt.Errorf("server offered no authentication methods")
	}

	fmt.Println(methods[0])
	return nil
}

func cmdTryPasswords(args []string) error {
	fs := flag.NewFlagSet("try-passwords", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	method := fs.String("method", "password",
		"authentication method to use: password or keyboard-interactive")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr,
			"usage: ssh-probe try-passwords [--method password|keyboard-interactive] <user@host> <password1> [ <password2> ... ]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) < 2 {
		fs.Usage()
		return fmt.Errorf("need a <user@host> and at least one password")
	}

	user, addr, err := splitUserHost(rest[0])
	if err != nil {
		return err
	}
	passwords := rest[1:]

	// Validate the method up front so a typo fails before we connect.
	if _, err := passwordAuth(*method, ""); err != nil {
		return err
	}

	accepted, err := tryPasswords(user, addr, *method, passwords)
	if err != nil {
		return err
	}
	if accepted == "" {
		return fmt.Errorf("none of the %d supplied passwords were accepted", len(passwords))
	}

	fmt.Println(accepted)
	return nil
}

// passwordAuth builds an auth method that submits the given password using the
// named SSH method. "keyboard-interactive" answers every PAM prompt with the
// password, matching what happens when a password is typed at the usual prompt;
// "password" uses the RFC 4252 "password" method directly.
func passwordAuth(method, password string) (ssh.AuthMethod, error) {
	switch method {
	case "keyboard-interactive":
		return ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = password
			}
			return answers, nil
		}), nil
	case "password":
		return ssh.Password(password), nil
	default:
		return nil, fmt.Errorf("unknown --method %q (want password or keyboard-interactive)", method)
	}
}

// tryPasswords tries each password in turn and returns the first the server
// accepts, or "" if none are. Like a normal SSH client typing several passwords
// at the prompt, it submits them over a single connection; if the server closes
// the connection after its per-connection limit before the passwords are
// exhausted, it reconnects and continues with the rest. A network-level failure
// is returned as an error.
func tryPasswords(user, addr, method string, passwords []string) (string, error) {
	remaining := passwords
	for len(remaining) > 0 {
		accepted, tried, err := tryPasswordsOnConn(user, addr, method, remaining)
		if err != nil {
			return "", err
		}
		if accepted != "" {
			return accepted, nil
		}
		if tried == 0 {
			// No password could be attempted (e.g. the server does not offer
			// this method), so reconnecting would not help.
			break
		}
		remaining = remaining[tried:]
	}
	return "", nil
}

// tryPasswordsOnConn opens one connection and submits passwords in order until
// one is accepted, the list is exhausted, or the server closes the connection.
// It returns the accepted password (or "") and how many passwords were actually
// attempted on this connection, so the caller can resume with the rest.
func tryPasswordsOnConn(user, addr, method string, passwords []string) (string, int, error) {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return "", 0, err
	}

	idx := -1 // index of the most recent password handed to the server
	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		AuthCallback: func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			if !slices.Contains(ctx.AllowedMethods, method) {
				return nil, nil // server will not accept this method; give up
			}
			if idx+1 >= len(passwords) {
				return nil, nil // all passwords on this connection exhausted
			}
			idx++
			auth, err := passwordAuth(method, passwords[idx])
			if err != nil {
				return nil, err
			}
			return auth, nil
		},
	}

	sshConn, _, _, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		// The TCP connection succeeded, so this is authentication being
		// rejected (or the server disconnecting us), not a network failure.
		return "", idx + 1, nil
	}
	sshConn.Close()
	if idx < 0 {
		// Authentication succeeded before any password was tried, i.e. the
		// server accepted the "none" method.
		return "", 0, errNoPasswordNeeded
	}
	return passwords[idx], idx + 1, nil
}

// stripUser removes an optional "user@" leader from a target, which commands
// that only need a host accept for convenience.
func stripUser(target string) string {
	if i := strings.LastIndex(target, "@"); i >= 0 {
		return target[i+1:]
	}
	return target
}

// splitUserHost splits a "user@host" target into the username and a dial
// address (with the default port applied when host has no port).
func splitUserHost(target string) (user, addr string, err error) {
	i := strings.LastIndex(target, "@")
	if i < 0 {
		return "", "", fmt.Errorf("expected user@host, got %q", target)
	}
	user = target[:i]
	host := target[i+1:]
	if user == "" || host == "" {
		return "", "", fmt.Errorf("expected user@host, got %q", target)
	}
	return user, withDefaultPort(host), nil
}

// errCaptured aborts the handshake once the server's offered authentication
// methods have been captured.
var errCaptured = errors.New("captured offered authentication methods")

// errNoPasswordNeeded reports that the server authenticated without any
// password, i.e. it accepted the "none" method.
var errNoPasswordNeeded = errors.New(`server authenticated without a password (accepted the "none" method)`)

// offeredAuthMethods connects as user and returns the authentication methods
// the server offers after the initial "none" probe, in the server's order. If
// the server accepts "none" authentication outright, it returns {"none"}.
func offeredAuthMethods(user, addr string) ([]string, error) {
	var methods []string
	var captured bool

	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
		AuthCallback: func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			methods = ctx.AllowedMethods
			captured = true
			return nil, errCaptured
		},
	}

	conn, err := ssh.Dial("tcp", addr, config)
	if err == nil {
		conn.Close()
		return []string{"none"}, nil
	}
	if captured {
		return methods, nil
	}
	return nil, err
}

// withDefaultPort appends the default SSH port if host has no port specified.
func withDefaultPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, defaultPort)
}
