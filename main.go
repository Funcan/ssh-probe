package main

import (
	"bufio"
	"errors"
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
  ssh-probe try-passwords <user@host> <password1> [ <password2> ... ]
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
	if len(args) < 2 {
		return fmt.Errorf("usage: ssh-probe try-passwords <user@host> <password1> [ <password2> ... ]")
	}

	user, addr, err := splitUserHost(args[0])
	if err != nil {
		return err
	}
	passwords := args[1:]

	for _, pw := range passwords {
		ok, err := tryPassword(user, addr, pw)
		if err != nil {
			return err
		}
		if ok {
			fmt.Println(pw)
			return nil
		}
	}

	return fmt.Errorf("none of the %d supplied passwords were accepted", len(passwords))
}

// tryPassword attempts password authentication as user against addr. It returns
// (true, nil) on success and (false, nil) when the server rejects the password.
// A network-level failure (so no password can be tried) is returned as an error.
func tryPassword(user, addr, password string) (bool, error) {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return false, err
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshConn, _, _, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		// The TCP connection succeeded, so this is an authentication (or
		// protocol) rejection rather than a network failure: report it as a
		// failed password so the next one is tried.
		return false, nil
	}
	sshConn.Close()
	return true, nil
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
