//go:build integration

// Integration tests that exercise the compiled ssh-probe binary against a real
// SSH server running in a throwaway Docker container.
//
// Run with:
//
//	go test -tags integration ./...
//
// Docker must be available. If it is not, the tests are skipped.
package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testImage    = "lscr.io/linuxserver/openssh-server:latest"
	testUser     = "tester"
	testPassword = "s3cret"
)

var (
	probeBin string // path to the compiled ssh-probe binary
	sshAddr  string // host:port the test server listens on
)

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Println("skipping integration tests: docker not found on PATH")
		os.Exit(0)
	}

	tmp, err := os.MkdirTemp("", "ssh-probe-it")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	probeBin = filepath.Join(tmp, "ssh-probe")
	if out, err := exec.Command("go", "build", "-o", probeBin, ".").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building ssh-probe: %v\n%s", err, out)
		os.Exit(1)
	}

	port := freePort()
	sshAddr = fmt.Sprintf("localhost:%d", port)

	container, err := startServer(port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "starting test server:", err)
		os.Exit(1)
	}

	code := m.Run()

	stopServer(container)
	os.Exit(code)
}

func TestVersion(t *testing.T) {
	out, _, code := runProbe("version", sshAddr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.HasPrefix(out, "SSH-2.0-OpenSSH") {
		t.Errorf("version = %q, want an OpenSSH identification string", strings.TrimSpace(out))
	}
}

func TestVersionAcceptsUserLeader(t *testing.T) {
	out, _, code := runProbe("version", testUser+"@"+sshAddr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.HasPrefix(out, "SSH-") {
		t.Errorf("version = %q, want an SSH identification string", strings.TrimSpace(out))
	}
}

func TestVersionUnreachable(t *testing.T) {
	addr := fmt.Sprintf("localhost:%d", freePort()) // nothing listening here
	_, stderr, code := runProbe("version", addr)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero for an unreachable host")
	}
	if stderr == "" {
		t.Errorf("expected an error message on stderr")
	}
}

func TestAuthMethods(t *testing.T) {
	out, _, code := runProbe("auth-methods", testUser+"@"+sshAddr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	got := strings.Fields(out)
	for _, want := range []string{"publickey", "password"} {
		if !slices.Contains(got, want) {
			t.Errorf("auth-methods = %v, want it to include %q", got, want)
		}
	}
}

func TestSupportsPasswordYes(t *testing.T) {
	out, _, code := runProbe("supports-password", testUser+"@"+sshAddr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.TrimSpace(out) != "yes" {
		t.Errorf("supports-password = %q, want %q", strings.TrimSpace(out), "yes")
	}
}

func TestFirstAuthMethod(t *testing.T) {
	out, _, code := runProbe("first-auth-method", testUser+"@"+sshAddr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(out); got == "" {
		t.Errorf("first-auth-method = %q, want a non-empty method", got)
	}
}

func TestFirstAuthMethodRequiresUser(t *testing.T) {
	_, stderr, code := runProbe("first-auth-method", sshAddr) // no user@ leader
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero when the user is missing")
	}
	if !strings.Contains(stderr, "user@host") {
		t.Errorf("stderr = %q, want it to mention user@host", strings.TrimSpace(stderr))
	}
}

func TestTryPasswordsFindsCorrect(t *testing.T) {
	out, _, code := runProbe("try-passwords", testUser+"@"+sshAddr, "wrong1", "wrong2", testPassword)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(out); got != testPassword {
		t.Errorf("try-passwords = %q, want %q", got, testPassword)
	}
}

func TestTryPasswordsAllWrong(t *testing.T) {
	out, stderr, code := runProbe("try-passwords", testUser+"@"+sshAddr, "nope1", "nope2")
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero when no password is accepted")
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("stdout = %q, want empty when no password is accepted", strings.TrimSpace(out))
	}
	if !strings.Contains(stderr, "none of") {
		t.Errorf("stderr = %q, want it to report that no password was accepted", strings.TrimSpace(stderr))
	}
}

// runProbe runs the compiled binary and returns its stdout, stderr and exit code.
func runProbe(args ...string) (stdout, stderr string, code int) {
	var o, e bytes.Buffer
	cmd := exec.Command(probeBin, args...)
	cmd.Stdout = &o
	cmd.Stderr = &e

	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return o.String(), e.String(), code
}

// freePort returns a currently-free TCP port on the loopback interface.
func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startServer launches the test SSH server, publishing its port on localhost,
// disables rate-limiting so the password-spraying tests are deterministic, sets
// a known password for the test user, and waits until it accepts connections.
// It returns the container name for later teardown.
func startServer(port int) (string, error) {
	name := fmt.Sprintf("ssh-probe-it-%d", port)
	_ = exec.Command("docker", "rm", "-f", name).Run() // remove any stale container

	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-e", "PASSWORD_ACCESS=true",
		"-e", "USER_NAME="+testUser,
		"-e", "USER_PASSWORD="+testPassword,
		"-e", "PUID=1000",
		"-e", "PGID=1000",
		"-p", fmt.Sprintf("127.0.0.1:%d:2222", port),
		testImage,
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker run: %v: %s", err, out)
	}

	if err := setup(name, port); err != nil {
		stopServer(name)
		return "", err
	}
	return name, nil
}

// setup prepares an already-running container for testing.
func setup(container string, port int) error {
	if err := waitForUser(container); err != nil {
		return err
	}

	// OpenSSH 10.x enables PerSourcePenalties by default, which blocks a source
	// IP after accumulated failed authentications. That would make the
	// try-passwords tests (which deliberately fail some attempts) flaky, so turn
	// it off and restart sshd to apply it.
	if out, err := exec.Command("docker", "exec", container, "sh", "-c",
		`echo "PerSourcePenalties no" >> /config/sshd/sshd_config`).CombinedOutput(); err != nil {
		return fmt.Errorf("disabling PerSourcePenalties: %v: %s", err, out)
	}
	if out, err := exec.Command("docker", "restart", container).CombinedOutput(); err != nil {
		return fmt.Errorf("docker restart: %v: %s", err, out)
	}

	// The restart re-runs the container init, which resets the user's password,
	// so wait for the user again and set it deterministically (the image's
	// USER_PASSWORD env var has proved unreliable).
	if err := waitForUser(container); err != nil {
		return err
	}
	if err := setPassword(container); err != nil {
		return err
	}
	return waitReady(port)
}

// waitForUser blocks until the container's init has created the test user.
func waitForUser(container string) error {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if exec.Command("docker", "exec", container, "id", testUser).Run() == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("timed out waiting for user %q to be created", testUser)
}

// setPassword sets the test user's password.
func setPassword(container string) error {
	cmd := exec.Command("docker", "exec", "-i", container, "chpasswd")
	cmd.Stdin = strings.NewReader(testUser + ":" + testPassword)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd: %v: %s", err, out)
	}
	return nil
}

// waitReady polls the server until it answers with an SSH identification string.
func waitReady(port int) error {
	addr := fmt.Sprintf("localhost:%d", port)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			buf := make([]byte, 4)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := conn.Read(buf)
			conn.Close()
			if n >= 4 && string(buf[:4]) == "SSH-" {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("timed out waiting for server on %s", addr)
}

func stopServer(container string) {
	_ = exec.Command("docker", "rm", "-f", container).Run()
}
