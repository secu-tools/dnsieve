// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build smoke

package smoke_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// Stable labels used for the two service smoke instances.  Short, lowercase,
// and alphanumeric so they are safe as service identifiers on all platforms.
// They are distinct from any typical user installation name so CI runs cannot
// conflict with a real service.
const (
	serviceLabel1 = "svcsmoke1"
	serviceLabel2 = "svcsmoke2"
)

// svcName returns the expected OS-level service identifier for a label,
// matching ServiceConfig.ServiceName() in internal/service.
func svcName(label string) string {
	return "dnsieve_" + label
}

// checkServicePrivileges skips the calling test if the process lacks the
// elevated privileges needed to install system services on the current
// platform.  Returns true when the test may proceed.
//
// Platform requirements:
//   - Linux: systemd must be running and the process must be root or have
//     passwordless sudo access (sudo -n).
//   - macOS: root or passwordless sudo access required.
//   - Windows: the process must already be running as Administrator (which
//     is the default on GitHub Actions Windows runners).
func checkServicePrivileges(t *testing.T) bool {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		if _, err := os.Stat("/run/systemd/system"); err != nil {
			t.Skip("service tests require systemd: /run/systemd/system not present")
			return false
		}
		if os.Getuid() != 0 {
			if out, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
				t.Skipf("service tests require root or passwordless sudo: %s", strings.TrimSpace(string(out)))
				return false
			}
		}
		return true
	case "windows":
		// GitHub Actions Windows runners execute as Administrator.
		// Locally, skip if the process is not elevated.  "net session" is a
		// well-known Administrator-only command that exits non-zero when
		// invoked from a standard (non-elevated) user context.
		if err := exec.Command("net.exe", "session").Run(); err != nil {
			t.Skip("service tests on Windows require Administrator privileges")
			return false
		}
		return true
	case "darwin":
		if os.Getuid() != 0 {
			if out, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
				t.Skipf("service tests require root or passwordless sudo: %s", strings.TrimSpace(string(out)))
				return false
			}
		}
		return true
	default:
		t.Skipf("service tests not supported on %s", runtime.GOOS)
		return false
	}
}

// elevatedCmd returns an *exec.Cmd that runs name with elevated privileges.
// On Windows the runner is already Administrator so no wrapper is needed.
// On Unix it wraps the invocation with "sudo -n" (non-interactive); if sudo
// requires a password the command will fail, which checkServicePrivileges
// would have caught before we reach this point.
func elevatedCmd(name string, args ...string) *exec.Cmd {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		return exec.Command(name, args...)
	}
	return exec.Command("sudo", append([]string{"-n", name}, args...)...)
}

// runInstall runs "dnsieve --install --cfgfile cfgPath [--logdir logDir]" and
// answers the interactive label prompt with the given label.
// logDir may be empty, in which case --logdir is omitted and the service uses
// its platform default log directory.
func runInstall(t *testing.T, cfgPath, logDir, label string) ([]byte, error) {
	t.Helper()
	args := []string{"--install", "--cfgfile", cfgPath}
	if logDir != "" {
		args = append(args, "--logdir", logDir)
	}
	cmd := elevatedCmd(dnsieveBinary, args...)
	cmd.Stdin = strings.NewReader(label + "\n")
	return cmd.CombinedOutput()
}

// logJournalctl captures the systemd journal for a service unit and logs it
// via t.Logf.  Called after a failed install to aid diagnosis.  Best-effort:
// if journalctl is unavailable or returns an error the call is silently
// skipped.
func logJournalctl(t *testing.T, label string) {
	t.Helper()
	out, err := elevatedCmd("journalctl", "-xeu", svcName(label)+".service",
		"--no-pager", "-n", "60").CombinedOutput()
	if err == nil && len(out) > 0 {
		t.Logf("journalctl -xeu %s:\n%s", svcName(label)+".service", strings.TrimSpace(string(out)))
	}
}

// removeService is a best-effort cleanup helper that uninstalls the named
// DNSieve service directly via platform commands, bypassing the interactive
// --uninstall prompt.  It logs but never fails the test.
func removeService(t *testing.T, label string) {
	t.Helper()
	name := svcName(label)
	switch runtime.GOOS {
	case "linux":
		for _, args := range [][]string{
			{"systemctl", "stop", name},
			{"systemctl", "disable", name},
			{"rm", "-f", "/etc/systemd/system/" + name + ".service"},
			{"systemctl", "daemon-reload"},
		} {
			if out, err := elevatedCmd(args[0], args[1:]...).CombinedOutput(); err != nil {
				t.Logf("removeService %v: %v -- %s", args, err, strings.TrimSpace(string(out)))
			}
		}
	case "windows":
		for _, args := range [][]string{
			{"sc.exe", "stop", name},
			{"sc.exe", "delete", name},
		} {
			if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
				t.Logf("removeService %v: %v -- %s", args, err, strings.TrimSpace(string(out)))
			}
		}
	case "darwin":
		plist := "/Library/LaunchDaemons/com.dnsieve." + name + ".plist"
		for _, args := range [][]string{
			{"launchctl", "unload", plist},
			{"rm", "-f", plist},
		} {
			if out, err := elevatedCmd(args[0], args[1:]...).CombinedOutput(); err != nil {
				t.Logf("removeService %v: %v -- %s", args, err, strings.TrimSpace(string(out)))
			}
		}
	}
}

// TestSmoke_ServiceInstall_DefaultConfig installs DNSieve as a platform
// service using a minimal configuration and verifies that the service
// starts correctly and can resolve DNS queries.
//
// The test is skipped automatically when elevated privileges are not
// available (non-root without passwordless sudo on Linux/macOS, or a
// non-Administrator process on Windows).
func TestSmoke_ServiceInstall_DefaultConfig(t *testing.T) {
	if !checkServicePrivileges(t) {
		return
	}

	// Pre-emptive removal of any stale instance from a previous test run.
	removeService(t, serviceLabel1)
	t.Cleanup(func() { removeService(t, serviceLabel1) })

	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		t.Fatalf("create log dir %s: %v", logDir, err)
	}
	t.Logf("config: %s, logdir: %s, port: %d", cfgPath, logDir, port)

	out, err := runInstall(t, cfgPath, logDir, serviceLabel1)
	t.Logf("install output:\n%s", strings.TrimSpace(string(out)))
	if err != nil {
		logJournalctl(t, serviceLabel1)
		t.Fatalf("service install failed: %v", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if !waitForPort(t, "tcp", addr, 30*time.Second) {
		logJournalctl(t, serviceLabel1)
		t.Fatalf("service %s did not start on %s within 30s", svcName(serviceLabel1), addr)
	}
	t.Logf("service %s is listening on %s", svcName(serviceLabel1), addr)

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DNS via service %s: rcode=%s, want NOERROR",
			svcName(serviceLabel1), dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("DNS via service %s: NOERROR but no answer records", svcName(serviceLabel1))
	}
	t.Logf("service %s resolved example.com A: %d answer(s)", svcName(serviceLabel1), len(resp.Answer))
}

// TestSmoke_ServiceInstall_CustomLabelAndConfig installs a second DNSieve
// service instance with a distinct label and a config file stored in a
// dedicated subdirectory.  This simulates a multi-instance deployment where
// each instance uses a separate configuration directory.
//
// The test verifies that the instance starts independently of the first
// service and can resolve DNS queries through its own upstream connections.
func TestSmoke_ServiceInstall_CustomLabelAndConfig(t *testing.T) {
	if !checkServicePrivileges(t) {
		return
	}

	removeService(t, serviceLabel2)
	t.Cleanup(func() { removeService(t, serviceLabel2) })

	base := smokeTempDir(t)
	cfgDir := filepath.Join(base, "custom_cfg")
	logDir := filepath.Join(base, "custom_logs")
	for _, d := range []string{cfgDir, logDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("create dir %s: %v", d, err)
		}
	}

	port := findFreePort(t)
	cfgPath := writeConfig(t, cfgDir, minimalConfig(port))
	t.Logf("custom config dir: %s, logdir: %s, port: %d", cfgDir, logDir, port)

	out, err := runInstall(t, cfgPath, logDir, serviceLabel2)
	t.Logf("install output:\n%s", strings.TrimSpace(string(out)))
	if err != nil {
		logJournalctl(t, serviceLabel2)
		t.Fatalf("service install (label=%s) failed: %v", serviceLabel2, err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if !waitForPort(t, "tcp", addr, 30*time.Second) {
		logJournalctl(t, serviceLabel2)
		t.Fatalf("service %s did not start on %s within 30s", svcName(serviceLabel2), addr)
	}
	t.Logf("service %s is listening on %s", svcName(serviceLabel2), addr)

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DNS via service %s: rcode=%s, want NOERROR",
			svcName(serviceLabel2), dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("DNS via service %s: NOERROR but no answer records", svcName(serviceLabel2))
	}
	t.Logf("service %s resolved example.com A: %d answer(s)", svcName(serviceLabel2), len(resp.Answer))
}
