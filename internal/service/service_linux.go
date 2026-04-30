// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func init() {
	platformInstall = installLinux
	platformUninstall = uninstallLinux
}

// installLinux handles systemd, OpenWRT procd.
func installLinux(cfg ServiceConfig) error {
	if isSystemd() {
		return installSystemd(cfg)
	}
	if isOpenWRT() {
		return installOpenWRT(cfg)
	}
	return fmt.Errorf("unsupported init system: neither systemd nor OpenWRT procd detected")
}

func uninstallLinux(cfg ServiceConfig) error {
	if isSystemd() {
		return uninstallSystemd(cfg)
	}
	if isOpenWRT() {
		return uninstallOpenWRT(cfg)
	}
	return fmt.Errorf("unsupported init system")
}

func isSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func isOpenWRT() bool {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "OpenWrt")
}

func installSystemd(cfg ServiceConfig) error {
	exe, err := cfg.resolveExePath()
	if err != nil {
		return err
	}

	name := cfg.ServiceName()
	unitPath := "/etc/systemd/system/" + name + ".service"

	// Check for existing service
	if _, err := os.Stat(unitPath); err == nil {
		return fmt.Errorf("service %q already exists at %s, use --uninstall to remove it first or choose a different label", name, unitPath)
	}

	args := cfg.ServerArgs()
	execStart := exe
	if len(args) > 0 {
		execStart += " " + strings.Join(args, " ")
	}

	cfgDir := "/etc/dnsieve"
	if cfg.CfgFile != "" {
		cfgDir = filepath.Dir(cfg.CfgFile)
	}
	logDir := "/var/log/dnsieve"
	if cfg.LogDir != "" {
		logDir = cfg.LogDir
	}

	// ProtectHome=yes hides /home, /root and /run/user at the mount-namespace
	// level; ReadWritePaths cannot override it.  If any relevant path falls
	// under one of those prefixes (e.g. a custom --cfgfile stored in a home
	// directory), we must relax the setting to avoid silently breaking the
	// service at startup.
	protectHome := "yes"
	if pathUnderHome(cfgDir) || pathUnderHome(logDir) || pathUnderHome(exe) {
		protectHome = "no"
	}

	// PrivateTmp=true gives the service an isolated /tmp namespace that hides
	// the real /tmp tree.  If the binary, config directory, or log directory
	// is located under /tmp (common when installing from a build or test
	// directory), disable PrivateTmp so the service can access those paths.
	privateTmp := "true"
	if pathUnderTmp(exe) || pathUnderTmp(cfgDir) || pathUnderTmp(logDir) {
		privateTmp = "false"
	}

	// ProtectSystem=strict remounts the entire filesystem hierarchy read-only
	// inside the service namespace, including /tmp.  Even though Go binaries
	// can be executed from a read-only mount in principle, in practice the
	// combination of strict mode with a binary located under /tmp causes the
	// service to fail at startup (the ExecStartPre control process cannot
	// operate correctly inside the restricted namespace).
	// When any relevant path is under /tmp -- which indicates a development or
	// CI installation -- set ProtectSystem=no so no filesystem restrictions are
	// applied.  For production installs (binary in /usr/local/bin, config in
	// /etc, logs in /var/log) the default strict mode is appropriate.
	protectSystem := "strict"
	if pathUnderTmp(exe) || pathUnderTmp(cfgDir) || pathUnderTmp(logDir) {
		protectSystem = "no"
	}

	unit := fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=+/bin/mkdir -p %s %s
ExecStart=%s
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Security hardening
ProtectSystem=%s
ReadWritePaths=%s %s
NoNewPrivileges=yes
PrivateTmp=%s
ProtectHome=%s

# DNS needs network access and potentially binding to port 53
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`, cfg.DisplayName(), cfgDir, logDir, execStart, protectSystem, cfgDir, logDir, privateTmp, protectHome)

	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write unit file %s: %w", unitPath, err)
	}

	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", name},
		{"systemctl", "start", name},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %s (%w)", strings.Join(c, " "), strings.TrimSpace(string(out)), err)
		}
	}

	fmt.Printf("Service %q (%s) installed and started.\n", cfg.DisplayName(), name)
	fmt.Printf("  Unit file: %s\n", unitPath)
	fmt.Printf("  Status:    systemctl status %s\n", name)
	fmt.Printf("  Logs:      journalctl -u %s -f\n", name)
	fmt.Printf("  Remove:    dnsieve --uninstall\n")
	return nil
}

func uninstallSystemd(cfg ServiceConfig) error {
	services := findDNSieveServicesSystemd()
	if len(services) == 0 {
		fmt.Println("No DNSieve services found.")
		return nil
	}

	fmt.Println("Found DNSieve services:")
	fmt.Println()
	for i, svc := range services {
		fmt.Printf("  %d. %s\n", i+1, svc.name)
		fmt.Printf("     Command: %s\n", svc.execStart)
		fmt.Println()
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the number to uninstall (or press Enter to cancel): ")
	choice := strings.TrimSpace(readLineLinux(reader))
	if choice == "" {
		fmt.Println("Cancelled.")
		return nil
	}

	idx := 0
	for _, c := range choice {
		if c < '0' || c > '9' {
			fmt.Println("Invalid choice.")
			return nil
		}
		idx = idx*10 + int(c-'0')
	}
	idx--
	if idx < 0 || idx >= len(services) {
		fmt.Println("Invalid choice.")
		return nil
	}

	svc := services[idx]

	exec.Command("systemctl", "stop", svc.unitName).Run()
	exec.Command("systemctl", "disable", svc.unitName).Run()

	if err := os.Remove(svc.unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()
	fmt.Printf("Service %q uninstalled.\n", svc.name)
	return nil
}

type linuxService struct {
	name      string
	unitName  string
	unitPath  string
	execStart string
}

// findDNSieveServicesSystemd scans /etc/systemd/system for DNSieve unit files.
func findDNSieveServicesSystemd() []linuxService {
	dir := "/etc/systemd/system"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var services []linuxService
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "dnsieve") || !strings.HasSuffix(name, ".service") {
			continue
		}
		unitPath := filepath.Join(dir, name)
		data, err := os.ReadFile(unitPath)
		if err != nil {
			continue
		}
		var execStart, description string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ExecStart=") {
				execStart = strings.TrimPrefix(line, "ExecStart=")
			}
			if strings.HasPrefix(line, "Description=") {
				description = strings.TrimPrefix(line, "Description=")
			}
		}
		displayName := description
		if displayName == "" {
			displayName = strings.TrimSuffix(name, ".service")
		}
		services = append(services, linuxService{
			name:      displayName,
			unitName:  strings.TrimSuffix(name, ".service"),
			unitPath:  unitPath,
			execStart: execStart,
		})
	}
	return services
}

func readLineLinux(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func installOpenWRT(cfg ServiceConfig) error {
	exe, err := cfg.resolveExePath()
	if err != nil {
		return err
	}

	name := cfg.ServiceName()
	initPath := "/etc/init.d/" + name

	// Check for existing service
	if _, err := os.Stat(initPath); err == nil {
		return fmt.Errorf("service %q already exists at %s, use --uninstall to remove it first", name, initPath)
	}

	args := cfg.ServerArgs()
	cmdLine := exe
	if len(args) > 0 {
		cmdLine += " " + strings.Join(args, " ")
	}

	script := fmt.Sprintf(`#!/bin/sh /etc/rc.common
# %s
START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command %s
    procd_set_param respawn
    procd_set_param stderr 1
    procd_set_param stdout 1
    procd_close_instance
}
`, cfg.DisplayName(), cmdLine)

	if err := os.WriteFile(initPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("write init script %s: %w", initPath, err)
	}

	cmds := [][]string{
		{initPath, "enable"},
		{initPath, "start"},
	}
	for _, c := range cmds {
		exec.Command(c[0], c[1:]...).Run()
	}

	fmt.Printf("Service %q installed and started (OpenWRT procd).\n", cfg.DisplayName())
	return nil
}

func uninstallOpenWRT(cfg ServiceConfig) error {
	name := cfg.ServiceName()
	initPath := "/etc/init.d/" + name

	exec.Command(initPath, "stop").Run()
	exec.Command(initPath, "disable").Run()

	if err := os.Remove(initPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove init script: %w", err)
	}

	fmt.Printf("Service %q uninstalled (OpenWRT procd).\n", name)
	return nil
}

// pathUnderHome reports whether path resides under a home directory that
// systemd's ProtectHome= hides from services (/home, /root, /run/user).
func pathUnderHome(path string) bool {
	return strings.HasPrefix(path, "/home/") ||
		path == "/root" ||
		strings.HasPrefix(path, "/root/") ||
		strings.HasPrefix(path, "/run/user/")
}

// pathUnderTmp reports whether path resides under /tmp.
// Services with PrivateTmp=true receive an isolated empty /tmp namespace;
// any path under the real /tmp would therefore be invisible to them.
func pathUnderTmp(path string) bool {
	return path == "/tmp" || strings.HasPrefix(path, "/tmp/")
}
