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
	platformInstall = installDarwin
	platformUninstall = uninstallDarwin
}

func installDarwin(cfg ServiceConfig) error {
	exe, err := cfg.resolveExePath()
	if err != nil {
		return err
	}

	name := cfg.ServiceName()
	label := "com.dnsieve." + name
	plistPath := "/Library/LaunchDaemons/" + label + ".plist"

	// Check for existing service
	if _, err := os.Stat(plistPath); err == nil {
		return fmt.Errorf("service %q already exists at %s, use --uninstall to remove it first", name, plistPath)
	}

	args := cfg.ServerArgs()
	var argElements string
	for _, a := range args {
		argElements += fmt.Sprintf("\t\t<string>%s</string>\n", a)
	}

	logDir := "/var/log/dnsieve"
	if cfg.LogDir != "" {
		logDir = cfg.LogDir
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
%s	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s/%s_stdout.log</string>
	<key>StandardErrorPath</key>
	<string>%s/%s_stderr.log</string>
</dict>
</plist>
`, label, exe, argElements, logDir, name, logDir, name)

	os.MkdirAll(logDir, 0750)

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write plist %s: %w", plistPath, err)
	}

	out, err := exec.Command("launchctl", "load", plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl load: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	fmt.Printf("Service %q installed and loaded (launchd).\n", cfg.DisplayName())
	fmt.Printf("  Label: %s\n", label)
	fmt.Printf("  Plist: %s\n", plistPath)
	fmt.Printf("  Remove: dnsieve --uninstall\n")
	return nil
}

func uninstallDarwin(cfg ServiceConfig) error {
	services := findDNSieveServicesDarwin("/Library/LaunchDaemons")
	if len(services) == 0 {
		fmt.Println("No DNSieve services found.")
		return nil
	}

	fmt.Println("Found DNSieve services:")
	fmt.Println()
	for i, svc := range services {
		fmt.Printf("  %d. %s\n", i+1, svc.label)
		fmt.Printf("     Plist: %s\n", svc.plistPath)
		fmt.Println()
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the number to uninstall (or press Enter to cancel): ")
	choice := strings.TrimSpace(readLineDarwin(reader))
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

	exec.Command("launchctl", "unload", svc.plistPath).Run()

	if err := os.Remove(svc.plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}

	fmt.Printf("Service %q uninstalled (launchd).\n", svc.label)
	return nil
}

type darwinService struct {
	label     string
	plistPath string
}

func findDNSieveServicesDarwin(dir string) []darwinService {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var services []darwinService
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "com.dnsieve.") || !strings.HasSuffix(name, ".plist") {
			continue
		}
		services = append(services, darwinService{
			label:     strings.TrimSuffix(name, ".plist"),
			plistPath: filepath.Join(dir, name),
		})
	}
	return services
}

func readLineDarwin(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
