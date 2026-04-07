// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func init() {
	platformInstall = installWindows
	platformUninstall = uninstallWindows
}

// Install installs DNSieve as a Windows service using sc.exe.
func installWindows(cfg ServiceConfig) error {
	exe, err := cfg.resolveExePath()
	if err != nil {
		return err
	}

	name := cfg.ServiceName()

	// Check for service name conflict
	if out, err := exec.Command("sc.exe", "query", name).Output(); err == nil {
		if strings.Contains(string(out), "SERVICE_NAME") {
			return fmt.Errorf("service %q already exists, use --uninstall to remove it first or choose a different label", name)
		}
	}

	args := cfg.ServerArgs()
	binPath := `"` + exe + `"`
	if len(args) > 0 {
		binPath += " " + strings.Join(args, " ")
	}

	// Create the service
	out, err := exec.Command("sc.exe", "create", name,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", cfg.DisplayName(),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc create: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	// Set description (best effort)
	desc := "DNSieve DNS Filtering Proxy - filters DNS queries through multiple upstream providers with block-consensus caching."
	if out, err := exec.Command("sc.exe", "description", name, desc).CombinedOutput(); err != nil {
		fmt.Printf("Warning: failed to set service description: %s\n", strings.TrimSpace(string(out)))
	}

	// Configure failure recovery (best effort)
	if out, err := exec.Command("sc.exe", "failure", name,
		"reset=", "86400",
		"actions=", "restart/10000/restart/10000/restart/30000",
	).CombinedOutput(); err != nil {
		fmt.Printf("Warning: failed to set failure actions: %s\n", strings.TrimSpace(string(out)))
	}

	// Start the service
	out, err = exec.Command("sc.exe", "start", name).CombinedOutput()
	if err != nil {
		fmt.Printf("Service created but failed to start: %s\n", strings.TrimSpace(string(out)))
		fmt.Println("You can start it manually: sc start", name)
		return nil
	}

	fmt.Printf("Service %q (%s) installed and started.\n", cfg.DisplayName(), name)
	fmt.Printf("  Status:  sc query %s\n", name)
	fmt.Printf("  Stop:    sc stop %s\n", name)
	fmt.Printf("  Remove:  dnsieve --uninstall\n")
	return nil
}

// Uninstall lists all DNSieve Windows services and prompts user to pick one.
func uninstallWindows(cfg ServiceConfig) error {
	services := findDNSieveServicesWindows()
	if len(services) == 0 {
		fmt.Println("No DNSieve services found.")
		return nil
	}

	fmt.Println("Found DNSieve services:")
	fmt.Println()
	for i, svc := range services {
		fmt.Printf("  %d. %s\n", i+1, svc.displayName)
		fmt.Printf("     Command: %s\n", svc.binPath)
		fmt.Println()
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the number to uninstall (or press Enter to cancel): ")
	choice := strings.TrimSpace(readLineStdio(reader))
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
	idx-- // 1-based to 0-based
	if idx < 0 || idx >= len(services) {
		fmt.Println("Invalid choice.")
		return nil
	}

	svc := services[idx]

	// Stop the service first (best effort)
	exec.Command("sc.exe", "stop", svc.name).Run()

	out, err := exec.Command("sc.exe", "delete", svc.name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc delete: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	fmt.Printf("Service %q uninstalled.\n", svc.displayName)
	return nil
}

type winService struct {
	name        string
	displayName string
	binPath     string
}

// findDNSieveServicesWindows queries Windows SCM for DNSieve-related services.
func findDNSieveServicesWindows() []winService {
	psCmd := `Get-WmiObject Win32_Service | Where-Object { $_.PathName -like '*dnsieve*' } | ForEach-Object { $_.Name + '|' + $_.DisplayName + '|' + $_.PathName }`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var services []winService
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}
		services = append(services, winService{
			name:        parts[0],
			displayName: parts[1],
			binPath:     parts[2],
		})
	}
	return services
}

func readLineStdio(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
