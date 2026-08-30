// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package service provides cross-platform system service installation
// and uninstallation for DNSieve (Windows, Linux, macOS).
//
// During install, the user is prompted for an optional service label.
// During uninstall, all DNSieve services are listed and the user picks
// which one to remove. The --cfgfile and --logdir flags are preserved
// in the service command line.
package service

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ServiceConfig holds parameters for service installation.
type ServiceConfig struct {
	CfgFile      string // Custom config file path (empty = platform default)
	LogDir       string // Custom log directory path (empty = platform default)
	ExePath      string // Absolute path to dnsieve binary (auto-detected if empty)
	DisplayLabel string // User-chosen label for multi-instance support
}

// ServiceName returns the service identifier.
func (sc *ServiceConfig) ServiceName() string {
	if sc.DisplayLabel != "" {
		return "dnsieve_" + sanitizeServiceLabel(sc.DisplayLabel)
	}
	return "dnsieve"
}

// DisplayName returns a human-readable service display name.
func (sc *ServiceConfig) DisplayName() string {
	if sc.DisplayLabel != "" {
		return "DNSieve DNS Filtering Proxy (" + sc.DisplayLabel + ")"
	}
	return "DNSieve DNS Filtering Proxy"
}

// ServerArgs returns command-line arguments for the service executable.
func (sc *ServiceConfig) ServerArgs() []string {
	var args []string
	if sc.CfgFile != "" {
		args = append(args, "--cfgfile", sc.CfgFile)
	}
	if sc.LogDir != "" {
		args = append(args, "--logdir", sc.LogDir)
	}
	return args
}

// resolveExePath finds the absolute path to the running binary.
func (sc *ServiceConfig) resolveExePath() (string, error) {
	if sc.ExePath != "" {
		return sc.ExePath, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("detect executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return exe, nil
}

var safeLabel = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// sanitizeServiceLabel removes characters that are unsafe for service names.
func sanitizeServiceLabel(label string) string {
	label = strings.TrimSpace(label)
	label = safeLabel.ReplaceAllString(label, "_")
	if label == "" {
		return "default"
	}
	return label
}

// Install registers DNSieve as a system service.
// Prompts the user for an optional service label.
func Install(cfg ServiceConfig) error {
	if err := fillDefaults(&cfg); err != nil {
		return err
	}

	// Prompt for display label
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Service Installation")
	fmt.Println("  The service will be named \"DNSieve DNS Filtering Proxy\".")
	fmt.Print("  Enter a custom label (or press Enter to skip): ")
	label := readLine(reader)
	if label != "" {
		cfg.DisplayLabel = label
	}
	fmt.Printf("  Service name: %s\n\n", cfg.DisplayName())

	return platformInstall(cfg)
}

// Uninstall removes a DNSieve system service.
// Lists all DNSieve services and prompts the user to pick one.
func Uninstall(cfg ServiceConfig) error {
	if err := fillDefaults(&cfg); err != nil {
		return err
	}
	return platformUninstall(cfg)
}

// platformInstall and platformUninstall are declared by the build-tagged
// platform files (service_linux.go, service_darwin.go, service_windows.go).
// Declaring them as functions rather than assigning function variables in
// init() means a GOOS with no platform file fails to compile here instead of
// panicking on a nil call at run time.

// fillDefaults populates missing fields.
func fillDefaults(cfg *ServiceConfig) error {
	exe, err := cfg.resolveExePath()
	if err != nil {
		return err
	}
	cfg.ExePath = exe
	return nil
}

// serviceChoice is one entry in the interactive uninstall picker.
// detailLabel is the caption for the second line ("Plist", "Command").
type serviceChoice struct {
	name        string
	detailLabel string
	detail      string
}

// promptServiceChoice prints a numbered list of discovered services and reads
// the user's pick from stdin. It returns the zero-based index and true, or
// false when there is nothing to pick, the user cancels, or the input is not a
// valid entry number. A message is printed on every false path.
func promptServiceChoice(choices []serviceChoice) (int, bool) {
	if len(choices) == 0 {
		fmt.Println("No DNSieve services found.")
		return 0, false
	}

	fmt.Println("Found DNSieve services:")
	fmt.Println()
	for i, c := range choices {
		fmt.Printf("  %d. %s\n", i+1, c.name)
		fmt.Printf("     %s: %s\n", c.detailLabel, c.detail)
		fmt.Println()
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the number to uninstall (or press Enter to cancel): ")
	choice := readLine(reader)
	if choice == "" {
		fmt.Println("Cancelled.")
		return 0, false
	}

	// Digits only: reject signs and whitespace the way the prompt always has.
	for _, c := range choice {
		if c < '0' || c > '9' {
			fmt.Println("Invalid choice.")
			return 0, false
		}
	}
	idx, err := strconv.Atoi(choice)
	if err != nil || idx < 1 || idx > len(choices) {
		fmt.Println("Invalid choice.")
		return 0, false
	}
	return idx - 1, true
}

func readLine(reader *bufio.Reader) string {
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "  Warning: failed to read input: %v\n", err)
	}
	return strings.TrimSpace(line)
}
