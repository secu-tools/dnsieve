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
	label := strings.TrimSpace(readLine(reader))
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

// platformInstall and platformUninstall are set by platform-specific files.
var platformInstall func(ServiceConfig) error
var platformUninstall func(ServiceConfig) error

// fillDefaults populates missing fields.
func fillDefaults(cfg *ServiceConfig) error {
	if cfg.ExePath == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("detect executable path: %w", err)
		}
		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			return fmt.Errorf("resolve executable path: %w", err)
		}
		cfg.ExePath = exe
	}
	return nil
}

func readLine(reader *bufio.Reader) string {
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "  Warning: failed to read input: %v\n", err)
	}
	return strings.TrimSpace(line)
}
