// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package app provides the CLI entry point, version banner, config
// generation, service management, speed testing, and server dispatch
// for DNSieve.
package app

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/server"
	"github.com/secu-tools/dnsieve/internal/service"
	"github.com/secu-tools/dnsieve/internal/speed"
)

// version, commit, and buildNumber are set via ldflags at build time:
//
//	-X github.com/secu-tools/dnsieve/internal/app.version=1.0.0
//	-X github.com/secu-tools/dnsieve/internal/app.commit=abc1234
//	-X github.com/secu-tools/dnsieve/internal/app.buildNumber=42
var (
	version     = "1.0.0"
	commit      = "dev"
	buildNumber = "0"
	buildMode   = "" // "docker" when running in container
)

// isRunningInDocker reports whether the process is running inside a Docker
// container. It checks the buildMode ldflags value first (set to "docker" in
// the Dockerfile), then falls back to the well-known /.dockerenv sentinel
// file that Docker creates in every container.
func isRunningInDocker() bool {
	if buildMode == "docker" {
		return true
	}
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func fullVersion() string {
	return fmt.Sprintf("%s.%s", version, buildNumber)
}

// resolveCommitLabel returns the short commit hash, falling back to
// runtime/debug.ReadBuildInfo for go-install builds.
func resolveCommitLabel() string {
	if commit != "dev" && commit != "" {
		return commit
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	// If installed via go install @vX.Y.Z, use the module version
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return "Go"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 7 {
			return s.Value[:7]
		}
	}
	return "dev"
}

// resolveVersion returns the version string for display. If built via
// go install @vX.Y.Z, uses the module version from BuildInfo.
func resolveVersion() string {
	if commit != "dev" && commit != "" {
		return fullVersion()
	}
	info, ok := debug.ReadBuildInfo()
	if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return fullVersion()
}

// versionTag returns the version with optional build mode suffix.
func versionTag() string {
	label := resolveCommitLabel()
	if buildMode != "" {
		label = buildMode
	}
	return label
}

func versionString() string {
	return fmt.Sprintf(
		"DNSieve - DNS Filtering Proxy - %s (%s)\n"+
			"Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)\n"+
			"Github Repository: https://github.com/secu-tools/dnsieve",
		resolveVersion(), versionTag())
}

// Run is the main entry point called from main.go.
func Run() {
	// Define flags (double-dash is default; Go flag package accepts both)
	cfgFile := flag.String("cfgfile", "", "Custom config file path")
	logDir := flag.String("logdir", "", "Custom log directory path")
	showVersion := flag.Bool("version", false, "Show version and exit")
	installSvc := flag.Bool("install", false, "Install as system service")
	uninstallSvc := flag.Bool("uninstall", false, "Uninstall system service")
	speedTest := flag.String("speed", "", "Test upstream DNS speed (optional: comma-separated domains)")
	flag.Parse()

	if *showVersion {
		fmt.Println(versionString())
		os.Exit(0)
	}

	// Print banner
	fmt.Fprintf(os.Stderr, "%s\n\n", versionString())

	// Handle service install/uninstall (independent of config)
	if *installSvc || *uninstallSvc {
		handleService(*installSvc, *cfgFile, *logDir)
		return
	}

	// Override log directory before anything else
	if *logDir != "" {
		if err := logging.SetLogDir(*logDir); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR | Failed to set log directory: %v\n", err)
			os.Exit(1)
		}
	}

	// Handle speed test mode (may need config for upstream list)
	if flag.Lookup("speed").Value.String() != "" || isSpeedFlag() {
		handleSpeedTest(*cfgFile, *speedTest)
		return
	}

	// Check if config exists; if not, auto-generate in Docker or prompt interactively.
	if !config.ConfigFileExists(*cfgFile) {
		if isRunningInDocker() {
			generated, err := config.GenerateDefaultConfig(*cfgFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR | Failed to generate default config: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "INFO  | No config found. Generated default config: %s\n", generated)
			fmt.Fprintln(os.Stderr, "INFO  | Mount a config volume to customise settings on next start.")
		} else {
			if config.PromptGenerateConfig(*cfgFile) {
				os.Exit(0)
			}
			fmt.Fprintln(os.Stderr, "Cannot start without a config file.")
			os.Exit(1)
		}
	}

	// Load and validate config
	cfg, cfgPath, warnings := loadAndValidateConfig(*cfgFile)

	// Set up logging
	logr := setupLogging(cfg)
	defer logr.Close()

	logr.Infof("Config loaded from: %s", cfgPath)
	for _, w := range warnings {
		logr.Warnf("%s", w)
	}
	if logging.UsingFallbackLogDir() {
		logr.Warnf("Using fallback log directory (default was not writable). Use --logdir to specify a custom location.")
	}

	logStartupInfo(cfg, logr)

	// Run startup speed test (logged at info level)
	speed.RunStartupTest(cfg, logr)

	// Start server
	if err := server.Run(cfg, logr); err != nil {
		logr.Errorf("Server error: %v", err)
		os.Exit(1)
	}
}

func handleService(install bool, cfgFile, logDir string) {
	svcCfg := service.ServiceConfig{
		CfgFile: cfgFile,
		LogDir:  logDir,
	}
	var err error
	if install {
		err = service.Install(svcCfg)
	} else {
		err = service.Uninstall(svcCfg)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR | %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func loadAndValidateConfig(cfgFile string) (*config.Config, string, []string) {
	cfg, cfgPath, err := config.Load(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR | Failed to load config: %v\n", err)
		os.Exit(1)
	}

	warnings, errors := cfg.Validate()
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "WARN  | %s\n", w)
	}
	if len(errors) > 0 {
		for _, e := range errors {
			fmt.Fprintf(os.Stderr, "ERROR | %s\n", e)
		}
		os.Exit(1)
	}
	return cfg, cfgPath, warnings
}

func setupLogging(cfg *config.Config) *logging.Logger {
	logCfg := logging.Config{
		MaxSizeMB:    cfg.Logging.LogMaxSizeMB,
		MaxBackups:   cfg.Logging.LogMaxBackups,
		MaxAgeDays:   cfg.Logging.LogMaxAgeDays,
		FloodLimitPS: cfg.Logging.LogFloodLimitPS,
	}

	logr, err := logging.New("dnsieve.log", logCfg, "server")
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN  | Failed to create log file, logging to stdout only: %v\n", err)
		fmt.Fprintln(os.Stderr, "       Specify --logdir to set a writable log directory.")
		logr = logging.NewStdoutOnly(logCfg, "server")
	}
	logr.SetLevelFromString(cfg.Logging.LogLevel)
	if logr.FilePath() != "" {
		logr.Infof("Logging to: %s", logr.FilePath())
	}
	return logr
}

func logStartupInfo(cfg *config.Config, logr *logging.Logger) {
	logr.Infof("Upstream servers: %d", len(cfg.Upstream))
	for i, u := range cfg.Upstream {
		verify := u.ShouldVerifyCert(cfg.UpstreamSettings.VerifyCertificates)
		logr.Infof("  [%d] %s (%s, verify_cert=%v)", i, u.Address, u.Protocol, verify)
	}
	if cfg.UpstreamSettings.BootstrapDNS != "" {
		logr.Infof("Bootstrap DNS: %s", cfg.UpstreamSettings.BootstrapDNS)
	}
	if cfg.Downstream.Plain.Enabled {
		logr.Infof("Downstream plain DNS: %v port %d (UDP+TCP)", cfg.Downstream.Plain.ListenAddresses, cfg.Downstream.Plain.Port)
		if cfg.Downstream.Plain.Port == 5353 {
			logr.Warnf("Port 5353 is non-standard, use port 53 for production (requires elevated privileges)")
		}
	}
	if cfg.Downstream.DoT.Enabled {
		logr.Infof("Downstream DoT: %v port %d", cfg.Downstream.DoT.ListenAddresses, cfg.Downstream.DoT.Port)
	}
	if cfg.Downstream.DoH.Enabled {
		proto := "HTTPS"
		if cfg.Downstream.DoH.UsePlaintextHTTP {
			proto = "HTTP (plaintext, no TLS)"
		}
		logr.Infof("Downstream DoH: %v port %d (%s)", cfg.Downstream.DoH.ListenAddresses, cfg.Downstream.DoH.Port, proto)
	}
	logr.Infof("Cache: enabled=%v, max_entries=%d, min_ttl=%ds, blocked_ttl=%ds, renew_percent=%d",
		cfg.Cache.Enabled, cfg.Cache.MaxEntries, cfg.Cache.MinTTL, cfg.Cache.BlockedTTL, cfg.Cache.RenewPercent)
	if cfg.Logging.SlowUpstreamMS > 0 {
		logr.Debugf("Slow upstream threshold: %dms", cfg.Logging.SlowUpstreamMS)
	}
}

// isSpeedFlag checks if --speed was passed (even without a value).
func isSpeedFlag() bool {
	for _, arg := range os.Args[1:] {
		if arg == "--speed" || arg == "-speed" {
			return true
		}
	}
	return false
}

// handleSpeedTest runs the speed test mode and exits.
func handleSpeedTest(cfgFile, domains string) {
	// If no config exists, offer to generate one first
	if !config.ConfigFileExists(cfgFile) {
		if config.PromptGenerateConfig(cfgFile) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "Cannot run speed test without a config file.")
		os.Exit(1)
	}

	cfg, _, err := config.Load(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR | Failed to load config: %v\n", err)
		os.Exit(1)
	}

	var domainList []string
	if domains != "" {
		for _, d := range strings.Split(domains, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				domainList = append(domainList, d)
			}
		}
	}

	speed.RunInteractiveTest(cfg, domainList)
}
