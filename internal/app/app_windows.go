// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build windows

package app

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"

	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/server"
	"github.com/secu-tools/dnsieve/internal/speed"
)

// maybeRunAsWindowsService checks whether the process was started by the
// Windows Service Control Manager (SCM).  If it was, it runs the full server
// inside the SCM service loop, which signals Running/StopPending status back
// to the SCM and handles graceful shutdown when the SCM sends a Stop request.
//
// Returns true when the process ran as a service (the caller should return
// immediately) and false when running from a normal interactive command line.
func maybeRunAsWindowsService(svcName, cfgFile, logDir string) bool {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false
	}

	// svc.Run blocks until the service exits.  Any error is written to stderr
	// because the event log is not guaranteed to be available here.
	if err := svc.Run(svcName, &winSvcHandler{cfgFile: cfgFile, logDir: logDir}); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR | Windows service %q exited: %v\n", svcName, err)
	}
	return true
}

// winSvcHandler implements the windows/svc.Handler interface so that the
// binary can be run as a first-class Windows Service without a wrapper.
type winSvcHandler struct {
	cfgFile string
	logDir  string
}

// Execute is called by the SCM dispatcher goroutine and must:
//  1. Report svc.StartPending then svc.Running to the SCM.
//  2. Start the actual server in a background goroutine.
//  3. Block waiting for a svc.Stop or svc.Shutdown command, then cancel the
//     server context and report svc.StopPending before returning.
func (h *winSvcHandler) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Override the log directory if one was specified at install time.
	if h.logDir != "" {
		if err := logging.SetLogDir(h.logDir); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR | Failed to set log directory: %v\n", err)
			return false, 1
		}
	}

	cfg, cfgPath, warnings := loadAndValidateConfig(h.cfgFile)
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
	speed.RunStartupTest(cfg, logr)

	// Start server asynchronously so we can handle SCM stop requests while it
	// runs.
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- server.RunContext(ctx, cfg, logr)
	}()

	// Signal the SCM that the service is fully running only once the server
	// has had a chance to start (or fail immediately).  We use a short poll
	// rather than waiting for the first DNS query.
	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-srvErr
				return false, 0
			default:
				// Interrogate and other commands: reply with current state.
				status <- svc.Status{
					State:   svc.Running,
					Accepts: svc.AcceptStop | svc.AcceptShutdown,
				}
			}
		case err := <-srvErr:
			if err != nil {
				logr.Errorf("Server exited unexpectedly: %v", err)
				return false, 1
			}
			return false, 0
		}
	}
}
