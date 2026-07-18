// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/daemon"
)

// startMetricsServer binds addr (typically "localhost:9876") and serves
// a Prometheus text-format /metrics endpoint reading state from srv.
// Returns a Close func the caller invokes during daemon shutdown.
//
// addr forms:
//
//	""               disabled (no listener spawned)
//	":9876"          all interfaces — opt-in public bind, requires
//	                 an explicit colon prefix the user has typed
//	"localhost:9876" loopback bind (default safe form)
//	"9876"           bare port — rewritten to "localhost:9876" so an
//	                 accidental --metrics 9876 does not expose the
//	                 endpoint to the LAN
//
// /metrics responds GET-only with `text/plain; version=0.0.4`. Other
// methods get 405; other paths get 404. The handler is intentionally
// minimal — no auth, no rate limit. Bind to loopback for prod scrape
// via a colocated agent; bind to "*" only when you explicitly want
// public exposure and have a firewall in front.
func startMetricsServer(addr string, srv *daemon.Server, startedAt time.Time) (func() error, error) {
	if strings.TrimSpace(addr) == "" {
		return func() error { return nil }, nil
	}

	// Bare port → loopback bind. We deliberately do NOT default a
	// blank-host ":port" to loopback because that form is the
	// established Go convention for "all interfaces" and overriding it
	// would surprise operators who knew exactly what they typed.
	bindAddr := addr
	if !strings.Contains(addr, ":") {
		bindAddr = "localhost:" + addr
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("metrics: bind %s: %w", bindAddr, err)
	}

	mux := http.NewServeMux()
	renderer := daemon.NewMetricsRenderer(srv, startedAt)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := renderer.Render(w); err != nil {
			// Render only fails on a broken pipe / aborted client;
			// log once for diagnosis but do not surface to the client
			// because the response is already partly written.
			fmt.Fprintf(os.Stderr, brand.DaemonName+": metrics render: %v\n", err)
		}
	})

	httpSrv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		if err := httpSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, brand.DaemonName+": metrics server: %v\n", err)
		}
	}()
	fmt.Fprintf(os.Stderr, brand.DaemonName+": metrics endpoint http://%s/metrics\n", listener.Addr().String())

	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return httpSrv.Shutdown(ctx)
	}, nil
}
