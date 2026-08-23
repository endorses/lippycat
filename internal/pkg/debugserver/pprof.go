package debugserver

import (
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

const envPprofAddr = "LC_PPROF_ADDR"

// StartPprof starts the Go debug/pprof HTTP server when addr is non-empty.
// The listener is opened synchronously so bind and safety errors are visible to
// the caller before packet capture begins.
func StartPprof(addr string, allowNonLoopback bool) error {
	if addr == "" {
		return nil
	}
	if !allowNonLoopback && !isLoopbackBind(addr) {
		return fmt.Errorf("debug listener %q is not loopback; use --debug-allow-non-loopback to expose pprof", addr)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("Failed to start pprof listener", "addr", addr, "error", err)
		return fmt.Errorf("failed to start pprof listener on %s: %w", addr, err)
	}

	logger.Info("pprof debug listener started", "addr", ln.Addr().String())
	go func() {
		if err := http.Serve(ln, nil); err != nil && err != http.ErrServerClosed {
			logger.Error("pprof listener failed", "addr", ln.Addr().String(), "error", err)
		}
	}()
	return nil
}

// StartPprofFromConfig uses the explicit CLI/config address when provided and
// falls back to LC_PPROF_ADDR for compatibility with older deployments.
func StartPprofFromConfig(addr string, allowNonLoopback bool) error {
	if addr == "" {
		addr = os.Getenv(envPprofAddr)
	}
	return StartPprof(addr, allowNonLoopback)
}

func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if host == "" {
		return false
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
