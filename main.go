package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/endorses/lippycat/cmd"
)

func main() {
	if addr := os.Getenv("LC_PPROF_ADDR"); addr != "" {
		go func() { _ = http.ListenAndServe(addr, nil) }()
	}
	cmd.Execute()
}
