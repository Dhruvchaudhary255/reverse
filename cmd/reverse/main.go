package main

import (
	"log/slog"
	"net/http"
	"os"

	_ "net/http/pprof" // profiling

	"reverse/internal/reverse/cmd"
	"reverse/internal/reverse/log"
)

func main() {
	defer log.RecoverPanic("main", func() {
		slog.Error("Application terminated due to unhandled panic")
	})

	if os.Getenv("REVERSE_PROFILE") != "" {
		go func() {
			slog.Info("Serving pprof at localhost:6060")
			if httpErr := http.ListenAndServe("localhost:6060", nil); httpErr != nil {
				slog.Error("Failed to pprof listen", "error", httpErr)
			}
		}()
	}

	cmd.Execute()
}