package log

import (
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

var (
	initOnce    sync.Once
	initialized atomic.Bool
)

func Setup(logFile string, debug bool) {
	initOnce.Do(func() {
		level := slog.LevelInfo
		if debug {
			level = slog.LevelDebug
		}

		// For now, just log to stderr
		logger := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level:     level,
			AddSource: debug,
		})

		slog.SetDefault(slog.New(logger))
		initialized.Store(true)
	})
}

func Initialized() bool {
	return initialized.Load()
}

func RecoverPanic(name string, cleanup func()) {
	if r := recover(); r != nil {
		if Initialized() {
			slog.Error(fmt.Sprintf("Panic in %s", name),
				"panic", r,
				"stack", string(debug.Stack()))
		}
		if cleanup != nil {
			cleanup()
		}
	}
}
