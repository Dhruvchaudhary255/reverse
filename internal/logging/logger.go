// Package logging provides structured logging with file output support.
// It uses environment variables for configuration and supports file cleanup.
package logging

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/charmbracelet/log"
)

// LoggerCloser wraps a logger and provides a Close method for cleanup
type LoggerCloser struct {
	*log.Logger
	closer io.Closer
}

// Close closes the underlying writer if it's closeable
func (lc *LoggerCloser) Close() error {
	if lc.closer != nil {
		return lc.closer.Close()
	}
	return nil
}

// NewLoggerWithWriter creates a new logger with the provided writer
func NewLoggerWithWriter(w io.Writer) *LoggerCloser {
	lg := log.NewWithOptions(w, log.Options{
		ReportTimestamp: true,
		TimeFormat:      time.Kitchen,
	})

	// Set log level from environment
	level := os.Getenv("REVERSE_LOG_LEVEL")
	switch level {
	case "debug":
		lg.SetLevel(log.DebugLevel)
	case "warn":
		lg.SetLevel(log.WarnLevel)
	case "error":
		lg.SetLevel(log.ErrorLevel)
	default:
		lg.SetLevel(log.InfoLevel)
	}

	// Set prefix from environment
	prefix := os.Getenv("REVERSE_LOG_PREFIX")
	if prefix == "" {
		prefix = "reverse "
	}

	var closer io.Closer
	if c, ok := w.(io.Closer); ok {
		closer = c
	}

	return &LoggerCloser{
		Logger: lg.WithPrefix(prefix),
		closer: closer,
	}
}

// NewLogger creates a new logger based on environment variables
// REVERSE_LOG_LEVEL: debug, info, warn, error (default: info)
// REVERSE_LOG_PREFIX: prefix for log messages (default: "reverse ")
// REVERSE_LOG_TO_FILE: when set to "1", logs to a timestamped file instead of stderr
func NewLogger() *LoggerCloser {
	output := io.Writer(os.Stderr)

	// Check if we should log to file
	if os.Getenv("REVERSE_LOG_TO_FILE") == "1" {
		// Create timestamped log file
		timestamp := time.Now().Format("20060102-150405")
		logFile := fmt.Sprintf("reverse-%s-debug.log", timestamp)

		f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err == nil {
			output = f
		}
		// If file creation fails, fall back to stderr
	}

	return NewLoggerWithWriter(output)
}

// IsDebug returns true if debug logging is enabled
func IsDebug() bool {
	return os.Getenv("REVERSE_LOG_LEVEL") == "debug"
}
