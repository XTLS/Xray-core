// Package logger provides a simple leveled logging interface.
package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"

	"github.com/pion/logging"
)

// verboseEnabled controls whether verbose and debug logging is enabled.
var verboseEnabled atomic.Bool //nolint:gochecknoglobals // package-level state intentional

// DisableNoisyPionLogs suppresses Pion scopes that are known to emit
// high-volume non-actionable background noise.
func DisableNoisyPionLogs() {
	mergePionLogDisable("turnc")
	removePionLogScopes([]string{"turnc"}, "ERROR", "WARN", "INFO", "DEBUG", "TRACE")
}

func mergePionLogDisable(scopes ...string) {
	const envKey = "PION_LOG_DISABLE"
	current := strings.TrimSpace(os.Getenv(envKey))
	if strings.EqualFold(current, "all") {
		return
	}
	seen := make(map[string]struct{})
	var merged []string
	for _, scope := range strings.Split(current, ",") {
		scope = strings.TrimSpace(strings.ToLower(scope))
		if scope == "" {
			continue
		}
		seen[scope] = struct{}{}
		merged = append(merged, scope)
	}
	for _, scope := range scopes {
		scope = strings.TrimSpace(strings.ToLower(scope))
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		merged = append(merged, scope)
	}
	_ = os.Setenv(envKey, strings.Join(merged, ","))
}

func removePionLogScopes(scopes []string, levels ...string) {
	remove := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(strings.ToLower(scope))
		if scope != "" {
			remove[scope] = struct{}{}
		}
	}
	for _, level := range levels {
		envKey := "PION_LOG_" + level
		current := strings.TrimSpace(os.Getenv(envKey))
		if current == "" || strings.EqualFold(current, "all") {
			continue
		}
		var kept []string
		for _, scope := range strings.Split(current, ",") {
			scope = strings.TrimSpace(strings.ToLower(scope))
			if scope == "" {
				continue
			}
			if _, drop := remove[scope]; drop {
				continue
			}
			kept = append(kept, scope)
		}
		_ = os.Setenv(envKey, strings.Join(kept, ","))
	}
}

// SetVerbose enables or disables verbose/debug logging.
func SetVerbose(enabled bool) {
	verboseEnabled.Store(enabled)
}

// IsVerbose returns true if verbose logging is enabled.
func IsVerbose() bool {
	return verboseEnabled.Load()
}

// Info logs an informational message.
func Info(v ...any) {
	log.Print(v...)
}

// Infof logs a formatted informational message.
func Infof(format string, v ...any) {
	log.Printf(format, v...)
}

// Warn logs a warning message.
func Warn(v ...any) {
	log.Print(v...)
}

// Warnf logs a formatted warning message.
func Warnf(format string, v ...any) {
	log.Printf(format, v...)
}

// Error logs an error message.
func Error(v ...any) {
	log.Print(v...)
}

// Errorf logs a formatted error message.
func Errorf(format string, v ...any) {
	log.Printf(format, v...)
}

// Verbosef logs a formatted message if verbose logging is enabled.
func Verbosef(format string, v ...any) {
	if verboseEnabled.Load() {
		log.Printf(format, v...)
	}
}

// Debugf logs a formatted message if verbose logging is enabled.
func Debugf(format string, v ...any) {
	if verboseEnabled.Load() {
		log.Printf(format, v...)
	}
}

// PionLoggerFactory implements a dummy logger factory for pion.
type PionLoggerFactory struct{}

// NewPionLoggerFactory creates a new PionLoggerFactory.
func NewPionLoggerFactory() logging.LoggerFactory {
	return &PionLoggerFactory{}
}

// NewLogger creates a new logger for the given scope.
func (f *PionLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	return &PionLeveledLogger{scope: scope}
}

// PionLeveledLogger implements a leveled logger that redirects to the standard log package.
type PionLeveledLogger struct {
	scope string
}

// Trace logs a trace message.
func (l *PionLeveledLogger) Trace(msg string) {
	if verboseEnabled.Load() {
		log.Printf("[%s] TRACE: %s", l.scope, msg)
	}
}

// Tracef logs a formatted trace message.
func (l *PionLeveledLogger) Tracef(format string, args ...any) {
	if verboseEnabled.Load() {
		log.Printf("[%s] TRACE: %s", l.scope, fmt.Sprintf(format, args...))
	}
}

// Debug logs a debug message.
func (l *PionLeveledLogger) Debug(msg string) {
	if verboseEnabled.Load() {
		log.Printf("[%s] DEBUG: %s", l.scope, msg)
	}
}

// Debugf logs a formatted debug message.
func (l *PionLeveledLogger) Debugf(format string, args ...any) {
	if verboseEnabled.Load() {
		log.Printf("[%s] DEBUG: %s", l.scope, fmt.Sprintf(format, args...))
	}
}

// Info logs an info message.
func (l *PionLeveledLogger) Info(msg string) {
	if shouldDropPionLog(l.scope, msg) {
		return
	}
	log.Printf("[%s] INFO: %s", l.scope, msg)
}

// Infof logs a formatted info message.
func (l *PionLeveledLogger) Infof(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if shouldDropPionLog(l.scope, msg) {
		return
	}
	log.Printf("[%s] INFO: %s", l.scope, msg)
}

// Warn logs a warning message.
func (l *PionLeveledLogger) Warn(msg string) {
	if shouldDropPionLog(l.scope, msg) {
		return
	}
	log.Printf("[%s] WARN: %s", l.scope, msg)
}

// Warnf logs a formatted warning message.
func (l *PionLeveledLogger) Warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if shouldDropPionLog(l.scope, msg) {
		return
	}
	log.Printf("[%s] WARN: %s", l.scope, msg)
}

// Error logs an error message.
func (l *PionLeveledLogger) Error(msg string) {
	if shouldDropPionLog(l.scope, msg) {
		return
	}
	log.Printf("[%s] ERROR: %s", l.scope, msg)
}

// Errorf logs a formatted error message.
func (l *PionLeveledLogger) Errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if shouldDropPionLog(l.scope, msg) {
		return
	}
	log.Printf("[%s] ERROR: %s", l.scope, msg)
}

func shouldDropPionLog(scope, msg string) bool {
	scope = strings.ToLower(scope)
	if scope == "srtp" || scope == "turnc" {
		return true
	}
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "refresh permissions") ||
		strings.Contains(msg, "createpermission error response")
}
