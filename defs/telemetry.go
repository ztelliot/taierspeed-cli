package defs

import (
	"fmt"
	"strings"
	"time"
)

const (
	TelemetryLevelDisabled = "disabled"
	TelemetryLevelBasic    = "basic"
	TelemetryLevelFull     = "full"
	TelemetryLevelDebug    = "debug"
)

// TelemetryLog is the logger for `log` field in telemetry data
type TelemetryLog struct {
	level   int
	content []string
}

// SetLevel sets the log level
func (t *TelemetryLog) SetLevel(level int) {
	t.level = level
}

// Logf logs when log level is higher than or equal to "full"
func (t *TelemetryLog) Logf(format string, a ...interface{}) {
	if t.level >= 2 {
		t.content = append(t.content, fmt.Sprintf("%s: %s", time.Now().String(), fmt.Sprintf(format, a...)))
	}
}

// Warnf logs when log level is higher than or equal to "full", with a WARN prefix
func (t *TelemetryLog) Warnf(format string, a ...interface{}) {
	if t.level >= 2 {
		t.content = append(t.content, fmt.Sprintf("%s: WARN: %s", time.Now().String(), fmt.Sprintf(format, a...)))
	}
}

// Verbosef logs when log level is higher than or equal to "debug"
func (t *TelemetryLog) Verbosef(format string, a ...interface{}) {
	if t.level >= 3 {
		t.content = append(t.content, fmt.Sprintf("%s: %s", time.Now().String(), fmt.Sprintf(format, a...)))
	}
}

// String returns the concatenated string of field `content`
func (t *TelemetryLog) String() string {
	return strings.Join(t.content, "\n")
}
