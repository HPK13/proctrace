//go:build !windows && !linux

package collector

import (
	"fmt"
	"runtime"

	"github.com/HPK13/proctrace/internal/event"
)

func listProcesses() ([]event.Process, error) {
	return nil, fmt.Errorf("process collection is not implemented on %s", runtime.GOOS)
}
