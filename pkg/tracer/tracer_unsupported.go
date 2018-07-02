// +build !linux

package tracer

import (
	"fmt"
)

// New sets up a new Tracer.
// This returns a dummy Tracer for non-linux systems to compile.
func New() (Tracer, error) {
	return nil, fmt.Errorf("not supported on non-Linux systems")
}
