package tracer

import (
	"net"
)

// EventType represents the type of TCP event that occurred, as one of the below.
type EventType uint32

// These constants should be in sync with the equivalent definitions in the ebpf program.
const (
	EventConnect   EventType = 1
	EventAccept              = 2
	EventClose               = 3
	EventFdInstall           = 4
)

// String returns a string representation of the event type.
func (e EventType) String() string {
	switch e {
	case EventConnect:
		return "connect"
	case EventAccept:
		return "accept"
	case EventClose:
		return "close"
	case EventFdInstall:
		return "fdinstall"
	default:
		return "unknown"
	}
}

// TCPType represents whether the connection was IPv4 or IPv6.
type TCPType string

const (
	IPv4 TCPType = "IPv4"
	IPv6 TCPType = "IPv6"
)

// TCPEvent represents a TCP event (connect, accept or close) on IPv4 or IPv6.
type TCPEvent struct {
	Timestamp uint64    // Monotonic timestamp
	CPU       uint64    // CPU index
	Type      EventType // connect, accept or close
	TCPType   TCPType   // IPv4 or IPv6
	Pid       uint32    // Process ID, who triggered the event
	Comm      string    // The process command (as in /proc/$pid/comm)
	SAddr     net.IP    // Local IP address
	DAddr     net.IP    // Remote IP address
	SPort     uint16    // Local TCP port
	DPort     uint16    // Remote TCP port
	NetNS     uint32    // Network namespace ID (as in /proc/$pid/ns/net)
	Fd        uint32    // File descriptor for fd_install events
}

// Event represents a message on the event channel for consumption.
// It includes an Error field in case something goes wrong.
type Event struct {
	TCPEvent
	Error error
}
