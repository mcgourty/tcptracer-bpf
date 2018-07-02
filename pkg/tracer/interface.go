package tracer

// Tracer represents the TCP tracing interface.
// Tracer returns new tcp events along a channel for convenient consumption.
type Tracer interface {
	// Start starts the TCP tracer.
	Start()
	// Events sends all new TCP events along a channel.
	Events() <-chan Event
	// Closed indicates when the channel has been closed.
	Closed() <-chan struct{}
	// Close closes the TCP tracer.
	Close()

	AddFdInstallWatcher(uint32) error
}
