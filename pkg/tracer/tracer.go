// +build linux

package tracer

import (
	"bytes"
	"fmt"
	"unsafe"
	bpflib "github.com/iovisor/gobpf/elf"
)

// tracer listens for TCP connections and sends events along
// an event channel.
type tracer struct {
	m           *bpflib.Module
	eventC     chan Event
	doneC       chan struct{}
	perfMapIPV4 *bpflib.PerfMap
	perfMapIPV6 *bpflib.PerfMap
	stopChan    chan struct{}
}

// maxActive configures the maximum number of instances of the probed functions
// that can be handled simultaneously.
// This value should be enough to handle typical workloads (for example, some
// amount of processes blocked on the accept syscall).
const maxActive = 128

// New sets up a new Tracer.
func New() (Tracer, error) {
	buf, err := Asset("tcptracer-ebpf.o")
	if err != nil {
		return nil, fmt.Errorf("couldn't find asset: %s", err)
	}
	reader := bytes.NewReader(buf)

	m := bpflib.NewModuleFromReader(reader)
	if m == nil {
		return nil, fmt.Errorf("BPF not supported")
	}

	sectionParams := make(map[string]bpflib.SectionParams)
	sectionParams["maps/tcp_event_ipv4"] = bpflib.SectionParams{PerfRingBufferPageCount: 256}
	err = m.Load(sectionParams)
	if err != nil {
		return nil, err
	}

	err = m.EnableKprobes(maxActive)
	if err != nil {
		return nil, err
	}

	channelV4 := make(chan []byte)
	channelV6 := make(chan []byte)
	lostChanV4 := make(chan uint64)
	lostChanV6 := make(chan uint64)

	perfMapIPV4, err := initializeIPv4(m, channelV4, lostChanV4)
	if err != nil {
		return nil, fmt.Errorf("failed to init perf map for IPv4 events: %s", err)
	}

	perfMapIPV6, err := initializeIPv6(m, channelV6, lostChanV6)
	if err != nil {
		return nil, fmt.Errorf("failed to init perf map for IPv6 events: %s", err)
	}

	perfMapIPV4.SetTimestampFunc(tcpV4Timestamp)
	perfMapIPV6.SetTimestampFunc(tcpV6Timestamp)

	stopChan := make(chan struct{})

	t := &tracer{
		m:           m,
		eventC:      make(chan Event),
		doneC:       make(chan struct{}),
		perfMapIPV4: perfMapIPV4,
		perfMapIPV6: perfMapIPV6,
		stopChan:    stopChan,
	}

	// consume and send messages in a routine to the tracer.
	go func() {
		for {
			select {
			case <-stopChan:
				// On stop, stopChan will be closed but the other channels will
				// also be closed shortly after. The select{} has no priorities,
				// therefore, the "ok" value must be checked below.
				return
			case data, ok := <-channelV4:
				if !ok {
					return // see explanation above
				}
				t.eventC <- newEvent(tcpV4ToGo(&data))
			case lost, ok := <-lostChanV4:
				if !ok {
					return // see explanation above
				}
				t.eventC <- newEventError(fmt.Errorf("%d tcp IPv4 events were lost", lost))
			case data, ok := <-channelV6:
				if !ok {
					return // see explanation above
				}
				t.eventC <- newEvent(tcpV6ToGo(&data))
			case lost, ok := <-lostChanV6:
				if !ok {
					return // see explanation above
				}
				t.eventC <- newEventError(fmt.Errorf("%d tcp IPv6 events were lost", lost))
			}
		}
	}()

	return t, nil
}

// Events returns a channel of events to range from.
// The Event type returned holds both events and any errors that occur.
func (t *tracer) Events() <-chan Event {
	return t.eventC
}

// Start starts a poll into the TCP perfMaps for new connection info.
// A Tracer should be closed with Close().
func (t *tracer) Start() {
	t.perfMapIPV4.PollStart()
	t.perfMapIPV6.PollStart()
}

// Closed returns whether or not the channel has closed.
func (t *tracer) Closed() <-chan struct{} {
	return t.doneC
}

// Close closes the Tracer.
func (t *tracer) Close() {
	t.perfMapIPV4.PollStop()
	t.perfMapIPV6.PollStop()
	t.m.Close()
	close(t.stopChan)
	close(t.eventC)
	close(t.doneC)
}

func (t *tracer) AddFdInstallWatcher(pid uint32) (err error) {
    var one uint32 = 1
    mapFdInstall := t.m.Map("fdinstall_pids")
    err = t.m.UpdateElement(mapFdInstall, unsafe.Pointer(&pid), unsafe.Pointer(&one), 0)
    return err
}

func initialize(module *bpflib.Module, eventMapName string, eventChan chan []byte, lostChan chan uint64) (*bpflib.PerfMap, error) {
	if err := guess(module); err != nil {
		return nil, fmt.Errorf("error guessing offsets: %v", err)
	}

	pm, err := bpflib.InitPerfMap(module, eventMapName, eventChan, lostChan)
	if err != nil {
		return nil, fmt.Errorf("error initializing perf map for %q: %v", eventMapName, err)
	}

	return pm, nil
}

func initializeIPv4(module *bpflib.Module, eventChan chan []byte, lostChan chan uint64) (*bpflib.PerfMap, error) {
	return initialize(module, "tcp_event_ipv4", eventChan, lostChan)
}

func initializeIPv6(module *bpflib.Module, eventChan chan []byte, lostChan chan uint64) (*bpflib.PerfMap, error) {
	return initialize(module, "tcp_event_ipv6", eventChan, lostChan)
}
