package tracer

import (
	"encoding/binary"
	"net"
	"unsafe"
)

/*
#include "../../tcptracer-bpf.h"
*/
import "C"

// tcpV4ToGo maps a given TCP IPv4 byte slice to a TCPEvent.
func tcpV4ToGo(data *[]byte) TCPEvent {
	eventC := (*C.struct_tcp_ipv4_event_t)(unsafe.Pointer(&(*data)[0]))

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(eventC.saddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(eventC.daddr))

	return TCPEvent{
		Timestamp: uint64(eventC.timestamp),
		CPU: uint64(eventC.cpu),
		Type: EventType(eventC._type),
		Pid: uint32(eventC.pid & 0xffffffff),
		Comm: C.GoString(&eventC.comm[0]),
		TCPType: IPv4,
		SAddr: net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3]),
		DAddr: net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3]),
		SPort: uint16(eventC.sport),
		DPort: uint16(eventC.dport),
		NetNS: uint32(eventC.netns),
		Fd: uint32(eventC.fd),
	}
}

// tcpV6ToGo maps a given TCP IPv6 byte slice to a TCPEvent.
func tcpV6ToGo(data *[]byte) TCPEvent {
	eventC := (*C.struct_tcp_ipv6_event_t)(unsafe.Pointer(&(*data)[0]))

	saddrbuf := make([]byte, 16)
	daddrbuf := make([]byte, 16)

	binary.LittleEndian.PutUint64(saddrbuf, uint64(eventC.saddr_h))
	binary.LittleEndian.PutUint64(saddrbuf[8:], uint64(eventC.saddr_l))
	binary.LittleEndian.PutUint64(daddrbuf, uint64(eventC.daddr_h))
	binary.LittleEndian.PutUint64(daddrbuf[8:], uint64(eventC.daddr_l))

	return TCPEvent{
		Timestamp: uint64(eventC.timestamp),
		CPU: uint64(eventC.cpu),
		Type: EventType(eventC._type),
		Pid: uint32(eventC.pid & 0xffffffff),
		Comm: C.GoString(&eventC.comm[0]),
		TCPType: IPv6,
		SAddr: net.IP(saddrbuf),
		DAddr: net.IP(daddrbuf),
		SPort: uint16(eventC.sport),
		DPort: uint16(eventC.dport),
		NetNS: uint32(eventC.netns),
		Fd: uint32(eventC.fd),
	}
}

func tcpV4Timestamp(data *[]byte) uint64 {
	eventC := (*C.struct_tcp_ipv4_event_t)(unsafe.Pointer(&(*data)[0]))
	return uint64(eventC.timestamp)
}

func tcpV6Timestamp(data *[]byte) uint64 {
	eventC := (*C.struct_tcp_ipv6_event_t)(unsafe.Pointer(&(*data)[0]))
	return uint64(eventC.timestamp)
}

func newEvent(t TCPEvent) Event {
	return Event{TCPEvent: t}
}

func newEventError(err error) Event {
	return Event{Error: err}
}
