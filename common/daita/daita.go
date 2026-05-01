//go:build daita

// Package daita implements Defence Against Traffic Analysis using the maybenot
// framework (https://github.com/maybenot-io/maybenot).
//
// Integration: wraps outbound net.Conn. On each Write/Read call, feeds events to
// maybenot and schedules dummy writes (InjectPadding actions) to obscure traffic
// patterns from ML-based classifiers.
package daita

/*
#include "maybenot.h"
#cgo LDFLAGS: -L${SRCDIR} -lmaybenot -lm -lntdll -lws2_32 -luserenv -lbcrypt
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"
)

// Framework wraps a maybenot C framework instance.
type Framework struct {
	fw          *C.MaybenotFramework
	numMachines C.uintptr_t
	mu          sync.Mutex
	closed      bool
}

// NewFramework initializes a maybenot framework from newline-separated base64
// machine strings.
func NewFramework(machinesStr string, maxPaddingFrac, maxBlockingFrac float64) (*Framework, error) {
	cs := C.CString(machinesStr)
	defer C.free(unsafe.Pointer(cs))

	var fw *C.MaybenotFramework
	result := C.maybenot_start(cs, C.double(maxPaddingFrac), C.double(maxBlockingFrac), &fw)
	if result != C.MaybenotResult_Ok {
		return nil, maybenotError(result)
	}
	return &Framework{
		fw:          fw,
		numMachines: C.maybenot_num_machines(fw),
	}, nil
}

// Close frees the maybenot framework.
func (f *Framework) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	C.maybenot_stop(f.fw)
	f.closed = true
}

// onEvents feeds events to maybenot and returns pending actions.
func (f *Framework) onEvents(events []C.MaybenotEvent) []C.MaybenotAction {
	if len(events) == 0 || f.numMachines == 0 {
		return nil
	}
	actions := make([]C.MaybenotAction, int(f.numMachines))
	var numActions C.uintptr_t

	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	C.maybenot_on_events(
		f.fw,
		(*C.MaybenotEvent)(unsafe.Pointer(&events[0])),
		C.uintptr_t(len(events)),
		(*C.MaybenotAction)(unsafe.Pointer(&actions[0])),
		&numActions,
	)
	f.mu.Unlock()

	return actions[:int(numActions)]
}

// NormalSent feeds a NormalSent event (real outgoing data packet).
func (f *Framework) NormalSent() []C.MaybenotAction {
	return f.onEvents([]C.MaybenotEvent{{event_type: C.MaybenotEventType_NormalSent}})
}

// NormalReceived feeds a NormalRecv event (real incoming data packet).
func (f *Framework) NormalReceived() []C.MaybenotAction {
	return f.onEvents([]C.MaybenotEvent{{event_type: C.MaybenotEventType_NormalRecv}})
}

// PaddingSent feeds a PaddingSent event (dummy packet sent).
func (f *Framework) PaddingSent(machine uint) []C.MaybenotAction {
	return f.onEvents([]C.MaybenotEvent{{
		event_type: C.MaybenotEventType_PaddingSent,
		machine:    C.uintptr_t(machine),
	}})
}

// ── Conn wrapper ──────────────────────────────────────────────────────────────

// Conn wraps a net.Conn with DAITA padding injection.
type Conn struct {
	net.Conn
	fw *Framework
}

// Wrap wraps conn with DAITA if fw is non-nil.
func Wrap(conn net.Conn, fw *Framework) net.Conn {
	if fw == nil {
		return conn
	}
	return &Conn{Conn: conn, fw: fw}
}

func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		return n, err
	}
	// Feed real-sent event and handle any pending padding actions.
	actions := c.fw.NormalSent()
	c.handleActions(actions)
	return n, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, err
	}
	// Feed real-received event.
	actions := c.fw.NormalReceived()
	c.handleActions(actions)
	return n, nil
}

func (c *Conn) handleActions(actions []C.MaybenotAction) {
	for _, action := range actions {
		if action.tag == C.MaybenotAction_SendPadding {
			body := (*C.MaybenotAction_SendPadding_Body)(unsafe.Pointer(&action.anon0[0]))
			timeout := toDuration(body.timeout)
			machine := uint(body.machine)
			// Schedule dummy write after timeout.
			time.AfterFunc(timeout, func() {
				c.injectPadding(machine)
			})
		}
		// BlockOutgoing and UpdateTimer are not implemented yet.
	}
}

func (c *Conn) injectPadding(machine uint) {
	// Write a 1-byte dummy payload (low overhead, obscures timing).
	dummy := []byte{0}
	_, err := c.Conn.Write(dummy)
	if err != nil {
		return
	}
	// Feed PaddingSent event back.
	actions := c.fw.PaddingSent(machine)
	c.handleActions(actions)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func toDuration(d C.MaybenotDuration) time.Duration {
	return time.Duration(uint64(d.secs)*uint64(time.Second) + uint64(d.nanos))
}

type maybenotResult = C.MaybenotResult

func maybenotError(r C.MaybenotResult) error {
	switch r {
	case C.MaybenotResult_MachineStringNotUtf8:
		return fmt.Errorf("maybenot: machine string is not valid UTF-8")
	case C.MaybenotResult_InvalidMachineString:
		return fmt.Errorf("maybenot: invalid machine string")
	case C.MaybenotResult_StartFramework:
		return fmt.Errorf("maybenot: failed to start framework")
	case C.MaybenotResult_NullPointer:
		return fmt.Errorf("maybenot: null pointer")
	default:
		return fmt.Errorf("maybenot: unknown error %d", r)
	}
}
