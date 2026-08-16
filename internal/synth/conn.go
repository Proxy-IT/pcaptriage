package synth

import (
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
)

// Conn is a TCP conversation being synthesised. It tracks sequence and
// acknowledgement numbers for both sides so fixtures can be written in terms
// of what happened rather than in terms of header fields.
type Conn struct {
	b              *Builder
	client, server string

	// cseq and sseq are each side's next sequence number.
	cseq, sseq uint32
	// cwin and swin are each side's most recently advertised window, reused
	// when a call does not specify one.
	cwin, swin uint16
}

// ConnOpts configure a synthesised conversation.
type ConnOpts struct {
	// Client and Server are "addr:port".
	Client, Server string
	// ClientISN and ServerISN are the initial sequence numbers.
	ClientISN, ServerISN uint32
	// ClientWindow and ServerWindow are the initial advertised windows.
	ClientWindow, ServerWindow uint16
}

// NewConn starts a conversation. It emits no frames on its own.
func (b *Builder) NewConn(o ConnOpts) *Conn {
	if o.ClientWindow == 0 {
		o.ClientWindow = 65535
	}
	if o.ServerWindow == 0 {
		o.ServerWindow = 65535
	}
	return &Conn{
		b:      b,
		client: o.Client,
		server: o.Server,
		cseq:   o.ClientISN,
		sseq:   o.ServerISN,
		cwin:   o.ClientWindow,
		swin:   o.ServerWindow,
	}
}

// Handshake emits SYN, SYN/ACK and ACK. The SYN/ACK lands rtt after the SYN,
// which is the handshake round-trip the analysis will measure, and the final
// ACK a further rtt/2 later.
//
// Both SYNs carry a window scale option, so the flow is COMPLETE and its
// window scale is known.
func (c *Conn) Handshake(at, rtt time.Duration) {
	c.b.AddTCP(TCPSpec{
		At: at, Src: c.client, Dst: c.server,
		Seq: c.cseq, Flags: capture.FlagSYN, Window: c.cwin, WindowScale: 7,
	})
	c.b.AddTCP(TCPSpec{
		At: at + rtt, Src: c.server, Dst: c.client,
		Seq: c.sseq, Ack: c.cseq + 1,
		Flags: capture.FlagSYN | capture.FlagACK, Window: c.swin, WindowScale: 7,
	})
	c.cseq++
	c.sseq++
	c.b.AddTCP(TCPSpec{
		At: at + rtt + rtt/2, Src: c.client, Dst: c.server,
		Seq: c.cseq, Ack: c.sseq, Flags: capture.FlagACK, Window: c.cwin,
	})
}

// ClientData emits n payload bytes from the client.
func (c *Conn) ClientData(at time.Duration, n int) {
	c.b.AddTCP(TCPSpec{
		At: at, Src: c.client, Dst: c.server,
		Seq: c.cseq, Ack: c.sseq,
		Flags: capture.FlagPSH | capture.FlagACK, Window: c.cwin,
		WindowScale: -1, PayloadLen: n,
	})
	c.cseq += uint32(n)
}

// ServerData emits n payload bytes from the server.
func (c *Conn) ServerData(at time.Duration, n int) {
	c.b.AddTCP(TCPSpec{
		At: at, Src: c.server, Dst: c.client,
		Seq: c.sseq, Ack: c.cseq,
		Flags: capture.FlagPSH | capture.FlagACK, Window: c.swin,
		WindowScale: -1, PayloadLen: n,
	})
	c.sseq += uint32(n)
}

// ClientAck emits a pure ACK from the client advertising win.
func (c *Conn) ClientAck(at time.Duration, win uint16) {
	c.cwin = win
	c.b.AddTCP(TCPSpec{
		At: at, Src: c.client, Dst: c.server,
		Seq: c.cseq, Ack: c.sseq,
		Flags: capture.FlagACK, Window: win, WindowScale: -1,
	})
}

// ServerAck emits a pure ACK from the server advertising win. A win of zero is
// how a fixture expresses a receiver that has stopped accepting data.
func (c *Conn) ServerAck(at time.Duration, win uint16) {
	c.swin = win
	c.b.AddTCP(TCPSpec{
		At: at, Src: c.server, Dst: c.client,
		Seq: c.sseq, Ack: c.cseq,
		Flags: capture.FlagACK, Window: win, WindowScale: -1,
	})
}

// ClientWindowProbe emits a one-byte probe from the client, as a sender does
// when the receiver's window is closed. The byte is outside the receiver's
// window so it does not advance the sequence number.
func (c *Conn) ClientWindowProbe(at time.Duration) {
	c.b.AddTCP(TCPSpec{
		At: at, Src: c.client, Dst: c.server,
		Seq: c.cseq, Ack: c.sseq,
		Flags: capture.FlagACK, Window: c.cwin, WindowScale: -1, PayloadLen: 1,
	})
}

// FinClose emits a clean four-way teardown initiated by the client.
func (c *Conn) FinClose(at time.Duration, step time.Duration) {
	c.b.AddTCP(TCPSpec{
		At: at, Src: c.client, Dst: c.server,
		Seq: c.cseq, Ack: c.sseq,
		Flags: capture.FlagFIN | capture.FlagACK, Window: c.cwin, WindowScale: -1,
	})
	c.cseq++
	c.b.AddTCP(TCPSpec{
		At: at + step, Src: c.server, Dst: c.client,
		Seq: c.sseq, Ack: c.cseq,
		Flags: capture.FlagFIN | capture.FlagACK, Window: c.swin, WindowScale: -1,
	})
	c.sseq++
	c.b.AddTCP(TCPSpec{
		At: at + 2*step, Src: c.client, Dst: c.server,
		Seq: c.cseq, Ack: c.sseq,
		Flags: capture.FlagACK, Window: c.cwin, WindowScale: -1,
	})
}

// ServerReset emits a RST from the server.
func (c *Conn) ServerReset(at time.Duration) {
	c.b.AddTCP(TCPSpec{
		At: at, Src: c.server, Dst: c.client,
		Seq: c.sseq, Ack: c.cseq,
		Flags: capture.FlagRST | capture.FlagACK, Window: 0, WindowScale: -1,
	})
}
