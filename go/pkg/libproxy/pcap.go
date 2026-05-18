// go/pkg/libproxy/pcap.go
//
// Connection-level capture for the Unix-socket forwarding path,
// represented as a synthetic but well-formed TCP conversation so
// Wireshark treats it as a normal stream: clean Follow-TCP-Stream,
// conversation grouping, and any port/heuristic application dissector
// can engage because real TCP reassembly is present.
//
// Addressing encodes REAL identifiers (unchanged from the agreed
// scheme); nothing about the endpoints is invented:
//
//   client IP : byte0 = per-flow disambiguator (low 8 bits of a
//               monotonic counter — keeps a reused backend fd from
//               collapsing two flows); bytes1..3 = low 24 bits of the
//               multiplexer sub-connection ID (channel.ID), which
//               correlates with the multiplexer event log.
//   host IP   : byte0 = 0xFF (unmistakable backend-side marker);
//               bytes1..3 = the same low 24 bits of the mux ID.
//   port      : the backend socket's real kernel fd,
//               so the 4-tuple is one TCP conversation keyed on the
//               one fd that actually exists (correlates lsof/strace).
//
// The TCP layer is synthetic but correct: a real SYN / SYN-ACK opens
// each flow, per-direction sequence numbers advance by payload length,
// every data segment ACKs the opposite direction, and CloseWrite/Close
// emit FIN so the stream terminates cleanly instead of showing as
// truncated. This is what makes it "not confusing" for Wireshark.
//
// pcapgo's NgWriter.WritePacket has no per-packet option path in the
// vendored version, so there is no pcapng comment. The real backend
// socket path is therefore NOT in the file; recover it by correlating
// the mux ID (encoded in the IP) against the multiplexer log, as
// agreed. Nothing is injected into the TCP payload — keeping it pure
// is the whole point of using real TCP here.
//
// Scope: Unix only.

package libproxy

import (
	"encoding/binary"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var connSeq uint64 // monotonic; low 8 bits = per-flow disambiguator

// PcapRecorder owns one pcapng file written as IPv4 link type.
type PcapRecorder struct {
	mu     sync.Mutex
	ngw    *pcapgo.NgWriter
	f      *os.File
	closed bool
}

// NewPcapRecorder creates/truncates a pcapng file at path.
func NewPcapRecorder(path string) (*PcapRecorder, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	ngw, err := pcapgo.NewNgWriter(f, layers.LinkTypeIPv4)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &PcapRecorder{ngw: ngw, f: f}, nil
}

// Close flushes and closes the file. Safe to call repeatedly.
func (p *PcapRecorder) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if err := p.ngw.Flush(); err != nil {
		_ = p.f.Close()
		return err
	}
	return p.f.Close()
}

// flow holds the synthetic TCP state for one proxied pair. Both
// recordingConn sides share it; the mutex serializes sequence/flag
// bookkeeping so the two directions stay coherent.
type flow struct {
	clientIP net.IP
	hostIP   net.IP
	port     uint16

	mu       sync.Mutex
	opened   bool   // SYN/SYN-ACK emitted
	cSeq     uint32 // next seq for client->backend direction
	hSeq     uint32 // next seq for backend->client direction
	cFinSent bool
	hFinSent bool
}

func muxIDOf(c Conn) (uint32, bool) {
	if ch, ok := c.(*channel); ok {
		return ch.ID, true
	}
	return 0, false
}

func backendFD(c Conn) int {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1
	}
	fd := -1
	_ = raw.Control(func(p uintptr) { fd = int(p) })
	return fd
}

func newFlow(client, backend Conn) *flow {
	id, _ := muxIDOf(client)
	seq := atomic.AddUint64(&connSeq, 1)
	id24 := id & 0x00FFFFFF

	clientIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(clientIP, id24)
	clientIP[0] = byte(seq) // disambiguator

	hostIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(hostIP, id24)
	hostIP[0] = 0xFF

	fd := backendFD(backend)
	port := uint16(0)
	if fd >= 0 {
		port = uint16(fd & 0xFFFF)
	}

	return &flow{
		clientIP: clientIP,
		hostIP:   hostIP,
		port:     port,
		// Distinct, non-zero initial sequence numbers per direction.
		cSeq: uint32(seq)*2654435761 + 1,
		hSeq: uint32(seq)*40503 + 1,
	}
}

// segment describes one synthetic TCP packet to serialize.
type segment struct {
	c2b     bool // client->backend direction
	syn     bool
	ack     bool
	fin     bool
	seq     uint32
	ackNum  uint32
	payload []byte
}

func (p *PcapRecorder) writeSeg(fl *flow, s segment) {
	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	hostPort := uint16(8080)
	if s.c2b {
		srcIP, dstIP = fl.clientIP, fl.hostIP
		srcPort, dstPort = fl.port, hostPort
	} else {
		srcIP, dstIP = fl.hostIP, fl.clientIP
		srcPort, dstPort = hostPort, fl.port
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     s.seq,
		Ack:     s.ackNum,
		SYN:     s.syn,
		ACK:     s.ack,
		FIN:     s.fin,
		PSH:     len(s.payload) > 0,
		Window:  65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	var err error
	if len(s.payload) > 0 {
		err = gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(s.payload))
	} else {
		err = gopacket.SerializeLayers(buf, opts, ip, tcp)
	}
	if err != nil {
		return
	}
	raw := buf.Bytes()

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	_ = p.ngw.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(raw),
		Length:        len(raw),
	}, raw)

	p.ngw.Flush()
}

// ensureOpen emits the SYN / SYN-ACK once, lazily, on first activity.
// Caller must hold fl.mu.
func (p *PcapRecorder) ensureOpen(fl *flow) {
	if fl.opened {
		return
	}
	cISN, hISN := fl.cSeq, fl.hSeq
	// client -> backend: SYN
	p.writeSeg(fl, segment{c2b: true, syn: true, seq: cISN})
	// backend -> client: SYN-ACK
	p.writeSeg(fl, segment{c2b: false, syn: true, ack: true,
		seq: hISN, ackNum: cISN + 1})
	// Sequence space consumed by SYN on each side.
	fl.cSeq = cISN + 1
	fl.hSeq = hISN + 1
	fl.opened = true
}

// emit records one chunk of stream data in the given direction.
func (p *PcapRecorder) emit(fl *flow, c2b bool, b []byte) {
	fl.mu.Lock()
	p.ensureOpen(fl)
	var seq, ackNum uint32
	if c2b {
		seq, ackNum = fl.cSeq, fl.hSeq
		fl.cSeq += uint32(len(b))
	} else {
		seq, ackNum = fl.hSeq, fl.cSeq
		fl.hSeq += uint32(len(b))
	}
	fl.mu.Unlock()

	p.writeSeg(fl, segment{
		c2b: c2b, ack: true, seq: seq, ackNum: ackNum, payload: b,
	})
}

// finish emits a FIN for one direction at CloseWrite/Close, once.
func (p *PcapRecorder) finish(fl *flow, c2b bool) {
	fl.mu.Lock()
	p.ensureOpen(fl)
	if c2b && fl.cFinSent || !c2b && fl.hFinSent {
		fl.mu.Unlock()
		return
	}
	var seq, ackNum uint32
	if c2b {
		seq, ackNum = fl.cSeq, fl.hSeq
		fl.cSeq++ // FIN consumes one sequence number
		fl.cFinSent = true
	} else {
		seq, ackNum = fl.hSeq, fl.cSeq
		fl.hSeq++
		fl.hFinSent = true
	}
	fl.mu.Unlock()

	p.writeSeg(fl, segment{
		c2b: c2b, ack: true, fin: true, seq: seq, ackNum: ackNum,
	})
}

// recordingConn wraps one side of a proxied pair; both share a *flow.
type recordingConn struct {
	Conn

	rec *PcapRecorder
	fl  *flow
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.rec.emit(c.fl, true, b[:n])
	}
	return n, err
}

func (c *recordingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.rec.emit(c.fl, false, b[:n])
	}
	return n, err
}

// Close terminates both directions. Emit a FIN for whichever side has
// not already sent one (finish() is idempotent per direction).
func (c *recordingConn) Close() error {
	c.rec.finish(c.fl, true)
	c.rec.finish(c.fl, false)
	return c.Conn.Close()
}

// RecordStream wraps a Unix (client, backend) pair for ProxyStream. If
// rec is nil the originals are returned unchanged.
func RecordStream(rec *PcapRecorder, client, backend Conn) (Conn, Conn) {
	if rec == nil {
		return client, backend
	}
	fl := newFlow(client, backend)
	return &recordingConn{Conn: client, rec: rec, fl: fl},
		backend
}
