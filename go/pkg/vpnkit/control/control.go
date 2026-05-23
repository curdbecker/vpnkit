package control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/moby/vpnkit/go/pkg/vpnkit/forward"
	"github.com/moby/vpnkit/go/pkg/vpnkit/log"
	"github.com/moby/vpnkit/go/pkg/vpnkit/transport"
)

type Control struct {
	Forwarder      forward.Maker // Forwarder makes local port forwards
	mux            libproxy.Multiplexer
	muxM           sync.Mutex
	muxC           *sync.Cond
	forwards       map[string]forward.Forward
	forwardsM      sync.Mutex
	rec            *libproxy.PcapRecorder // nil unless pcap set
	services       libproxy.Services
	dockerDataPath *string
}

func Make() *Control {
	return MakeWithOptions(nil, nil, nil)
}

func MakeWithOptions(rec *libproxy.PcapRecorder, services libproxy.Services, dockerDataPath *string) *Control {
	c := &Control{
		forwards:       make(map[string]forward.Forward),
		rec:            rec,
		services:       services,
		dockerDataPath: dockerDataPath,
	}
	c.muxC = sync.NewCond(&c.muxM)
	return c
}

func (c *Control) PcapRecorder() *libproxy.PcapRecorder {
	return c.rec
}

func (c *Control) SetMux(m libproxy.Multiplexer) {
	c.muxM.Lock()
	defer c.muxM.Unlock()
	log.Println("established connection to vpnkit-forwarder")
	c.mux = m
	c.muxC.Broadcast()
}

func (c *Control) Mux() libproxy.Multiplexer {
	c.muxM.Lock()
	defer c.muxM.Unlock()
	for {
		if c.mux != nil {
			return c.mux
		}
		c.muxC.Wait()
	}
}

func portKey(port *vpnkit.Port) string {
	return port.String()
}

func (c *Control) Expose(_ context.Context, port *vpnkit.Port) error {
	if port == nil {
		return errors.New("cannot expose a nil Port")
	}
	key := portKey(port)
	c.forwardsM.Lock()
	defer c.forwardsM.Unlock()
	if _, ok := c.forwards[key]; ok {
		// ensure Expose is idempotent
		return nil
	}
	forward, err := c.Forwarder.Make(c, *port)
	if err != nil {
		// This error (e.g. EADDRINUSE) is special and we want to show it to the user
		return &vpnkit.ExposeError{
			Message: err.Error(),
		}
	}
	// If the request port was 0 (meaning any) we should use the concrete port
	// in the table so that we can `Unexpose()` the results of `ListExposed()`.
	resolvedPort := forward.Port()
	key = portKey(&resolvedPort)
	c.forwards[key] = forward
	go forward.Run()
	return nil
}

func (c *Control) Unexpose(_ context.Context, port *vpnkit.Port) error {
	if port == nil {
		return errors.New("cannot unexpose a nil Port")
	}
	key := portKey(port)
	c.forwardsM.Lock()
	defer c.forwardsM.Unlock()
	forward, ok := c.forwards[key]
	if !ok {
		// make it idempotent
		return nil
	}
	forward.Stop()
	delete(c.forwards, key)
	return nil
}

func (c *Control) ListExposed(_ context.Context) ([]vpnkit.Port, error) {
	c.forwardsM.Lock()
	defer c.forwardsM.Unlock()
	var results []vpnkit.Port
	for _, forward := range c.forwards {
		results = append(results, forward.Port())
	}
	return results, nil
}

func (c *Control) DumpState(_ context.Context, w io.Writer) error {
	m := c.Mux()
	m.DumpState(w)
	return nil
}

var _ vpnkit.Implementation = &Control{}
var _ vpnkit.Control = &Control{}

// recvFD reads one SCM_RIGHTS-bearing message from uc, returning the
// first socket-type fd. Any other fds in the message are closed.
func recvFD(uc *net.UnixConn) (int, error) {
	// One dummy byte of payload — recvmsg won't surface cmsg without it.
	data := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4*16)) // up to 16 fds, generous
	_, oobn, _, _, err := uc.ReadMsgUnix(data, oob)
	if err != nil {
		return -1, err
	}
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("ParseSocketControlMessage: %w", err)
	}
	chosen := -1
	for _, scm := range scms {
		if scm.Header.Level != syscall.SOL_SOCKET || scm.Header.Type != syscall.SCM_RIGHTS {
			continue
		}
		fds, err := syscall.ParseUnixRights(&scm)
		if err != nil {
			return -1, fmt.Errorf("ParseUnixRights: %w", err)
		}
		for _, fd := range fds {
			if chosen < 0 && isSocket(fd) {
				chosen = fd
				continue
			}
			_ = syscall.Close(fd)
		}
	}
	if chosen < 0 {
		return -1, errors.New("no socket fd in SCM_RIGHTS message")
	}
	return chosen, nil
}

func isSocket(fd int) bool {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return false
	}
	return st.Mode&syscall.S_IFMT == syscall.S_IFSOCK
}

// handshake performs the services key/length/JSON exchange. Endianness
// is little-endian to match the C reference (which writes raw uint32_t
// bytes with memcpy).
func handshake(conn io.ReadWriteCloser, services libproxy.Services) error {
	servicesMsg, err := json.Marshal(services)
	if err != nil {
		return fmt.Errorf("unable to serialize services back to JSON: %s", err)
	}

	var key uint32
	if err := binary.Read(conn, binary.LittleEndian, &key); err != nil {
		return fmt.Errorf("read services key: %w", err)
	}
	log.Printf("services key: 0x%08x", key)

	if err := binary.Write(conn, binary.LittleEndian, uint32(len(servicesMsg))); err != nil {
		return fmt.Errorf("write services length: %w", err)
	}
	if _, err := conn.Write(servicesMsg); err != nil {
		return fmt.Errorf("write services message: %w", err)
	}
	log.Printf("sent services message: %d byte(s)", len(servicesMsg))
	return nil
}

// Listen for incoming data connections
func (c *Control) Listen(path string, fd bool, doHandshake bool, quit <-chan struct{}) {
	t := transport.Choose(path)
	l, err := t.Listen(path)
	if err != nil {
		log.Fatalf("unable to create a data server on %s %s: %s", t.String(), path, err)
	}
	c.ListenOnListener(l, fmt.Sprintf("%s %s", t.String(), path), fd, doHandshake, quit)
}

// receives a socket fd via SCM_RIGHTS, acks one byte, and
// reconstructs a net.Conn around the received fd.
func (c *Control) receiveFdConn(conn net.Conn) (net.Conn, error) {

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("accepted conn is %T, not *net.UnixConn", conn)
	}
	fd, err := recvFD(uc)
	if err != nil {
		return nil, fmt.Errorf("recv fd: %w", err)
	}

	// Ack with one byte (matches the C tool's value 253).
	if _, err := conn.Write([]byte{253}); err != nil {
		// Best-effort: the peer may close the control immediately;
		// if it does, ack delivery is irrelevant.
		log.Printf("warning: ack write failed: %v", err)
	}

	// Reconstruct a net.Conn around the received fd. os.NewFile takes
	// ownership; net.FileConn dups the fd internally and we close the
	// original via file.Close().
	file := os.NewFile(uintptr(fd), "vpnkit-data-fd")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("os.NewFile(fd=%d) failed", fd)
	}
	newConn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("net.FileConn: %w", err)
	}
	log.Printf("received data fd")

	return newConn, nil
}

// ListenOnListener listen for incoming data connections on an already setup listener
func (c *Control) ListenOnListener(l net.Listener, listenerName string,
	fd bool, doHandshake bool, quit <-chan struct{}) {
	for {
		// listen for one connection at a time
		log.Printf("listening on %s for data connection", listenerName)
		conn, err := l.Accept()
		if err != nil {
			log.Printf("unable to accept connection on %s: %s", listenerName, err)
			continue
		}
		if fd {
			conn, err = c.receiveFdConn(conn)
			if err != nil {
				log.Printf("unable to receive fd on %s: %s", listenerName, err)
				continue
			}
		}
		log.Printf("accepted data connection on %s", listenerName)
		c.handleDataConn(conn, quit, false, fd || doHandshake)
	}
}

// Connect a data connection
func (c *Control) Connect(path string, doHandshake bool, quit <-chan struct{}) error {
	for {
		conn := c.connectOnce(path, quit)
		c.handleDataConn(conn, quit, true, doHandshake)
		// Since there is no initial handshake in t.Dial, sometimes it can connect() successfully
		// and then handleDataConn immediately returns with an EOF. We need to avoid spinning.
		log.Printf("data connection closed. Will reconnect in 1s.")
		time.Sleep(time.Second)
	}
}

func (c *Control) connectOnce(path string, quit <-chan struct{}) net.Conn {
	var lastLog time.Time
	start := time.Now()
	t := transport.Choose(path)
	log.Printf("dialing %s %s for data connection", t.String(), path)
	for {
		conn, err := t.Dial(context.Background(), path)
		if err == nil {
			log.Printf("connected data connection on %s %s after %s", t.String(), path, time.Since(start))
			return conn
		}
		// This can happen if the server is restarting
		if time.Since(lastLog) > 30*time.Second {
			log.Printf("unable to connect data on %s %s after %s: %s. Is the server restarting? Will retry every 1s.", t.String(), path, time.Since(start), err)
			lastLog = time.Now()
		}
		time.Sleep(time.Second)
	}
}

// handle data-plane forwarding
func (c *Control) handleDataConn(rw io.ReadWriteCloser, quit <-chan struct{}, allocateBackward bool, doHandshake bool) {
	defer rw.Close()

	if doHandshake {
		if err := handshake(rw, c.services); err != nil {
			log.Errorf("unable to perform handshake: %v", err)
		}
	}

	mux, err := libproxy.NewMultiplexer("local", rw, allocateBackward)
	if err == io.EOF || errors.Is(err, syscall.EPIPE) {
		// EOF is uninteresting: probably someone connected to the socket and disconnected again.
		return
	}
	if err != nil {
		log.Errorf("error accepting multiplexer data connection: %v", err)
		return
	}
	mux.Run()
	c.SetMux(mux)
	defer c.SetMux(nil)
	for {
		conn, destination, err := mux.Accept()
		if err == io.EOF || errors.Is(err, syscall.EPIPE) {
			// Not an error because this happens when we're shutting everything down.
			return
		}
		if err == libproxy.ErrNotRunning {
			// Not an error because this happens when we're shutting everything down.
			log.Println("connection multiplexer has shutdown")
			return
		}
		if err != nil {
			log.Errorf("error accepting subconnection: %v", err)
			return
		}
		go libproxy.Forward(conn, *destination, quit, c.rec, c.services, c.dockerDataPath)
	}
}
