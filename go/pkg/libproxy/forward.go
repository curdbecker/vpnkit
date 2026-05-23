package libproxy

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// service is one entry in the services file.
type service struct {
	Guest string `json:"guest"`
	Host  string `json:"host,omitempty"`
	// not supported yet
	FailFastOnDial bool `json:"failFastOnDial,omitempty"`
	NoopCloseWrite bool `json:"noopCloseWrite,omitempty"`
}

type Services map[string]service

// Load reads and parses the services file at path.
func LoadServices(path string) (Services, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading services file %s: %w", path, err)
	}
	var services Services
	if err := json.Unmarshal(b, &services); err != nil {
		return nil, fmt.Errorf("parsing services file %s: %w", path, err)
	}
	for _, service := range services {
		if service.Host != "" {
			service.Host, _ = strings.CutPrefix(service.Host, "unix://")
		}
	}

	return services, nil
}

// Forward a connection to a given destination.
func Forward(conn Conn, destination Destination, quit <-chan struct{},
	rec *PcapRecorder, services Services, dockerDataPath *string) {
	defer conn.Close()

	log.Printf("forward to %s requested", destination)

	switch destination.Proto {
	case TCP:
		backendAddr := net.TCPAddr{IP: destination.IP, Port: int(destination.Port), Zone: ""}
		if err := HandleTCPConnection(conn, &backendAddr, quit); err != nil {
			log.Printf("closing TCP proxy because %v", err)
			return
		}
	case Unix:
		var destinationPath string
		if services == nil {
			destinationPath = destination.Path
		} else {
			destinationPath = filepath.Join(*dockerDataPath, destination.Path+".sock")
			if service, ok := services[destination.Path]; ok && service.Host != "" {
				destinationPath = service.Host
			}
		}
		log.Printf("forwarding to %s", destinationPath)

		backendAddr, err := net.ResolveUnixAddr("unix", destinationPath)
		if err != nil {
			log.Printf("Error resolving Unix address %s", destinationPath)
			return
		}
		if err := HandleUnixConnection(conn, backendAddr, quit, rec); err != nil {
			log.Printf("closing Unix proxy because %v", err)
			return
		}
	case UDP:
		backendAddr := &net.UDPAddr{IP: destination.IP, Port: int(destination.Port), Zone: ""}
		// copy to and from the backend without using NewUDPProxy
		inside, err := net.DialUDP("udp", nil, backendAddr)
		if err != nil {
			log.Printf("Failed to Dial UDP backend for %s: %v", backendAddr, err)
			return
		}
		log.Printf("accepted UDP connection to %s\n", backendAddr.String())
		one := make(chan struct{})
		two := make(chan struct{})
		go func() {
			copyUDP(fmt.Sprintf("from %s to host", backendAddr.String()), inside, conn)
			close(one)
		}()
		go func() {
			copyUDP(fmt.Sprintf("from host to %s", backendAddr.String()), conn, inside)
			close(two)
		}()
		select {
		case <-quit: // we want to quit
		case <-one: // we get an error like "connection refused"
		case <-two: // we get an error like "connection refused"
		}
		log.Printf("closing UDP connection to %s\n", backendAddr.String())
		_ = inside.Close()
		return
	default:
		log.Printf("Unknown protocol: %d", destination.Proto)
		return
	}
}

func copyUDP(description string, left, right net.Conn) {
	b := make([]byte, UDPBufSize)
	for {
		n, err := left.Read(b)
		if err != nil {
			log.Printf("%s: unable to read UDP: %v", description, err)
			return
		}
		pkt := b[0:n]
		_, err = right.Write(pkt)
		if err != nil {
			log.Printf("%s: unable to write UDP: %v", description, err)
			return
		}
	}
}
