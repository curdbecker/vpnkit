package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime/pprof"
	"syscall"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit/control"
	"github.com/moby/vpnkit/go/pkg/vpnkit/http"
)

var (
	controlListen       string
	bridgeFdConnect     string
	dataListen          string
	dataListenFd        string
	dataListenHandshake string
	dataConnect         string
	dockerDataPath      string
	pcap                string
	servicesFile        string
	debug               bool
)

func getDefaultDockerPath() string {
	user, err := user.Current()
	if err != nil {
		return ""
	}
	return filepath.Join(user.HomeDir, "/Library/Containers/com.docker.docker/Data/")
}

// Listen on either AF_VSOCK or AF_HVSOCK (depending on the kernel) for multiplexed connections
func main() {
	flag.StringVar(&controlListen, "control-listen", "", "AF_VSOCK port or socket/Pipe path to listen for control connections")
	flag.StringVar(&dataListen, "data-listen", "", "AF_VSOCK port or socket/Pipe path to listen for data connections on")
	flag.StringVar(&dataListenFd, "data-listen-fd", "",
		"AF_VSOCK port or socket/Pipe path to listen to receive data connection multiplexing fds from com.docker.virtualization (requires services file)")
	flag.StringVar(&dataListenHandshake, "data-listen-handshake", "",
		"AF_VSOCK port or socket/Pipe path to listen to receive connection from docker's vpnkit daemon inside the VM (requires services file) (same data-listen-fd just without fd)")
	flag.StringVar(&dataConnect, "data-connect", "", "AF_VSOCK port or socket/Pipe path to connect to on the host for data connections")
	flag.StringVar(&dockerDataPath, "docker-data-path", getDefaultDockerPath(),
		"path to docker data directory with UNIX sockets (default: ~/Library/Containers/com.docker.docker/Data/)")
	flag.StringVar(&bridgeFdConnect, "bridge-fd-connect", "", "connect to to docker's upstream bridge-fd socket at the given path to retrieve services")
	flag.StringVar(&pcap, "pcap", "", "PCAP file path")
	flag.StringVar(&servicesFile, "services", "", "path to a services JSON file")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()
	if dataListen == "" && dataListenFd == "" && dataListenHandshake == "" && dataConnect == "" {
		log.Fatal("You must provide either -data-listen or -data-listen-fd or -data-listen-handshake or -data-connect to establish a data connection")
	}

	quit := make(chan struct{})
	defer close(quit)

	var err error

	var rec *libproxy.PcapRecorder
	if pcap != "" {
		rec, err = libproxy.NewPcapRecorder(pcap)
		if err != nil {
			log.Fatal(err)
		}
		defer rec.Close()
	}

	var services libproxy.Services
	if dataListenFd != "" || dataListenHandshake != "" {
		if bridgeFdConnect == "" && servicesFile == "" {
			log.Fatalf("must provide either services file or bridge-fd socket with -data-listen-fd")
		}
		if dockerDataPath == "" {
			log.Fatalf("must provide valid -docker-data-path")
		}

		if bridgeFdConnect != "" {
			services, err = control.ConnectForServices(bridgeFdConnect)
			if err != nil {
				log.Fatalf("failed to retrieve services from bridge-fd socket: %s", err)
			}
		} else {
			services, err = libproxy.LoadServices(servicesFile)
			if err != nil {
				log.Fatalf("reading services file %s: %s", servicesFile, err)
			}
		}
		log.Printf("services: %s", services.String())
	}

	ctrl := control.MakeWithOptions(rec, services, &dockerDataPath)

	if controlListen != "" {
		s, err := http.NewServer(controlListen, ctrl)
		if err != nil {
			log.Fatalf("unable to create a control server on %s: %s", controlListen, err)
		}
		s.Start()
	} else {
		log.Println("Not starting a control server")
	}

	if dataListen != "" {
		go ctrl.Listen(dataListen, false, false, quit)
	}
	if dataListenFd != "" {
		go ctrl.Listen(dataListenFd, true, true, quit)
	}
	if dataListenHandshake != "" {
		go ctrl.Listen(dataListenHandshake, false, true, quit)
	}
	if dataConnect != "" {
		go func() {
			if err := ctrl.Connect(dataConnect, false, quit); err != nil {
				fmt.Printf("unable to connect data on %s: %s\n", dataConnect, err)
			}
		}()
	}
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for {
			<-c
			log.Println("Writing profiles to current directory")
			for _, profile := range pprof.Profiles() {
				filename := filepath.Join(os.TempDir(), profile.Name()+".profile")
				log.Printf("Writing %s", filename)
				f, err := os.Create(filename)
				if err != nil {
					log.Fatalf("unable to create %s: %v", filename, err)
				}
				if err := profile.WriteTo(f, 2); err != nil {
					log.Fatalf("writing profile: %s", err)
				}
				f.Close()
			}
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	log.Println("Interrupt received, shutting down")
}
