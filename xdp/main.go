package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"learn-ebpf/xdp/gen"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir gen -go-package gen Bpf xdp.bpf.c

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := gen.BpfObjects{}
	if err := gen.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// The kernel needs to know where to watch traffic.
	// We can attach to different network interfaces, and the choice of interface determines what traffic we see.
	// lo  ->   Internal (Self)	    -> Testing, internal APIs, inter-process communication.
	// eth0 ->   External (Other)	-> Internet traffic, external APIs, communication with other machines.
	ifaceName := "eth0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %s: %s", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.PingDrop,
		Interface: iface.Index,
		// Force Generic XDP mode to ensure compatibility with Docker/Virtual interfaces
		Flags: link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("XDP Program attached to %q (Index %d)", iface.Name, iface.Index)
	log.Println("Try running 'ping 127.0.0.1' in another terminal.")
	log.Println("Press Ctrl+C to exit and restore ping access...")

	// eBPF programs only stay loaded in the kernel as long as the process that loaded them is still running (unless you "pin" them, which is a more advanced topic).
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
