package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"learn-ebpf/tc/gen"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir gen -go-package gen Bpf tc.bpf.c

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

	// Attach to TCX Egress (Outgoing traffic)
	l, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcEgress,
		Attach:    ebpf.AttachTCXEgress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s\n(Note: If this fails, your Docker kernel might be older than Linux 6.6)", err)
	}
	defer l.Close()

	log.Printf("TC Program attached to %q (Egress)", ifaceName)
	log.Println("Try running 'ping 8.8.8.8' in another terminal.")
	log.Println("Press Ctrl+C to exit...")

	// eBPF programs only stay loaded in the kernel as long as the process that loaded them is still running (unless you "pin" them, which is a more advanced topic).
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
