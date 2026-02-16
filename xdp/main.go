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

	ifaceName := "lo"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %s: %s", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.PingDrop,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("XDP Program attached to %q (Index %d)", iface.Name, iface.Index)
	log.Println("Try running 'ping 127.0.0.1' in another terminal.")
	log.Println("Press Ctrl+C to exit and restore ping access...")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
