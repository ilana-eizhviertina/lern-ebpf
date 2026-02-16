package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	// This import is for the generated eBPF code. The 'gen' package is created by the bpf2go tool.
	"learn-ebpf/tracepoint/gen"
)

// When we run 'go generate', it runs this command to compile the C code.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir gen -go-package gen Bpf hello.bpf.c

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 1. Load the eBPF program
	objs := gen.BpfObjects{}
	if err := gen.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// 2. Attach to the kernel
	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HelloWorld, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %v", err)
	}
	defer kp.Close()

	log.Println("Counting processes... (Press Ctrl+C to exit)")

	// 3. The Dashboard Loop
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// --- Read the Map ---
		var uid uint32
		var count uint32

		// Iterate over all keys in the "ExecCounts" map
		iter := objs.ExecCounts.Iterate()
		log.Println("-----------------------------")
		for iter.Next(&uid, &count) {
			log.Printf("UID %d has run %d commands", uid, count)
		}

		if err := iter.Err(); err != nil {
			log.Printf("Iterator error: %v", err)
		}
	}
}
