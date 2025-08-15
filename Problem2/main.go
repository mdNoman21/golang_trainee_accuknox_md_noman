package main

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const interfaceName = "eth0" // Change if needed

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock limit: %v", err)
	}

	// Load the compiled eBPF object file (from filter.c)
	spec, err := ebpf.LoadCollectionSpec("filter.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF object: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["xdp_filter"]
	if prog == nil {
		log.Fatalf("Program xdp_filter not found")
	}

	// Get interface index from name
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Failed to get interface index: %v", err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer link.Close()

	fmt.Println("eBPF program loaded and attached successfully.")
	fmt.Println("Press Ctrl+C to exit.")
	select {} // Wait indefinitely
}
