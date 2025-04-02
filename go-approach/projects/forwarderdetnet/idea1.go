package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/asavie/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var globalVariable int
var lock sync.Mutex

// __________________________________________  PACKET QUEUES  __________________________________________

type PacketQueue struct {
	Queues [][][]byte // A slice of slices, where each inner slice is a queue of frames
}

func Createqueues(numberOfQueues int) *PacketQueue {
	packetQueue := &PacketQueue{
		Queues: make([][][]byte, numberOfQueues),
	}

	// Initialize each queue
	for i := range packetQueue.Queues {
		packetQueue.Queues[i] = make([][]byte, 0)
	}

	return packetQueue
}

func (pq *PacketQueue) AddPacket(queueIndex int, frame []byte) {
	if queueIndex < 0 || queueIndex >= len(pq.Queues) {
		return
	}
	pq.Queues[queueIndex] = append(pq.Queues[queueIndex], frame)
}

func (pq *PacketQueue) GetPackets(queueIndex int) [][]byte {
	if queueIndex < 0 || queueIndex >= len(pq.Queues) {
		return [][]byte{}
	}
	return pq.Queues[queueIndex]
}

// __________________________________________  INTERFACE MANAGEMENT  __________________________________________

func restartNetworkInterface(iface string) error {
	downCmd := exec.Command("sudo", "ip", "link", "set", iface, "down")
	if err := downCmd.Run(); err != nil {
		return fmt.Errorf("error al apagar la interfaz %s: %v", iface, err)
	}
	time.Sleep(1 * time.Second)

	upCmd := exec.Command("sudo", "ip", "link", "set", iface, "up")
	if err := upCmd.Run(); err != nil {
		return fmt.Errorf("error al encender la interfaz %s: %v", iface, err)
	}
	time.Sleep(1 * time.Second)
	log.Printf("Interface %s restarted", iface)

	vlanoffload := exec.Command("sudo", "ethtool", "-K", iface, "rx-vlan-offload", "off", "tx-vlan-offload", "off")
	if err := vlanoffload.Run(); err != nil {
		return fmt.Errorf("error al desactivar hardware offloading en la interfaz %s: %v", iface, err)
	}
	time.Sleep(1 * time.Second)
	return nil
}

func readInterfacesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	var interfaces []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		interfaces = append(interfaces, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	return interfaces, nil
}

// __________________________________________  MAIN  __________________________________________

func main() {
	var queues int
	var verbose bool

	flag.IntVar(&queues, "queues", 0, "Number of queues (between 1 and 6).")
	flag.BoolVar(&verbose, "verbose", false, "Output forwarding statistics.")
	flag.Parse()

	if queues == 0 {
		log.Fatalf("Error: The 'queues' flag must be between 1 and 6.")
	}

	interfaces, err := readInterfacesFromFile("ifaces")
	if err != nil {
		log.Fatalf("failed to read interfaces from file: %v", err)
	}

	// Require at least two interfaces for forwarding
	if len(interfaces) < 2 {
		log.Fatalf("Error: The file must contain at least 2 interfaces, found %d", len(interfaces))
	}

	var links []netlink.Link
	for _, ifaceName := range interfaces {
		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			log.Fatalf("failed to fetch info about link %s: %v", ifaceName, err)
		}
		links = append(links, link)

		log.Printf("Restarting interface %s...", ifaceName)
		if err := restartNetworkInterface(ifaceName); err != nil {
			log.Fatalf("Error restarting the interface %s: %v", ifaceName, err)
		}
	}

	globalVariable = 1
	go updateGlobalVariable(queues)

	launchswitch(verbose, links, queues)
}

func updateGlobalVariable(queues int) {
	ticker := time.NewTicker(10 * time.Millisecond)
	for {
		select {
		case <-ticker.C:
			lock.Lock()
			currentTime := time.Now().UnixNano() / int64(time.Millisecond)
			cycleDuration := int64(10) // cycle duration in ms
			currentCycle := (currentTime / cycleDuration) % int64(queues)
			globalVariable = int(currentCycle) + 1
			lock.Unlock()
		}
	}
}

// __________________________________________  TSN SWITCH  __________________________________________

func launchswitch(verbose bool, links []netlink.Link, queues int) {
	var Xsks []*xdp.Socket
	for _, link := range links {
		log.Printf("Attaching XDP program for %s...", link.Attrs().Name)
		Prog, err := xdp.LoadProgram("ebpf.o", "xdp_redirect", "qidconf_map", "xsks_map")
		if err != nil {
			log.Fatalf("failed to load xdp program: %v", err)
		}
		if err := Prog.Attach(link.Attrs().Index); err != nil {
			log.Fatalf("failed to attach xdp program to interface: %v", err)
		}
		defer Prog.Detach(link.Attrs().Index)

		log.Printf("Opening XDP socket for %s...", link.Attrs().Name)
		Xsk, err := xdp.NewSocket(link.Attrs().Index, 0, nil)
		if err != nil {
			log.Fatalf("failed to open XDP socket for link %s: %v", link.Attrs().Name, err)
		}

		log.Printf("Registering XDP socket for %s...", link.Attrs().Name)
		// Use unique key per interface (0 for the first, 1 for the second)
		key := 0
		if len(Xsks) > 0 {
			key = 1
		}
		if err := Prog.Register(key, Xsk.FD()); err != nil {
			fmt.Printf("error: failed to register socket in BPF map: %v\n", err)
			return
		}
		defer Prog.Unregister(key)
		Xsks = append(Xsks, Xsk)
	}

	log.Printf("XDP deployed...")
	detnet_init("./config/detnetData.json", "./config/newFlows.json")
	log.Printf("Detnet deployed...")
	log.Printf("Starting TSN Switch...")

	packetQueues := Createqueues(queues)
	log.Printf("Created %d queues", len(packetQueues.Queues))

	var numBytesTotal uint64
	var numFramesTotal uint64
	if verbose {
		go func() {
			var numBytesPrev, numFramesPrev uint64
			var numBytesNow, numFramesNow uint64
			for {
				numBytesPrev = numBytesNow
				numFramesPrev = numFramesNow
				time.Sleep(1 * time.Second)
				numBytesNow = numBytesTotal
				numFramesNow = numFramesTotal
				pps := numFramesNow - numFramesPrev
				bps := (numBytesNow - numBytesPrev) * 8
				log.Printf("%9d pps / %6d Mbps", pps, bps/1000000)
			}
		}()
	}

	// Launch a separate goroutine for each interface, each with its own polling structure.
	for _, xsk := range Xsks {
		go func(xsk *xdp.Socket) {
			localFds := []unix.PollFd{{Fd: int32(xsk.FD())}}
			for {
				xsk.Fill(xsk.GetDescs(xsk.NumFreeFillSlots(), true))
				localFds[0].Events = unix.POLLIN
				if xsk.NumTransmitted() > 0 {
					localFds[0].Events |= unix.POLLOUT
				}
				localFds[0].Revents = 0

				_, err := unix.Poll(localFds, -1)
				if err == syscall.EINTR {
					continue
				} else if err != nil {
					fmt.Fprintf(os.Stderr, "poll failed: %v\n", err)
					os.Exit(1)
				}

				if (localFds[0].Revents & unix.POLLIN) != 0 {
					numBytes, numFrames := forwardFrames4(xsk, Xsks, packetQueues)
					numBytesTotal += numBytes
					numFramesTotal += numFrames
				}
				if (localFds[0].Revents & unix.POLLOUT) != 0 {
					xsk.Complete(xsk.NumCompleted())
				}
			}
		}(xsk)
	}

	// Block main thread indefinitely
	select {}
}

// __________________________________________  PACKET FORWARDING  __________________________________________

func forwardFrames4(input *xdp.Socket, Xsks []*xdp.Socket, packetQueues *PacketQueue) (numBytes uint64, numFrames uint64) {
	var output *xdp.Socket
	// For exactly two interfaces, use the other socket as the output.
	if len(Xsks) == 2 {
		if input == Xsks[0] {
			output = Xsks[1]
		} else {
			output = Xsks[0]
		}
	} else {
		output = input // Fallback if not exactly 2 interfaces.
	}

	inDescs := input.Receive(input.NumReceived())
	outDescs := output.GetDescs(output.NumFreeTxSlots(), false)

	if len(inDescs) > len(outDescs) {
		inDescs = inDescs[:len(outDescs)]
	}
	numFrames = uint64(len(inDescs))

	for i := 0; i < len(inDescs); i++ {
		inFrame := input.GetFrame(inDescs[i])
		Frame2send := detnet(inFrame)
		outFrame := output.GetFrame(outDescs[i])
		numBytes += uint64(len(Frame2send))
		outDescs[i].Len = uint32(copy(outFrame, Frame2send))
	}
	outDescs = outDescs[:len(inDescs)]
	output.Transmit(outDescs)

	return
}

// __________________________________________  HELPER FUNCTIONS  __________________________________________

// The rest of your helper functions (enqueueframe, clearqueues, getPriority, isVLAN, getVLANID) remain unchanged.

func getPriority(frame []byte) (int, error) {
	priority := -1
	if isVLAN(frame) {
		vlanID, err := getVLANID(frame)
		if err != nil {
			return -1, err
		}
		log.Printf("VLAN DETECTED: %d", vlanID)
		priority = vlanID - 9
	} else {
		priority = 1 // default priority for non-VLAN packets
	}
	return priority, nil
}

func isVLAN(frame []byte) bool {
	if len(frame) >= 16 {
		ethertype := (uint16(frame[12]) << 8) | uint16(frame[13])
		return ethertype == 0x8100
	}
	return false
}

func getVLANID(frame []byte) (int, error) {
	if len(frame) < 18 {
		return 0, fmt.Errorf("frame demasiado corto para ser un paquete VLAN")
	}
	vlanID := (int(frame[14])<<8 | int(frame[15])) & 0x0FFF
	return vlanID, nil
}
