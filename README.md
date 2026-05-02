# ARP SPOOF Tool in Go

A Man-in-the-Middle (MITM) tool written in Go using raw packet manipulation via `gopacket`. Poisons ARP tables on both the victim and gateway, intercepting all traffic transparently.

---

## Usage

Pretty straightforward — just fill in the variables at the top of the code with your network values:

```go
var (
    VICTIM_MAC                    = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    GATEWAY_MAC                   = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    ATTACKERS_MAC                 = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    VICTIM_IP                     = []byte{00, 000, 000, 000}
    GATEWAY_IP                    = []byte{000, 000, 000, 000}
    FORWARD         *bool         = flag.Bool("FORWARD", false, "Use This Flag In Order to Use the Script's Forwarder")
    SPOOF_TIME_STEP time.Duration = 50
    SPOOF_ITERATIONS              = 10000
    INTERFACE_NAME  string        = "<your interface name>"
    sendMu          sync.Mutex
    wg              sync.WaitGroup
)
```

Then run it:

```bash
sudo go run main.go
```

---

## Forwarder

The tool supports two forwarding styles:

### Style 1 — OS Handles Forwarding

Enable forwarding at the OS level and let the kernel do the work:

```bash
# enable ip forwarding
sysctl -w net.ipv4.ip_forward=1

# allow forwarded packets through iptables
iptables -P FORWARD ACCEPT
iptables -F FORWARD
```

### Sytle 2 — Script Handles Forwarding

If you don't want to touch OS settings, use the `-FORWARD` flag and the tool will handle packet forwarding itself via gopacket:

```bash
sudo go run main.go -FORWARD
```

> **Note:** Never enable both at the same time — you will get duplicate packets and broken connections.

---

## Cleanup

When done, restore your OS settings:

```bash
# disable forwarding
sysctl -w net.ipv4.ip_forward=0
iptables -P FORWARD DROP

```

---

## Dependencies

```bash
go get github.com/google/gopacket
sudo apt install libpcap-dev
```

---

## ⚠️ Disclaimer

This tool is for **educational purposes and authorized penetration testing only**. Running this on networks without explicit permission is illegal. The author is not responsible for any misuse.