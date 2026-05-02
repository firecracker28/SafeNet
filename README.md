# SafeNet: Your Network's Security Blanket

> ⚠️ **Disclaimer**: This is a student project and is not intended for production use. Use at your own discretion.

SafeNet is a lightweight tool for analyzing network traffic in real time. It captures packets, stores them in an in-memory database, and provides basic analytics to help identify suspicious activity.

---

## 🚀 Features

- Supports live packet capture and pcap files
- CLI for customizing capture behavior
- captured packets are stored in SQLite database
- Basic analytics: top IPs, Suspicious IP's
- *(Planned)* API functionality

---

## 🛠 Usage

### Command-Line Arguments

- `-MaxBytes`: Maximum packet size to store (default: 1650 bytes)
- `-timeout`: Timeout in seconds before stopping capture if no packets are received
- *(Planned)* `-interface`: Specify the network interface to sniff on

**Example:**
```bash
go run ./internal/cmd/SafeNet/main.go -timeout=30 -MaxBytes=1600
