# CodeAlpha
This Python script is a simple network packet sniffer built using the Scapy library. It captures and analyzes IP-based network packets, displaying details such as source and destination IP addresses, protocol type (TCP, UDP, ICMP, or other).

# Network Packet Sniffer

## Overview
This Python script is a simple network packet sniffer built using the Scapy library. It captures and analyzes IP-based network packets, displaying details such as source and destination IP addresses, protocol type (TCP, UDP, ICMP, or other), and the packet payload in hexadecimal format. The tool is designed for educational purposes, network troubleshooting, or monitoring network traffic.

### Features

Captures IP packets in real-time.
Supports TCP, UDP, and ICMP protocols, with fallback for other protocols.
Displays source and destination IP addresses, protocol type, and payload (truncated to 50 bytes for readability).
Limits capture to 10 packets by default to prevent overwhelming output.
Handles errors gracefully, including permission issues and user interrupts.

#### Requirements

1. **Python 3.x:** Ensure Python is installed on your system.
2. **Scapy:** Install the Scapy library using pip:
 ```bash
   pip install scapy
 ```
2. **Root/Administrator Privileges:** Packet sniffing requires elevated privileges (e.g., `sudo` on Linux or admin rights on Windows).

#### Installation

  **-Clone this repository:** 
  ```bash
       git clone https://github.com/LadanbeFlorand/CodeAlpha.git
  ```
 **-Navigate to the project directory:** 
  ```bash
    cd network-packet-sniffer
  ```

#### Install the required dependencies:pip install scapy

1. **Usage**
Run the script with root/admin privileges to start sniffing packets:
  ```bash
     sudo python3 packet_sniffer.py
  ```

The script captures up to 10 IP packets and displays their details.
Press Ctrl+C to stop the sniffer manually.
Output includes:
Source and destination IP addresses.
Protocol type (e.g., TCP, UDP, ICMP) and protocol number.
Hexadecimal representation of the packet payload (first 50 bytes).

#### Example Output:
```bash
Starting network sniffer... Press Ctrl+C to stop.
Source IP: 192.168.0.126
Destination IP: 142.250.79.10
Protocol: TCP (6)
Payload (hex): No payload
--------------------------------------------------
Source IP: 172.64.146.215
Destination IP: 192.168.0.126
Protocol: UDP (17)
Payload (hex): 58c6d8e83977a63a7b2c77cd9eeeb896e39e79bab3ad3805d51c7b236f48d38b693184e73cb62627743628d99357e80f95db...
--------------------------------------------------
Source IP: 192.168.0.126
Destination IP: 172.64.146.215
Protocol: UDP (17)
Payload (hex): 5c019c3688f44a4d70fc9fe288fb4a760c317003e825ced0eeee859b640f9852eb1b13e2b0f0c6ad5fd75841e4
--------------------------------------------------
Source IP: 142.250.79.10
Destination IP: 192.168.0.126
Protocol: TCP (6)
Payload (hex): No payload
--------------------------------------------------
Source IP: 192.168.0.126
Destination IP: 142.250.79.10
Protocol: TCP (6)
Payload (hex): No payload
--------------------------------------------------
Source IP: 192.168.0.1
Destination IP: 255.255.255.255
Protocol: UDP (17)
Payload (hex): 4b414e4e4f55254e0000000000ec086ba014b8546f7563682050350000000000000000546f75636820503500000000000000...
--------------------------------------------------
```

#### Notes

The script uses a filter (filter="ip") to capture only IP packets.
Promiscuous mode is disabled to avoid capturing unintended traffic.
Payloads longer than 50 bytes are truncated for readability.
Ensure you have permission to monitor the network, as unauthorized sniffing may violate privacy laws or network policies.

#### Limitations

Requires root/admin privileges, which may not be available in all environments.
Currently captures only 10 packets by default (modify the count parameter in the sniff function to change this).
Does not support advanced filtering or packet storage (packets are not saved to disk).

#### License
This project is licensed under the MIT License. See the LICENSE file for details.
Contributing
Contributions are welcome! Please open an issue or submit a pull request with any improvements or bug fixes.
