\# Advanced Network Sniffer \& Scanner



A high-performance network monitoring and analysis tool developed using Java 17 and the Pcap4j library. This application provides real-time packet inspection, protocol analysis, and traffic statistics with a clean JavaFX interface.



\## Key Features



\- \*\*Live Packet Capture:\*\* Real-time monitoring of traffic on selected network interfaces.

\- \*\*Protocol Deep Dive:\*\* Detailed parsing for TCP, UDP, ICMP, and ARP protocols.

\- \*\*HTTP Inspection:\*\* Capture and parse GET/POST requests (URL, Headers, Methods) on ports 80/8080.

\- \*\*ARP Device Scanner:\*\* Automatically list active network devices with their IP and MAC addresses.

\- \*\*BPF Filtering:\*\* Support for Berkeley Packet Filters (e.g., `tcp port 443`, `icmp`).

\- \*\*Pcap Export:\*\* Option to save captured traffic into `.pcap` files for later analysis in tools like Wireshark.

\- \*\*Real-time Statistics:\*\* Dashboard for total packets, PPS (Packets Per Second), protocol distribution, and total data throughput.

\- \*\*Modern UI:\*\* Responsive JavaFX table view and control panel.



\## Requirements



\- \*\*Java:\*\* 17 or higher.

\- \*\*Build Tool:\*\* Maven.

\- \*\*Drivers (Mandatory):\*\*

&nbsp; - \*\*Windows:\*\* \[Npcap](https://npcap.com/#download) (Select "Install Npcap in WinPcap API-compatible Mode" during setup).

&nbsp; - \*\*Linux:\*\* `libpcap-dev` library.



\## Installation \& Usage



1\. Clone the repository:

&nbsp;  ```bash

&nbsp;  git clone \[https://github.com/mecik-arda/NetworkSniffer.git](https://github.com/mecik-arda/NetworkSniffer.git)

&nbsp;  cd NetworkSniffer



