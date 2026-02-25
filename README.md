# Network Sniffer and Scanner Java

A powerful tool developed with JavaFX to monitor and analyze network traffic in real time. It combines the low-level packet capture capabilities of the Pcap4j library with a sleek user interface.

## Features and Capabilities

- **Live Packet Analysis** Parses TCP, UDP, ICMP, and ARP packets passing through the selected network interface instantly.
- **HTTP Traffic Monitoring** Captures GET and POST requests on ports 80 and 8080 by URL and method.
- **Active Device Scanning** Detects devices on the network from ARP packets and lists their IP and MAC addresses.
- **BPF Filtering** Allows you to apply custom filters (like "tcp port 443") to see only the traffic you care about.
- **PCAP Support** Saves captured data in .pcap format for further detailed inspection with tools like Wireshark.
- **Real-Time Statistics** Displays total data size, packets per second (PPS), and protocol distribution on the screen.

## Requirements and Supported Versions

- **Java Version** Requires Java 17 or higher.
- **Operating System** Works on Windows and Linux environments.
- **Drivers** Npcap for Windows (with WinPcap compatibility mode enabled) and libpcap-dev package for Linux are strictly required.

## How to Use

1. **Prepare the System** Install the appropriate Pcap drivers for your operating system.
2. **Download the Project** Clone the repository to your computer using the git clone github.com/mecik-arda/Network-Sniffer-Scanner-Java.git command in your terminal.
3. **Build** Open your terminal with administrator privileges in the project directory and run the mvn clean install command to download dependencies.
4. **Run** Start the interface by running the Main class via your IDE (make absolutely sure you run your IDE or terminal as an administrator to access network cards).
5. **Use the Interface** Select your network card from the top menu, set your filters, and press the Start button to monitor the network flow.

## Developer

**Arda Meçik**
You can check my GitHub profile for my projects and other works
github.com/mecik-arda