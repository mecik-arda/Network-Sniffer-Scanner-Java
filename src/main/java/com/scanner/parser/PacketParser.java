package com.scanner.parser;

import org.pcap4j.packet.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class PacketParser {
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_CYAN = "\u001B[36m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_PURPLE = "\u001B[35m";
    
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
            .withZone(ZoneId.systemDefault());
    private final Map<String, String> activeArpDevices = new ConcurrentHashMap<>();

    public ParsedPacket parse(Packet packet, Instant timestamp) {
        String timeStr = timeFormatter.format(timestamp);
        String srcIp = "-";
        String dstIp = "-";
        String srcPort = "-";
        String dstPort = "-";
        String protocol = "UNKNOWN";
        int length = packet.length();
        String info = "";

        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            srcIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();
            protocol = ipV4Packet.getHeader().getProtocol().name();
        }

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            srcPort = String.valueOf(tcpPacket.getHeader().getSrcPort().valueAsInt());
            dstPort = String.valueOf(tcpPacket.getHeader().getDstPort().valueAsInt());
            protocol = "TCP";
            info = checkHttpPayload(tcpPacket, srcPort, dstPort);
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            srcPort = String.valueOf(udpPacket.getHeader().getSrcPort().valueAsInt());
            dstPort = String.valueOf(udpPacket.getHeader().getDstPort().valueAsInt());
            protocol = "UDP";
        } else if (packet.contains(IcmpV4CommonPacket.class)) {
            protocol = "ICMP";
        } else if (packet.contains(ArpPacket.class)) {
            protocol = "ARP";
            ArpPacket arpPacket = packet.get(ArpPacket.class);
            String senderMac = arpPacket.getHeader().getSrcHardwareAddr().toString();
            String senderIp = arpPacket.getHeader().getSrcProtocolAddr().getHostAddress();
            activeArpDevices.put(senderIp, senderMac);
            info = "ARP Device: IP=" + senderIp + " MAC=" + senderMac;
        }

        printToConsole(timeStr, srcIp, dstIp, srcPort, dstPort, protocol, length, info);
        return new ParsedPacket(timeStr, srcIp, dstIp, srcPort, dstPort, protocol, length, info);
    }

    private String checkHttpPayload(TcpPacket tcpPacket, String srcPort, String dstPort) {
        if (srcPort.equals("80") || dstPort.equals("80") || srcPort.equals("8080") || dstPort.equals("8080")) {
            byte[] payload = tcpPacket.getPayload() != null ? tcpPacket.getPayload().getRawData() : new byte[0];
            if (payload.length > 0) {
                String payloadStr = new String(payload);
                if (payloadStr.startsWith("GET ") || payloadStr.startsWith("POST ")) {
                    String[] lines = payloadStr.split("\r\n");
                    return "HTTP " + lines[0];
                }
            }
        }
        return "";
    }

    private void printToConsole(String time, String srcIp, String dstIp, String srcPort, 
                                String dstPort, String proto, int len, String info) {
        String formatted = String.format("%s[%s] %s%s:%s -> %s:%s %s%s %sLen:%d %s",
                ANSI_CYAN, time, ANSI_YELLOW, srcIp, srcPort, dstIp, dstPort,
                ANSI_PURPLE, proto, ANSI_GREEN, len, info.isEmpty() ? "" : "| " + info) + ANSI_RESET;
        System.out.println(formatted);
    }

    public Map<String, String> getActiveArpDevices() {
        return activeArpDevices;
    }
}