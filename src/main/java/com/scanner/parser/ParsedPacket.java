package com.scanner.parser;

public class ParsedPacket {
    private final String timestamp;
    private final String sourceIp;
    private final String destinationIp;
    private final String sourcePort;
    private final String destinationPort;
    private final String protocol;
    private final int length;
    private final String info;

    public ParsedPacket(String timestamp, String sourceIp, String destinationIp, 
                        String sourcePort, String destinationPort, 
                        String protocol, int length, String info) {
        this.timestamp = timestamp;
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.length = length;
        this.info = info;
    }

    public String getTimestamp() { return timestamp; }
    public String getSourceIp() { return sourceIp; }
    public String getDestinationIp() { return destinationIp; }
    public String getSourcePort() { return sourcePort; }
    public String getDestinationPort() { return destinationPort; }
    public String getProtocol() { return protocol; }
    public int getLength() { return length; }
    public String getInfo() { return info; }
}