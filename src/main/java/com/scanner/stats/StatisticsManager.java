package com.scanner.stats;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class StatisticsManager {
    private final AtomicInteger totalPackets = new AtomicInteger(0);
    private final AtomicInteger tcpCount = new AtomicInteger(0);
    private final AtomicInteger udpCount = new AtomicInteger(0);
    private final AtomicInteger icmpCount = new AtomicInteger(0);
    private final AtomicInteger arpCount = new AtomicInteger(0);
    private final AtomicInteger otherCount = new AtomicInteger(0);
    private final AtomicLong totalBytes = new AtomicLong(0);
    private final AtomicInteger currentSecondPackets = new AtomicInteger(0);
    private int lastPps = 0;

    public void recordPacket(String protocol, int length) {
        totalPackets.incrementAndGet();
        currentSecondPackets.incrementAndGet();
        totalBytes.addAndGet(length);

        switch (protocol) {
            case "TCP" -> tcpCount.incrementAndGet();
            case "UDP" -> udpCount.incrementAndGet();
            case "ICMP" -> icmpCount.incrementAndGet();
            case "ARP" -> arpCount.incrementAndGet();
            default -> otherCount.incrementAndGet();
        }
    }

    public void updatePps() {
        lastPps = currentSecondPackets.getAndSet(0);
    }

    public int getTotalPackets() { return totalPackets.get(); }
    public int getTcpCount() { return tcpCount.get(); }
    public int getUdpCount() { return udpCount.get(); }
    public int getIcmpCount() { return icmpCount.get(); }
    public int getArpCount() { return arpCount.get(); }
    public int getOtherCount() { return otherCount.get(); }
    public int getPps() { return lastPps; }
    public double getTotalMb() { return totalBytes.get() / (1024.0 * 1024.0); }
}