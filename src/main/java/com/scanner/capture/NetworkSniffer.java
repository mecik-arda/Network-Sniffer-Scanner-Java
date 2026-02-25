package com.scanner.capture;

import com.scanner.parser.PacketParser;
import com.scanner.parser.ParsedPacket;
import com.scanner.stats.StatisticsManager;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.util.List;
import java.util.function.Consumer;

public class NetworkSniffer {
    private PcapHandle handle;
    private PcapDumper dumper;
    private Thread captureThread;
    private volatile boolean isRunning = false;
    private final PacketParser parser = new PacketParser();
    private final StatisticsManager statsManager;

    public NetworkSniffer(StatisticsManager statsManager) {
        this.statsManager = statsManager;
    }

    public List<PcapNetworkInterface> getInterfaces() throws PcapNativeException {
        return Pcaps.findAllDevs();
    }

    public void startCapture(PcapNetworkInterface nif, String bpfFilter, boolean saveToFile, 
                             Consumer<ParsedPacket> onPacketCaptured) throws Exception {
        if (isRunning) return;

        int snapLen = 65536;
        int timeout = 10;
        handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

        if (bpfFilter != null && !bpfFilter.trim().isEmpty()) {
            handle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
        }

        if (saveToFile) {
            dumper = handle.dumpOpen("capture.pcap");
        }

        isRunning = true;
        PacketListener listener = packet -> {
            if (dumper != null) {
                try {
                    dumper.dump(packet, handle.getTimestamp());
                } catch (NotOpenException e) {
                    e.printStackTrace();
                }
            }
            ParsedPacket parsed = parser.parse(packet, handle.getTimestamp().toInstant());
            statsManager.recordPacket(parsed.getProtocol(), parsed.getLength());
            onPacketCaptured.accept(parsed);
        };

        captureThread = new Thread(() -> {
            try {
                handle.loop(-1, listener);
            } catch (InterruptedException | NotOpenException | PcapNativeException e) {
                if (isRunning) e.printStackTrace();
            }
        });
        captureThread.setDaemon(true);
        captureThread.start();
    }

    public void stopCapture() {
        isRunning = false;
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
            handle.close();
        }
        if (dumper != null && dumper.isOpen()) {
            dumper.close();
        }
    }
}