package com.scanner.ui;

import com.scanner.capture.NetworkSniffer;
import com.scanner.parser.ParsedPacket;
import com.scanner.stats.StatisticsManager;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Hyperlink;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Duration;
import org.pcap4j.core.PcapNetworkInterface;

import java.awt.Desktop;
import java.net.URI;
import java.util.List;

public class MainWindow {
    private final StatisticsManager statsManager = new StatisticsManager();
    private final NetworkSniffer sniffer = new NetworkSniffer(statsManager);
    private final ObservableList<ParsedPacket> packetList = FXCollections.observableArrayList();
    private final TableView<ParsedPacket> table = new TableView<>();
    
    private ComboBox<String> interfaceCombo;
    private List<PcapNetworkInterface> nifs;
    private TextField bpfInput;
    private CheckBox saveToFileCheck;
    private Label statsLabel;
    private Button startBtn;
    private Button stopBtn;

    public void start(Stage primaryStage) {
        BorderPane root = new BorderPane();
        root.setTop(createTopPanel());
        root.setCenter(createTable());
        root.setBottom(createBottomPanel());

        loadInterfaces();
        setupStatsTimer();

        Runtime.getRuntime().addShutdownHook(new Thread(sniffer::stopCapture));

        Scene scene = new Scene(root, 1000, 600);
        primaryStage.setTitle("Advanced Network Scanner");
        primaryStage.setScene(scene);
        primaryStage.setOnCloseRequest(e -> {
            sniffer.stopCapture();
            Platform.exit();
            System.exit(0);
        });
        primaryStage.show();
    }

    private VBox createTopPanel() {
        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(10));
        
        HBox controls = new HBox(10);
        interfaceCombo = new ComboBox<>();
        interfaceCombo.setPrefWidth(300);
        
        bpfInput = new TextField();
        bpfInput.setPromptText("BPF Filter (e.g. tcp port 80)");
        
        saveToFileCheck = new CheckBox("Save to .pcap");
        
        startBtn = new Button("Start");
        stopBtn = new Button("Stop");
        stopBtn.setDisable(true);

        startBtn.setOnAction(e -> startCapture());
        stopBtn.setOnAction(e -> stopCapture());

        controls.getChildren().addAll(new Label("Interface"), interfaceCombo, bpfInput, saveToFileCheck, startBtn, stopBtn);
        vbox.getChildren().add(controls);
        return vbox;
    }

    private TableView<ParsedPacket> createTable() {
        table.setItems(packetList);
        
        TableColumn<ParsedPacket, String> timeCol = new TableColumn<>("Time");
        timeCol.setCellValueFactory(new PropertyValueFactory<>("timestamp"));
        
        TableColumn<ParsedPacket, String> srcIpCol = new TableColumn<>("Source IP");
        srcIpCol.setCellValueFactory(new PropertyValueFactory<>("sourceIp"));
        
        TableColumn<ParsedPacket, String> dstIpCol = new TableColumn<>("Destination IP");
        dstIpCol.setCellValueFactory(new PropertyValueFactory<>("destinationIp"));
        
        TableColumn<ParsedPacket, String> protoCol = new TableColumn<>("Protocol");
        protoCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        
        TableColumn<ParsedPacket, Integer> lenCol = new TableColumn<>("Length");
        lenCol.setCellValueFactory(new PropertyValueFactory<>("length"));
        
        TableColumn<ParsedPacket, String> infoCol = new TableColumn<>("Info");
        infoCol.setCellValueFactory(new PropertyValueFactory<>("info"));
        infoCol.setPrefWidth(300);

        table.getColumns().addAll(timeCol, srcIpCol, dstIpCol, protoCol, lenCol, infoCol);
        return table;
    }

    private HBox createBottomPanel() {
        HBox hbox = new HBox(20);
        hbox.setPadding(new Insets(10));
        hbox.setStyle("-fx-background-color: #f4f4f4; -fx-border-color: #ccc; -fx-border-width: 1 0 0 0;");

        statsLabel = new Label("Total 0 | TCP 0 | UDP 0 | ICMP 0 | ARP 0 | PPS 0 | Traffic 0.00 MB");
        statsLabel.setStyle("-fx-font-weight: bold;");

        Hyperlink githubLink = new Hyperlink("Developed by Arda Meçik");
        githubLink.setStyle("-fx-text-fill: #007bff; -fx-font-weight: bold;");
        githubLink.setOnAction(e -> {
            try {
                Desktop.getDesktop().browse(new URI("https://github.com/mecik-arda"));
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        hbox.getChildren().addAll(statsLabel, spacer, githubLink);
        return hbox;
    }

    private void loadInterfaces() {
        try {
            nifs = sniffer.getInterfaces();
            for (PcapNetworkInterface nif : nifs) {
                interfaceCombo.getItems().add(nif.getName() + " - " + nif.getDescription());
            }
            if (!nifs.isEmpty()) interfaceCombo.getSelectionModel().select(0);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void startCapture() {
        int index = interfaceCombo.getSelectionModel().getSelectedIndex();
        if (index < 0) return;
        
        PcapNetworkInterface selectedNif = nifs.get(index);
        String filter = bpfInput.getText();
        boolean save = saveToFileCheck.isSelected();

        packetList.clear();
        startBtn.setDisable(true);
        stopBtn.setDisable(false);
        interfaceCombo.setDisable(true);

        try {
            sniffer.startCapture(selectedNif, filter, save, packet -> {
                Platform.runLater(() -> {
                    if (packetList.size() > 5000) packetList.remove(0);
                    packetList.add(packet);
                    table.scrollTo(packetList.size() - 1);
                });
            });
        } catch (Exception e) {
            e.printStackTrace();
            stopCapture();
        }
    }

    private void stopCapture() {
        sniffer.stopCapture();
        startBtn.setDisable(false);
        stopBtn.setDisable(true);
        interfaceCombo.setDisable(false);
    }

    private void setupStatsTimer() {
        Timeline timeline = new Timeline(new KeyFrame(Duration.seconds(1), e -> {
            statsManager.updatePps();
            String text = String.format("Total %d | TCP %d | UDP %d | ICMP %d | ARP %d | PPS %d | Traffic %.2f MB",
                    statsManager.getTotalPackets(), statsManager.getTcpCount(),
                    statsManager.getUdpCount(), statsManager.getIcmpCount(),
                    statsManager.getArpCount(), statsManager.getPps(),
                    statsManager.getTotalMb());
            statsLabel.setText(text);
        }));
        timeline.setCycleCount(Timeline.INDEFINITE);
        timeline.play();
    }
}