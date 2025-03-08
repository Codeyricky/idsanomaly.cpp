#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <vector>
#include <string>
#include <ctime>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/prepared_statement.h> // Ensure this header is included

using namespace std;
using namespace sql;

// Database connection details
const string DB_HOST = "hostname";
const string DB_USER = "username";
const string DB_PASS = "password";
const string DB_NAME = "database";

// Base class for a NetworkPacket
class NetworkPacket {
public:
    string sourceIP;
    string destinationIP;
    string protocol;
    int packetSize;
    time_t timestamp;

    NetworkPacket(string src, string dest, string proto, int size)
        : sourceIP(src), destinationIP(dest), protocol(proto), packetSize(size) {
        timestamp = time(0); // current time
    }

    virtual void analyzePacket() {
        cout << "Analyzing Packet from " << sourceIP << " to " << destinationIP << " using protocol " << protocol << endl;
    }

    void saveToNetworkEvents(Connection* con) {
        std::unique_ptr<PreparedStatement> pstmt(con->prepareStatement(
            "INSERT INTO NetworkEvents (timestamp, source_ip, destination_ip, protocol, packet_size) VALUES (?, ?, ?, ?, ?)"));
        pstmt->setInt64(1, timestamp);
        pstmt->setString(2, sourceIP);
        pstmt->setString(3, destinationIP);
        pstmt->setString(4, protocol);
        pstmt->setInt(5, packetSize);
        pstmt->execute();
        cout << "Network event saved successfully." << endl;
    }
};

// Class for capturing and analyzing packets
class PacketCapture {
public:
    vector<NetworkPacket> packets;

    void capturePacket(NetworkPacket packet) {
        packets.push_back(packet);
        packet.analyzePacket();
    }

    void listCapturedPackets() {
        for (auto& packet : packets) {
            cout << "Captured Packet: " << packet.sourceIP << " -> " << packet.destinationIP << " [" << packet.protocol << "]" << endl;
        }
    }
};

// Base class for detection methods
class DetectionMethod {
public:
    virtual bool detect(NetworkPacket packet) = 0;
};

// Class for Signature-based Detection
class SignatureDetection : public DetectionMethod {
public:
    vector<string> knownSignatures;

    SignatureDetection() {
        // Example signatures
        knownSignatures.push_back("MaliciousPattern1");
        knownSignatures.push_back("MaliciousPattern2");
    }

    bool detect(NetworkPacket packet) override {
        cout << "Running signature-based detection on packet..." << endl;
        for (auto& sig : knownSignatures) {
            if (packet.sourceIP.find(sig) != string::npos) {
                cout << "Signature match found: " << sig << endl;
                return true;
            }
        }
        return false;
    }
};

// Class for Anomaly-based Detection
class AnomalyDetection : public DetectionMethod {
public:
    double threshold;

    AnomalyDetection(double thres) : threshold(thres) {}

    bool detect(NetworkPacket packet) override {
        cout << "Running anomaly-based detection on packet..." << endl;
        if (packet.packetSize > threshold) {
            cout << "Anomaly detected: Packet size exceeds threshold." << endl;
            return true;
        }
        return false;
    }
};

// Class for Alerts
class Alert {
public:
    time_t timestamp;
    string description;
    string severityLevel;
    string potentialAttackType;
    string sourceIP;
    string destinationIP;

    Alert(string desc, string severity, string attackType, string srcIP, string destIP)
        : description(desc), severityLevel(severity), potentialAttackType(attackType), sourceIP(srcIP), destinationIP(destIP) {
        timestamp = time(0); // current time
    }

    void generateAlert() {
        cout << "ALERT: [" << severityLevel << "] " << description << " from " << sourceIP << " to " << destinationIP << endl;
    }

    void saveToDatabase(Connection* con) {
        std::unique_ptr<PreparedStatement> pstmt(con->prepareStatement(
            "INSERT INTO Alerts (timestamp, description, severity_level, potential_attack_type, source_ip, destination_ip) VALUES (?, ?, ?, ?, ?, ?)"));
        pstmt->setInt64(1, timestamp);
        pstmt->setString(2, description);
        pstmt->setString(3, severityLevel);
        pstmt->setString(4, potentialAttackType);
        pstmt->setString(5, sourceIP);
        pstmt->setString(6, destinationIP);
        pstmt->execute();
        cout << "Alert saved successfully." << endl;
    }
};

// Class for managing Alerts
class AlertManager {
public:
    vector<Alert> alerts;

    void addAlert(Alert alert, Connection* con) {
        alerts.push_back(alert);
        alert.generateAlert();
        alert.saveToDatabase(con);
    }

    void listAlerts() {
        for (auto& alert : alerts) {
            cout << "Alert: " << alert.description << " [" << alert.severityLevel << "] - " << alert.sourceIP << " -> " << alert.destinationIP << endl;
        }
    }
};

// Main IDS class
class IntrusionDetectionSystem {
private:
    PacketCapture packetCapture;
    SignatureDetection signatureDetection;
    AnomalyDetection anomalyDetection;
    AlertManager alertManager;
    Connection* con;

public:
    IntrusionDetectionSystem(double anomalyThreshold) 
        : anomalyDetection(anomalyThreshold) {
        sql::mysql::MySQL_Driver* driver;

        try {
            driver = sql::mysql::get_mysql_driver_instance();
            con = driver->connect(DB_HOST, DB_USER, DB_PASS);
            con->setSchema(DB_NAME);
            cout << "Database connection established successfully." << endl;
        } catch (SQLException &e) {
            cout << "Error connecting to the database: " << e.what() << endl;
            exit(EXIT_FAILURE); // Exit if connection fails
        }
    }

    ~IntrusionDetectionSystem() {
        delete con;
    }

    void monitorNetwork(NetworkPacket packet) {
        packetCapture.capturePacket(packet);
        packet.saveToNetworkEvents(con); // Save network packet details

        if (signatureDetection.detect(packet)) {
            alertManager.addAlert(Alert("Signature-based detection triggered", "High", "Possible Attack", packet.sourceIP, packet.destinationIP), con);
        }
        if (anomalyDetection.detect(packet)) {
            alertManager.addAlert(Alert("Anomaly-based detection triggered", "Medium", "Possible Anomaly", packet.sourceIP, packet.destinationIP), con);
        }
    }

    void showCapturedPackets() {
        packetCapture.listCapturedPackets();
    }

    void showAlerts() {
        alertManager.listAlerts();
    }

    void startPacketCapture() {
        char error_buffer[PCAP_ERRBUF_SIZE];  // Error buffer for pcap errors
        pcap_t* handle;                       // Handle for capturing packets
        const char* device = "eth0";          // Network interface (replace with your interface name)
        int packet_count_limit = 10;          // Number of packets to capture
        int timeout_limit = 10000;            // Timeout in milliseconds (10000 ms = 10 seconds)

        // Open the network device for packet capture
        handle = pcap_open_live(device, BUFSIZ, 1, timeout_limit, error_buffer);
        if (handle == nullptr) {
            std::cerr << "Could not open device " << device << ": " << error_buffer << std::endl;
            return;
        }

        // Capture packets
        struct pcap_pkthdr packet_header; // Packet header
        const u_char* packet;             // Actual packet

        for (int i = 0; i < packet_count_limit; ++i) {
            packet = pcap_next(handle, &packet_header);
            if (packet == nullptr) {
                std::cout << "Failed to capture a packet." << std::endl;
                continue;
            }

            // Extract IP headers
            struct ip* ip_header = (struct ip*)(packet + 14); // Skip Ethernet header

            // Get source and destination IP addresses
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

            // Get the protocol
            uint8_t protocol = ip_header->ip_p;

            // Create a NetworkPacket object and monitor it
            NetworkPacket networkPacket(src_ip, dst_ip, to_string(protocol), packet_header.len);
            monitorNetwork(networkPacket);
        }

        // Close the packet capture handle
        pcap_close(handle);
    }
};

// Main function
int main() {
    IntrusionDetectionSystem ids(500); // Threshold for anomaly detection is 500 bytes

    // Start packet capturing