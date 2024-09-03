#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <array>
#include <cstdio>
#include <fstream>          
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/stat.h>       
#include <sys/types.h>      

// Function to execute a shell command and return the output
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// Function to get application name based on port number
std::string get_application_name(int port) {
    std::string cmd = "ss -tnlp | grep ':";
    cmd += std::to_string(port);
    cmd += "' | awk '{print $6}'";
    std::string result = exec(cmd.c_str());

    // Trim leading/trailing whitespace
    result.erase(result.find_last_not_of(" \n\r\t")+1);
    return result.empty() ? "Unknown" : result;
}

// Function to ensure the logs directory exists
void ensure_logs_directory() {
    struct stat info;
    if (stat("../agent/logs", &info) != 0) {
        // Directory does not exist
        if (mkdir("../agent/logs", 0755) != 0) {
            std::cerr << "Error: Unable to create logs directory!" << std::endl;
            exit(1);
        }
    } else if (!(info.st_mode & S_IFDIR)) {
        // Path exists but is not a directory
        std::cerr << "Error: logs path exists but is not a directory!" << std::endl;
        exit(1);
    }
}

// Function to log packet details to a file
void log_packet_info(const std::string& log_entry) {
    std::ofstream logfile("../agent/logs/network_traffic.log", std::ios::app);
    if (logfile.is_open()) {
        logfile << log_entry << std::endl;
        logfile.close();
    } else {
        std::cerr << "Error: Unable to open log file!" << std::endl;
    }
}

// Function to print and log packet details including application name
void print_packet_info(const u_char *packet, struct pcap_pkthdr header) {
    struct ip *ip_header = (struct ip*)(packet + 14); // Skip Ethernet header (14 bytes)
    int ip_header_len = ip_header->ip_hl * 4;

    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);
    std::string protocol;
    std::string log_entry;

    log_entry += "Source IP: " + src_ip + "\n";
    log_entry += "Destination IP: " + dst_ip + "\n";

    if (ip_header->ip_p == IPPROTO_TCP) {
        protocol = "TCP";
        struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + ip_header_len);
        int src_port = ntohs(tcp_header->th_sport);
        int dst_port = ntohs(tcp_header->th_dport);
        log_entry += "Protocol: " + protocol + "\n";
        log_entry += "Source Port: " + std::to_string(src_port) + " (" + get_application_name(src_port) + ")\n";
        log_entry += "Destination Port: " + std::to_string(dst_port) + " (" + get_application_name(dst_port) + ")\n";
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        protocol = "UDP";
        struct udphdr *udp_header = (struct udphdr*)(packet + 14 + ip_header_len);
        int src_port = ntohs(udp_header->uh_sport);
        int dst_port = ntohs(udp_header->uh_dport);
        log_entry += "Protocol: " + protocol + "\n";
        log_entry += "Source Port: " + std::to_string(src_port) + " (" + get_application_name(src_port) + ")\n";
        log_entry += "Destination Port: " + std::to_string(dst_port) + " (" + get_application_name(dst_port) + ")\n";
    } else {
        protocol = "Other";
        log_entry += "Protocol: " + protocol + "\n";
    }

    log_entry += "Packet Length: " + std::to_string(header.len) + "\n";
    log_entry += "------------------------------------\n";

    // Log to file
    log_packet_info(log_entry);

    // Print to console
    std::cout << log_entry;
}

int main() {
    ensure_logs_directory(); // Ensure logs directory exists

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    device = alldevs;
    std::cout << "Capturing on device: " << device->name << std::endl;

    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        return 1;
    }

    // Capture packets and display details
    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != nullptr) {
        print_packet_info(packet, header);
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
