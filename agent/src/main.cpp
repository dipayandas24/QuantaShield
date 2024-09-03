#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <array>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

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

// Function to print packet details including application name
void print_packet_info(const u_char *packet, struct pcap_pkthdr header) {
    struct ip *ip_header = (struct ip*)(packet + 14); // Skip Ethernet header (14 bytes)
    int ip_header_len = ip_header->ip_hl * 4;

    std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
    std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

    if (ip_header->ip_p == IPPROTO_TCP) {
        std::cout << "Protocol: TCP" << std::endl;
        struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + ip_header_len);
        int src_port = ntohs(tcp_header->th_sport);
        int dst_port = ntohs(tcp_header->th_dport);
        std::cout << "Source Port: " << src_port << " (" << get_application_name(src_port) << ")" << std::endl;
        std::cout << "Destination Port: " << dst_port << " (" << get_application_name(dst_port) << ")" << std::endl;
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        std::cout << "Protocol: UDP" << std::endl;
        struct udphdr *udp_header = (struct udphdr*)(packet + 14 + ip_header_len);
        int src_port = ntohs(udp_header->uh_sport);
        int dst_port = ntohs(udp_header->uh_dport);
        std::cout << "Source Port: " << src_port << " (" << get_application_name(src_port) << ")" << std::endl;
        std::cout << "Destination Port: " << dst_port << " (" << get_application_name(dst_port) << ")" << std::endl;
    } else {
        std::cout << "Protocol: Other" << std::endl;
    }

    std::cout << "Packet Length: " << header.len << std::endl;
    std::cout << "------------------------------------" << std::endl;
}

int main() {
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

