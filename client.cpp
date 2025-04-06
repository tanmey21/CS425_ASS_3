#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

using namespace std;

// Utility function to print the TCP flags and basic info from a TCP header
void print_tcp_flags(struct tcphdr *tcp) {
    cout << "[+] TCP Flags: "
         << " SYN=" << (int)tcp->syn
         << " ACK=" << (int)tcp->ack
         << " FIN=" << (int)tcp->fin
         << " RST=" << (int)tcp->rst
         << " PSH=" << (int)tcp->psh
         << " SEQ=" << ntohl(tcp->seq)
         << " SRC_PORT=" << ntohs(tcp->source)
         << " DST_PORT=" << ntohs(tcp->dest)
         << endl;
}

// Constructs and sends a SYN packet to initiate a TCP handshake
bool send_syn(int sock) {
    // Allocate buffer for IP + TCP headers
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    // Split the packet into IP and TCP header regions
    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Fill in IP header fields
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("127.0.0.1");   // Source IP
    ip->daddr = inet_addr("127.0.0.1");   // Destination IP

    // Check for invalid IP
    if (ip->saddr == INADDR_NONE || ip->daddr == INADDR_NONE) {
        cerr << "[-] Invalid IP address format" << endl;
        return false;
    }

    // Fill in TCP header fields
    tcp->source = htons(1000);           // Source port
    tcp->dest = htons(12345);            // Destination port
    tcp->seq = htonl(200);               // Initial sequence number
    tcp->ack_seq = 0;                    // No ACK yet
    tcp->doff = 5;                       // TCP header size (5 * 4 = 20 bytes)
    tcp->syn = 1;                        // Set SYN flag to initiate handshake
    tcp->window = htons(8192);           // TCP window size
    tcp->check = 0;                      // Let kernel fill checksum

    // Define the target destination for sendto()
    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(12345);      
    dest.sin_addr.s_addr = ip->daddr;

    // Send the crafted packet
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("[-] sendto() failed");
        return false;
    }

    cout << "[+] Sent SYN" << endl;
    return true;
}

// Constructs and sends an ACK packet in response to a SYN-ACK
bool send_ack(int sock, struct sockaddr_in *server_addr, struct tcphdr *tcp_in) {
    if (!server_addr || !tcp_in) {
        cerr << "[-] Invalid input to send_ack" << endl;
        return false;
    }

    // Allocate buffer for IP + TCP headers
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    // Split the packet into IP and TCP header regions
    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp_response = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Fill in IP header fields
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = inet_addr("127.0.0.1");

    if (ip->saddr == INADDR_NONE || ip->daddr == INADDR_NONE) {
        cerr << "[-] Invalid IP address format in ACK" << endl;
        return false;
    }

    // Fill in TCP ACK response
    tcp_response->source = htons(1000);                      // Our source port
    tcp_response->dest = tcp_in->source;                     // Destination = sender's source port
    tcp_response->seq = htonl(600);                          // New sequence number
    tcp_response->ack_seq = htonl(ntohl(tcp_in->seq) + 1);   // Acknowledge their sequence
    tcp_response->doff = 5;
    tcp_response->syn = 0;
    tcp_response->ack = 1;                                   // Set ACK flag
    tcp_response->window = htons(8192);
    tcp_response->check = 0;

    // Send ACK packet to the sender of the SYN-ACK
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("[-] sendto() failed for ACK");
        return false;
    }

    cout << "[+] Sent ACK" << endl;
    return true;
}

int main() {
    // Create a raw socket with TCP protocol
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("[-] socket() failed");
        return 1;
    }

    // Enable IP_HDRINCL so we provide our own IP header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[-] setsockopt() failed");
        close(sock);
        return 1;
    }

    // Send the initial SYN packet
    if (!send_syn(sock)) {
        cerr << "[-] Failed to send SYN" << endl;
        close(sock);
        return 1;
    }

    // Start listening for incoming responses
    while (true) {
        char buffer[65536];                           // Buffer to receive raw packets
        struct sockaddr_in source_addr{};
        socklen_t addr_len = sizeof(source_addr);

        // Receive raw packet
        ssize_t data_size = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &addr_len);
        if (data_size < 0) {
            perror("[-] recvfrom() failed");
            continue;
        }

        // Sanity check: packet must be large enough for IP header
        if ((size_t)data_size < sizeof(struct iphdr)) {
            cerr << "[-] Received packet too short for IP header" << endl;
            continue;
        }

        struct iphdr *ip = (struct iphdr *)buffer;
        int ip_hdr_len = ip->ihl * 4;

        // Sanity check: packet must be large enough for TCP header
        if (data_size < ip_hdr_len + (int)sizeof(struct tcphdr)) {
            cerr << "[-] Packet too short for TCP header" << endl;
            continue;
        }

        struct tcphdr *tcp = (struct tcphdr *)(buffer + ip_hdr_len);
        print_tcp_flags(tcp);                          // Log the incoming TCP flags

        // We're only interested in packets sent to port 1000
        if (ntohs(tcp->dest) != 1000) {
            continue;
        }

        // Check if it's a SYN-ACK (part of handshake)
        if (tcp->syn == 1 && tcp->ack == 1) {
            // Send ACK to complete handshake
            if (!send_ack(sock, &source_addr, tcp)) {
                cerr << "[-] Failed to send ACK" << endl;
                break;
            }

            cout << "[+] Handshake completed" << endl;
            break;
        }
    }

    // Close the raw socket
    close(sock);
    return 0;
}
