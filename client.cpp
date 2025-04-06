#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

using namespace std;

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

bool send_syn(int sock) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

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
        cerr << "[-] Invalid IP address format" << endl;
        return false;
    }

    tcp->source = htons(1000);
    tcp->dest = htons(12345);
    tcp->seq = htonl(200);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(8192);
    tcp->check = 0;

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(12345);
    dest.sin_addr.s_addr = ip->daddr;

    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("[-] sendto() failed");
        return false;
    }

    cout << "[+] Sent SYN" << endl;
    return true;
}

bool send_ack(int sock, struct sockaddr_in *server_addr, struct tcphdr *tcp_in) {
    if (!server_addr || !tcp_in) {
        cerr << "[-] Invalid input to send_ack" << endl;
        return false;
    }

    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp_response = (struct tcphdr *)(packet + sizeof(struct iphdr));

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

    tcp_response->source = htons(1000);
    tcp_response->dest = tcp_in->source;
    tcp_response->seq = htonl(600);
    tcp_response->ack_seq = htonl(ntohl(tcp_in->seq) + 1);
    tcp_response->doff = 5;
    tcp_response->syn = 0;
    tcp_response->ack = 1;
    tcp_response->window = htons(8192);
    tcp_response->check = 0;

    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("[-] sendto() failed for ACK");
        return false;
    }

    cout << "[+] Sent ACK" << endl;
    return true;
}

int main() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("[-] socket() failed");
        return 1;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[-] setsockopt() failed");
        close(sock);
        return 1;
    }

    if (!send_syn(sock)) {
        cerr << "[-] Failed to send SYN" << endl;
        close(sock);
        return 1;
    }

    while (true) {
        char buffer[65536];
        struct sockaddr_in source_addr{};
        socklen_t addr_len = sizeof(source_addr);

        ssize_t data_size = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &addr_len);
        if (data_size < 0) {
            perror("[-] recvfrom() failed");
            continue;
        }

        if ((size_t)data_size < sizeof(struct iphdr)) {
            cerr << "[-] Received packet too short for IP header" << endl;
            continue;
        }

        struct iphdr *ip = (struct iphdr *)buffer;
        int ip_hdr_len = ip->ihl * 4;
        if (data_size < ip_hdr_len + (int)sizeof(struct tcphdr)) {
            cerr << "[-] Packet too short for TCP header" << endl;
            continue;
        }

        struct tcphdr *tcp = (struct tcphdr *)(buffer + ip_hdr_len);
        print_tcp_flags(tcp);

        if (ntohs(tcp->dest) != 1000) {
            continue;
        }

        if (tcp->syn == 1 && tcp->ack == 1) {
            
            if (!send_ack(sock, &source_addr, tcp)) {
                cerr << "[-] Failed to send ACK" << endl;
                break;
            }

            cout << "[+] Handshake completed" << endl;
            break;
        }
    }

    close(sock);
    return 0;
}
