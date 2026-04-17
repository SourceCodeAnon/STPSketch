#include <pcap.h>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <cstring>

#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

static const int ETHERNET_HEADER_LEN = 14;
static const uint16_t ETHER_TYPE_IPv4 = 0x0800;

static const uint64_t CHUNK_SIZE = 10'000'000ULL;

std::string make_output_name(const std::string &prefix, uint64_t index) {
    std::ostringstream oss;
    oss << prefix << "_" << std::setw(2) << std::setfill('0') << index << ".txt";
    return oss.str();
}

int main() {

    const char *pcap_path = "/mnt/c/Users/45512/Downloads/202001011400.pcap";
    std::string out_prefix = "/mnt/c/Users/45512/Documents/dataset/mawi/ip_num";

    char errbuf[PCAP_ERRBUF_SIZE];
    std::memset(errbuf, 0, sizeof(errbuf));

    pcap_t *handle = pcap_open_offline(pcap_path, errbuf);
    if (!handle) {
        std::cerr << "Failed to open pcap file: " << pcap_path
                  << "\nError: " << errbuf << "\n";
        return 1;
    }

    uint64_t total_count = 0;
    uint64_t chunk_index = 0;
    std::ofstream ofs;

    std::string out_name = make_output_name(out_prefix, chunk_index);
    ofs.open(out_name, std::ios::out | std::ios::trunc);
    if (!ofs) {
        std::cerr << "Failed to open output file: " << out_name << "\n";
        pcap_close(handle);
        return 1;
    }
    std::cout << "Writing to: " << out_name << "\n";

    const u_char *packet;
    struct pcap_pkthdr *header;

    int ret = 0;
    while ((ret = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (ret == 0) {

            continue;
        }

        if (header->caplen < ETHERNET_HEADER_LEN) {
            continue;
        }

        const u_char *eth = packet;
        uint16_t ether_type = (static_cast<uint16_t>(eth[12]) << 8) | eth[13];
        if (ether_type != ETHER_TYPE_IPv4) {
            continue;
        }

        const u_char *ip = packet + ETHERNET_HEADER_LEN;
        if (header->caplen < ETHERNET_HEADER_LEN + 20) {

            continue;
        }

        uint8_t ver_ihl = ip[0];
        uint8_t version = ver_ihl >> 4;
        if (version != 4) {
            continue;
        }

        const u_char *dst_ptr = ip + 16;
        uint32_t dst_ip_net;
        std::memcpy(&dst_ip_net, dst_ptr, sizeof(dst_ip_net));

        uint32_t dst_ip_host = ntohl(dst_ip_net);

        ofs << dst_ip_host << '\n';

        ++total_count;

        if (total_count % CHUNK_SIZE == 0) {
            ofs.close();
            std::cout << "Chunk " << chunk_index
                      << " finished with " << CHUNK_SIZE << " records.\n";

            ++chunk_index;
            out_name = make_output_name(out_prefix, chunk_index);
            ofs.open(out_name, std::ios::out | std::ios::trunc);
            if (!ofs) {
                std::cerr << "Failed to open output file: " << out_name << "\n";
                pcap_close(handle);
                return 1;
            }
            std::cout << "Writing to: " << out_name << "\n";
        }
    }

    ofs.close();
    pcap_close(handle);

    if (ret == -1) {
        std::cerr << "Error reading pcap: " << errbuf << "\n";
    }

    if (total_count < CHUNK_SIZE) {
        std::cout << "Total IPv4 packets less than " << CHUNK_SIZE
                  << ", actual: " << total_count << "\n";
    }

    std::cout << "Done. Total IPv4 packets: " << total_count << "\n";
    std::cout << "Generated "
              << (chunk_index + (total_count % CHUNK_SIZE ? 1 : 0))
              << " file(s).\n";

    return 0;
}
