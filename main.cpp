#include <iostream>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <sstream>

extern "C" {
#include <netinet/if_ether.h> 
#include <netinet/ether.h> 
#include <netinet/ip.h> 
#include <netinet/ip6.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
}

#include "utils.h"
#include "arguments.h"
#include "analyzer.h"
#include "pcap_ptr.h"

using namespace PacketAnalyzer;
using namespace std;

struct TupleToHashForIPv4 {
    uint32_t SrcIP;
    uint32_t DstIP;
    uint16_t identification;
};

struct FragmentInfo {
    size_t maxSize;
    size_t currentSize;
};

namespace std {
    template<>
    struct hash<TupleToHashForIPv4> {
        size_t operator()(const TupleToHashForIPv4& t) const {
            return hash<uint32_t>{}(t.SrcIP) ^
                   hash<uint32_t>{}(t.DstIP) ^
                   hash<uint16_t>{}(t.identification);
        }
    };

    template<>
    struct equal_to<TupleToHashForIPv4> {
        bool operator()(const TupleToHashForIPv4& l, const TupleToHashForIPv4& r) const {
            return l.SrcIP == r.SrcIP && 
                   l.DstIP == r.DstIP && 
                   l.identification == r.identification;
        }
    };
}

void print_all(Arguments::Parser& ap) {
    // typed options
    for (const auto& s : ap.args())
        if (!s.second.empty())
            cout << s.first << " : " << s.second << '\n';

    // file names
    for (const auto& s : ap.files())  {
        PCAP::PcapPtr pcap {s};
        cout << s << '\n';
    }
}

time_t ToMicroSeconds(const timeval& ts) {
    return 1'000'000UL * ts.tv_sec + ts.tv_usec;
}

struct HeaderVLAN {
    struct Tci {
        unsigned vid    :12;
        bool     dei    :1;
        unsigned pcp    :3;
    } __attribute__((packed)) tci;
    uint16_t tpid;
} __attribute__((packed));

pair<const uint8_t*, int> vlan_packet(const uint8_t* packet) {
    uint32_t bytes {ntohl(*(uint32_t*)(packet + 12))};

    HeaderVLAN vlan {*(HeaderVLAN*)&bytes};

    /*cout << "\nTPID: " << hex << vlan.tpid << '\n'
         << "PCP:  " << dec <<vlan.tci.pcp <<  '\n'
         << "DEI:  " << vlan.tci.dei << '\n'
         << "VID:  " << vlan.tci.vid << '\n';
         */

    cout << ' ' << vlan.tci.vid;

    int packetType {ntohs(*(uint16_t*)(packet + 16))};

    packet += 4;

    return make_pair(packet, packetType);
}

pair<string, string> SrcDstMAC(const uint8_t* packet) {
    const ether_header* eptr {reinterpret_cast<const ether_header*>(packet)};

    string SrcMAC {ether_ntoa((const ether_addr*)(&eptr->ether_shost))};
    string DstMAC {ether_ntoa((const ether_addr*)(&eptr->ether_dhost))};

    return make_pair(SrcMAC, DstMAC);
}

int EtherType(const uint8_t* packet) {
    const ether_header* eptr {reinterpret_cast<const ether_header*>(packet)};
    return ntohs(eptr->ether_type);
}

string MakeIPv4StringToPrint(const ip& packetIP) {
    string SrcIP {inet_ntoa(packetIP.ip_src)};
    string DstIP {inet_ntoa(packetIP.ip_dst)};

    ostringstream ss;

    ss << "IPv4"    << ' '
       << SrcIP     << ' ' 
       << DstIP     << ' ' 
       << unsigned{packetIP.ip_ttl};

    return ss.str();
}

TupleToHashForIPv4 TupleToHash(const ip& headerIPv4) {
    return {headerIPv4.ip_src.s_addr, 
            headerIPv4.ip_dst.s_addr, 
            headerIPv4.ip_id};
}

inline bool IsFlagMoreFragmentsSet(uint16_t offset) { return offset & IP_MF; }
inline bool IsOffsetNonZero(uint16_t offset) { return offset != 0; }
inline bool IsFragmented(const ip& header) { 
    uint16_t offset {ntohs(header.ip_off)};
    return IsFlagMoreFragmentsSet(offset) || IsOffsetNonZero(offset); 
}

inline size_t HeaderLenIPv4(const ip& header) { return header.ip_hl * 4; }

unordered_map<TupleToHashForIPv4, FragmentInfo> fragments;

enum class ExtensionsIPv6 { TCP = 6, UDP = 17, ICMPv6 = 58  };
inline bool IsExtension(uint8_t number) {
    ExtensionsIPv6 n {static_cast<ExtensionsIPv6>(number)};
    return n != ExtensionsIPv6::TCP && 
           n != ExtensionsIPv6::UDP && 
           n != ExtensionsIPv6::ICMPv6;
}

void PacketLayer3(const uint8_t* packetL3, int packetType) {
    enum class Layer3 { IPv4 = ETHERTYPE_IP, IPv6 = ETHERTYPE_IPV6 };

    string SrcIP;
    string DstIP;

    switch(static_cast<Layer3>(packetType)) {
        case Layer3::IPv4: 
        {
            const ip& packet {*(ip*)packetL3};

            if (IsFragmented(packet)) {
                uint16_t offset {ntohs(packet.ip_off)};
                size_t DataLen {ntohs(packet.ip_len) - HeaderLenIPv4(packet)};

                FragmentInfo& fragment = fragments[TupleToHash(packet)];

                if (IsFlagMoreFragmentsSet(offset)) {
                    fragment.currentSize += DataLen;
                } else if (IsOffsetNonZero(offset)) {
                    fragment.maxSize = offset*8 + DataLen;
                    fragment.currentSize += DataLen;
                }

                if (fragment.maxSize > 0 && fragment.currentSize >= fragment.maxSize) {
                    cout << MakeIPv4StringToPrint(packet) << ' ';
                }
            } else {
                cout << MakeIPv4StringToPrint(packet) << ' ';
            }

            break;
        }
        case Layer3::IPv6: 
        {
            const ip6_hdr& packetIP {*(ip6_hdr*)packetL3};
            array<char, INET6_ADDRSTRLEN> buf;

            SrcIP = inet_ntop(AF_INET6, (void*)(&packetIP.ip6_src), buf.data(), buf.size());
            DstIP = inet_ntop(AF_INET6, (void*)(&packetIP.ip6_dst), buf.data(), buf.size());

            cout << "IPv6 ";
            cout << SrcIP << " "
                 << DstIP << " "
                 << unsigned{packetIP.ip6_hlim} << " "
                 << unsigned{packetIP.ip6_nxt};

            size_t HeaderLen {sizeof(ip6_hdr)};
            const ip6_ext* e {(ip6_ext*)(packetL3+HeaderLen)};
            cout << "\n next: " << hex << unsigned{e->ip6e_nxt} << dec << '\n';
            cout << " size: " << unsigned{e->ip6e_len} << '\n';
            e = (ip6_ext*)(packetL3+HeaderLen+e->ip6e_len+1);
            cout << " next: " << hex << unsigned{e->ip6e_nxt} << dec << '\n';
            cout << " size: " << unsigned{e->ip6e_len} << '\n';
            break;

            uint8_t p {};
            for (uint8_t next {packetIP.ip6_nxt}; IsExtension(next);) {
                const ip6_ext* e {(ip6_ext*)p};

                cout << "next: " << unsigned{next} << '\n';

                next = e->ip6e_nxt;
                p += e->ip6e_len + 1;
            }

            break;
        }
        default: throw runtime_error{"Unknown packet type: " + to_string(packetType)};
    }

    // PacketLayer4(packet, packetType);
}

void PrintSrcDstMAC(const uint8_t* packet) {
    string SrcMAC;
    string DstMAC;
    tie(SrcMAC, DstMAC) = SrcDstMAC(packet);
    cout << "Ethernet: " << SrcMAC << " " << DstMAC;
}

void PacketLayer2(const uint8_t* packet) {
    enum class Layer2 { IEEE_802_1q  = 0x8100, IEEE_802_1ad = 0x88a8 };

    PrintSrcDstMAC(packet);

    auto packetType = EtherType(packet);
    switch (static_cast<Layer2>(packetType)) {
        case Layer2::IEEE_802_1q:
        {
            tie(packet, packetType) = vlan_packet(packet);
            break;
        }
        case Layer2::IEEE_802_1ad: 
        {
            tie(packet, packetType) = vlan_packet(packet);
            tie(packet, packetType) = vlan_packet(packet);
            break;
        }
        default: break;
    }

    cout << " | ";
    constexpr auto ipOffset {14};
    PacketLayer3(packet+ipOffset, packetType);
}

void PrintPacket(const uint8_t* packet) {
    PacketLayer2(packet);
}

int main(int argc, char* argv[]) {
    try {
        Arguments::Parser ap {argc, argv, "ha:s:l:f:"};
        if (Arguments::print_help(ap.get<string>("-h"))) return 1; 
        print_all(ap);

        size_t packetsCount {1};
        for (PCAP::Analyzer a {ap.files()[0]}; a.NextPacket(); ++packetsCount) {
            const auto& header = a.Header();
            const uint8_t* packet = a.Packet();

            cout << packetsCount << ": " << ToMicroSeconds(header.ts) << " " << header.len << " | ";

            PrintPacket(packet);

            cout << '\n';
        }

        for (const auto& p : fragments)
            cout << p.second.maxSize << " : " <<p.second.currentSize << '\n';
    } catch (Arguments::Parser::BadArgsStructure) {
        // no message because getopt writes error by itself
        return 2;
    } catch (Arguments::Parser::BadArgsNum) {
        cerr << "Invalid arguments count!\n";
        return 3;
    } catch (const runtime_error& e) {
        cerr << "Runtime error caught: " << e.what() << '\n';
        return 4;
    }
}
