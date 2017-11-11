#include <iostream>
#include <string>
#include <stdexcept>
#include <map>
#include <utility>
#include <cstring>
#include <sstream>

extern "C" {
#include <netinet/if_ether.h> 
#include <netinet/ether.h> 
#include <netinet/ip.h> 
#include <netinet/ip6.h> 
#include <netinet/icmp6.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
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
constexpr size_t HeaderLenIPv6() { return sizeof(ip6_hdr); }

unordered_map<TupleToHashForIPv4, FragmentInfo> fragments;

// TODO: extensions
enum class ExtensionsIPv6 { TCP = 6, UDP = 17, ICMPv6 = 58  };
inline bool IsExtension(uint8_t number) {
    ExtensionsIPv6 n {static_cast<ExtensionsIPv6>(number)};
    return n != ExtensionsIPv6::TCP && 
           n != ExtensionsIPv6::UDP && 
           n != ExtensionsIPv6::ICMPv6;
}

pair<uint8_t, const uint8_t*> SkipExtensions(uint8_t next, const uint8_t* packet) {
    const uint8_t* p {packet + HeaderLenIPv6()};
    const ip6_ext* e {(ip6_ext*)p};
    for (; IsExtension(next);) {
        cout << " next: " << unsigned{next} << ' ';
        next = e->ip6e_nxt;
        p += (e->ip6e_len + 1)*8;
        e = (ip6_ext*)p;
    }
    cout << " next: " << unsigned{next} << '\n';
    return make_pair(next, p);
}

map<int, pair<string, vector<string>>> errorMsgICMPv4;
map<int, pair<string, vector<string>>> errorMsgICMPv6;

void PrintICMPv4(uint8_t type, uint8_t code) {
    const auto& info = errorMsgICMPv4[type];

    cout << "ICMPv4: " << unsigned{type} << ' ' << unsigned{code} << ' '
         << info.first << ' ' << info.second[code] << " | ";
}

inline bool IsICMPv4(const ip& ip) {
    return ip.ip_p == 1;
}

void PrintICMPv6(uint8_t type, uint8_t code) {
    const auto& info = errorMsgICMPv6[type];

    cout << "ICMPv6: " << unsigned{type} << ' ' << unsigned{code} << ' '
         << info.first << ' ' << info.second[code] << " | ";
}

inline bool IsICMPv6(const ip6_hdr& ip) {
    return ip.ip6_nxt == 58;
}

inline const uint8_t* SkipICMPv4Header(const uint8_t* packetL3) {
    return packetL3 + sizeof(icmphdr);
}

inline const uint8_t* SkipICMPv6Header(const uint8_t* packetL3) {
    return packetL3 + sizeof(icmp6_hdr);
}

void PacketLayer4(const uint8_t* packetL4, int packetType) {
    enum class Layer4 { TCP = 6, UDP = 17 };
    const tcphdr& tcp {*(tcphdr*)packetL4};

    switch (static_cast<Layer4>(packetType)) {
        case Layer4::TCP: cout << "TCP " << ntohs(tcp.th_sport) << ' ' << ntohs(tcp.th_dport) << ' '; break;
        case Layer4::UDP: cout << "UDP " << ntohs(tcp.th_sport) << ' ' << ntohs(tcp.th_dport) << ' '; break;
        default: throw runtime_error{"Layer4: Unknown packet type: " + to_string(packetType)};
    }
}

void PacketLayer3(const uint8_t* packetL3, int packetType) {
    enum class Layer3 { IPv4 = ETHERTYPE_IP, IPv6 = ETHERTYPE_IPV6, ICMPv4 = 1 };

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
                cout << MakeIPv4StringToPrint(packet) << " | ";

                if (IsICMPv4(packet)) {
                    const icmphdr& icmp {*(icmphdr*)(packetL3 + HeaderLenIPv4(packet))};
                    PrintICMPv4(icmp.type, icmp.code);
                    // packetL3 = SkipICMPv4Header(packetL3);
                    return;
                }

                packetType = packet.ip_p;
            }

            break;
        }
        case Layer3::IPv6: 
        {
            ip6_hdr& packetIP {*(ip6_hdr*)packetL3};
            array<char, INET6_ADDRSTRLEN> buf;

            SrcIP = inet_ntop(AF_INET6, (void*)(&packetIP.ip6_src), buf.data(), buf.size());
            DstIP = inet_ntop(AF_INET6, (void*)(&packetIP.ip6_dst), buf.data(), buf.size());

            cout << "IPv6 ";
            cout << SrcIP << " "
                 << DstIP << " "
                 << unsigned{packetIP.ip6_hlim} << " ";
            
            uint8_t next {packetIP.ip6_nxt};
            tie(next, packetL3) = SkipExtensions(next, packetL3);
            packetIP = *(ip6_hdr*)packetL3;

            if (IsICMPv6(packetIP)) {
                const icmp6_hdr& icmp {*(icmp6_hdr*)(packetL3 + HeaderLenIPv6())};
                PrintICMPv6(icmp.icmp6_type, icmp.icmp6_code);
                // packetL3 = SkipICMPv6Header(packetL3);
                return;
            }

            // TODO: really?
            packetType = next;

            break;
        }
        default: throw runtime_error{"Unknown packet type: " + to_string(packetType)};
    }

    PacketLayer4(packetL3, packetType);
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
        default: runtime_error{"Unknown frame type: " + to_string(packetType)};
    }

    cout << " | ";
    constexpr auto ipOffset {14};
    PacketLayer3(packet+ipOffset, packetType);
}

void PrintPacket(const uint8_t* packet) {
    PacketLayer2(packet);
}

void InitICMPv4Messages()
{
    errorMsgICMPv4[0]  = make_pair("echo reply", vector<string>{""});
    errorMsgICMPv4[3]  = make_pair("destination unreachable", 
                         vector<string>{"net unreachable", "host unreachable", 
                                        "protocol unreachable", "port unreachable", 
                                        "fragmentation needed and DF set", "source route failed"});
    errorMsgICMPv4[4]  = make_pair("source quench", vector<string>{""});
    errorMsgICMPv4[5]  = make_pair("redirect", 
                         vector<string>{"redirect datagrams for the network", 
                                        "redirect datagrams for the host", 
                                        "redirect datagrams for the type of service and network", 
                                        "redirect datagrams for the type of service and host"});
    errorMsgICMPv4[8]  = make_pair("echo", vector<string>{""});
    errorMsgICMPv4[11] = make_pair("time exceeded", vector<string>{"time to live exceeded in transit", 
                                                                   "fragment reassembly time exceeded"});
    errorMsgICMPv4[12] = make_pair("parameter problem", vector<string>{"pointer indicates the error"});
    errorMsgICMPv4[13] = make_pair("timestamp", vector<string>{""});
    errorMsgICMPv4[14] = make_pair("timestamp reply", vector<string>{""});
    errorMsgICMPv4[15] = make_pair("information request", vector<string>{""});
    errorMsgICMPv4[16] = make_pair("information reply", vector<string>{""});
}

void InitICMPv6Messages()
{
    errorMsgICMPv6[1]  = make_pair("destination unreachable", 
                         vector<string>{"no route to destination", 
                                        "communication with destination administratively prohibited", 
                                        "beyond scope of source address", "address unreachable", 
                                        "port unreachable", "source address failed ingress/egress policy", 
                                        "reject route to destination"});
    errorMsgICMPv6[2]  = make_pair("packet too big", vector<string>{""});
    errorMsgICMPv6[3] = make_pair("time exceeded", vector<string>{"hop limit exceeded in transit", 
                                                                  "fragment reassembly time exceeded"});
    errorMsgICMPv6[4] = make_pair("parameter problem", vector<string>{"erroneous header field encountered",
                                                                      "unrecognized next header type encountered",
                                                                      "Unrecognized IPv6 option encountered"});
    errorMsgICMPv6[128]  = make_pair("echo request", vector<string>{""});
    errorMsgICMPv6[129]  = make_pair("echo reply", vector<string>{""});
}

int main(int argc, char* argv[]) {
    try {
        Arguments::Parser ap {argc, argv, "ha:s:l:f:"};
        if (Arguments::print_help(ap.get<string>("-h"))) return 1; 
    
        InitICMPv4Messages();
        InitICMPv6Messages();

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
