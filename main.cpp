#include <iostream>
#include <string>
#include <stdexcept>
#include <map>
#include <utility>
#include <cstring>
#include <sstream>
#include <iomanip>

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
#include <netinet/udp.h>
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

string InfoVLAN(const uint8_t* packet) {
    uint32_t bytes {ntohl(*(uint32_t*)(packet + 12))};

    HeaderVLAN vlan {*(HeaderVLAN*)&bytes};

    /*cout << "\nTPID: " << hex << vlan.tpid << '\n'
         << "PCP:  " << dec <<vlan.tci.pcp <<  '\n'
         << "DEI:  " << vlan.tci.dei << '\n'
         << "VID:  " << vlan.tci.vid << '\n';
         */

    return ' ' + to_string(vlan.tci.vid);
}

pair<const uint8_t*, int> SkipVLAN(const uint8_t* packet) {
    int packetType {ntohs(*(uint16_t*)(packet + 16))};
    packet += 4;

    return make_pair(packet, packetType);
}

string PrintMAC(const ether_addr* mac) {
    const uint8_t* octets {&mac->ether_addr_octet[0]};

    ostringstream ss;
    ss.fill('0');
    ss << hex << setw(2) << unsigned{octets[0]} << ':' 
              << setw(2) << unsigned{octets[1]} << ':' 
              << setw(2) << unsigned{octets[2]} << ':' 
              << setw(2) << unsigned{octets[3]} << ':' 
              << setw(2) << unsigned{octets[4]} << ':' 
              << setw(2) << unsigned{octets[5]};
    return ss.str();
}

pair<string, string> SrcDstMAC(const uint8_t* packet) {
    const ether_header* eptr {reinterpret_cast<const ether_header*>(packet)};

    string SrcMAC {PrintMAC((const ether_addr*)(&eptr->ether_shost))};
    string DstMAC {PrintMAC((const ether_addr*)(&eptr->ether_dhost))};

    return make_pair(SrcMAC, DstMAC);
}

int EtherType(const uint8_t* packet) {
    const ether_header* eptr {reinterpret_cast<const ether_header*>(packet)};
    return ntohs(eptr->ether_type);
}

string MakeIPv4StringToPrint(const ip& packetIP) {
    string SrcIP {inet_ntoa(packetIP.ip_src)};
    string DstIP {inet_ntoa(packetIP.ip_dst)};

    return "IPv4: " + SrcIP + ' ' + DstIP + ' ' + to_string(packetIP.ip_ttl);
}

string MakeIPv6StringToPrint(const ip6_hdr& ip) {
    array<char, INET6_ADDRSTRLEN> buf;

    string SrcIP {inet_ntop(AF_INET6, (void*)(&ip.ip6_src), buf.data(), buf.size())};
    string DstIP {inet_ntop(AF_INET6, (void*)(&ip.ip6_dst), buf.data(), buf.size())};

    return "IPv6: " + SrcIP + ' ' + DstIP + ' ' + to_string(ip.ip6_hlim);
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
enum class UpperLayerIPv6 { TCP = 6, UDP = 17, ICMPv6 = 58  };
enum class ExtensionsIPv6 { HopByHop = 0, 
                            Routing = 43,
                            // Fragment header not supported
                            DestinationOptions = 60,
                            NoNextHeader = 59 };

inline bool IsIPv6Extension(uint8_t number) {
    ExtensionsIPv6 n {static_cast<ExtensionsIPv6>(number)};
    return n == ExtensionsIPv6::HopByHop ||
           n == ExtensionsIPv6::Routing || 
           n == ExtensionsIPv6::DestinationOptions || 
           n == ExtensionsIPv6::NoNextHeader;
}

inline bool IsProtocolFromL4(uint8_t number) {
    UpperLayerIPv6 n {static_cast<UpperLayerIPv6>(number)};
    return n == UpperLayerIPv6::TCP || 
           n == UpperLayerIPv6::UDP || 
           n == UpperLayerIPv6::ICMPv6;
}

pair<uint8_t, const uint8_t*> SkipExtensions(const uint8_t* packet) {
    ip6_hdr& packetIP {*(ip6_hdr*)packet};
    uint8_t next {packetIP.ip6_nxt};
    const uint8_t* p {packet + HeaderLenIPv6()};

    const ip6_ext* e {(ip6_ext*)p};

    for (; !IsProtocolFromL4(next);) {
        // cout << " next: " << unsigned{next} << ' ';
        next = e->ip6e_nxt;
        p += (e->ip6e_len + 1)*8;
        e = (ip6_ext*)p;
    }

    // cout << " next: " << unsigned{next} << '\n';
    return make_pair(next, p);
}


class ICMPv4ErrorMessages {
public:
    ICMPv4ErrorMessages() {
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

    pair<string, string> MessageFor(uint8_t type, uint8_t code) const {
        auto pos = errorMsgICMPv4.find(type);
        if (pos != errorMsgICMPv4.end()) {
            const auto& info = pos->second;
            if (code < info.second.size()) {
                return make_pair(info.first, info.second[code]);
            }
        }
        return make_pair("", "");
    }
private:
    map<int, pair<string, vector<string>>> errorMsgICMPv4;
};

class ICMPv6ErrorMessages {
public:
    ICMPv6ErrorMessages() {
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

    pair<string, string> MessageFor(uint8_t type, uint8_t code) const {
        auto pos = errorMsgICMPv6.find(type);
        if (pos != errorMsgICMPv6.end()) {
            const auto& info = pos->second;
            if (code < info.second.size()) {
                return make_pair(info.first, info.second[code]);
            }
        }
        return make_pair("", "");
    }
private:
    map<int, pair<string, vector<string>>> errorMsgICMPv6;
};

inline bool IsICMPv4(const ip& ip) {
    return ip.ip_p == 1;
}

string PrintICMPv4(uint8_t type, uint8_t code) {
    static ICMPv4ErrorMessages ICMPv4Messages;

    string typeMsg;
    string codeMsg;
    tie(typeMsg, codeMsg) = ICMPv4Messages.MessageFor(type, code);

    string errorMsg;

    if (!typeMsg.empty() && !codeMsg.empty()) {
        errorMsg = ' ' + typeMsg + ' ' + codeMsg;
    }

    return "ICMPv4: " + to_string(type) + ' ' + to_string(code) + errorMsg;
}

string PrintICMPv6(uint8_t type, uint8_t code) {
    static ICMPv6ErrorMessages ICMPv6Messages;

    string typeMsg;
    string codeMsg;
    tie(typeMsg, codeMsg) = ICMPv6Messages.MessageFor(type, code);

    string errorMsg;

    if (!typeMsg.empty() && !codeMsg.empty()) {
        errorMsg = ' ' + typeMsg + ' ' + codeMsg;
    }

    return "ICMPv6: " + to_string(type) + ' ' + to_string(code) + errorMsg;
}

inline bool IsICMPv6(uint8_t next) {
    return static_cast<UpperLayerIPv6>(next) == UpperLayerIPv6::ICMPv6;
}

inline bool NoNextProtocol(uint8_t next) {
    return static_cast<ExtensionsIPv6>(next) == ExtensionsIPv6::NoNextHeader;
}

inline const uint8_t* SkipICMPv4Header(const uint8_t* packetL3) {
    return packetL3 + sizeof(icmphdr);
}

inline const uint8_t* SkipICMPv6Header(const uint8_t* packetL3) {
    return packetL3 + sizeof(icmp6_hdr);
}

inline const uint8_t* SkipIPv4Header(const uint8_t* packetL3) {
    return packetL3 + HeaderLenIPv4(*(ip*)packetL3);
}

enum class Flags { CWR = 128, ECE = 64, URG = 32, ACK = 16, PSH = 8, RST = 4, SYN = 2, FIN = 1, NotSet = 0 };
constexpr Flags operator&(Flags l, Flags r) {
    return static_cast<Flags>(static_cast<uint8_t>(l) & static_cast<uint8_t>(r));
}

constexpr bool operator==(Flags l, Flags r) {
    return static_cast<uint8_t>(l) == static_cast<uint8_t>(r);
}

constexpr bool operator!=(Flags l, Flags r) {
    return !(l == r);
}

string TcpFlagsString(uint8_t flags) {
    Flags f {static_cast<Flags>(flags)};
    string s;

    if ((f & Flags::CWR) != Flags::NotSet)
        s += 'C';
    else
        s += '.';

    if ((f & Flags::ECE) != Flags::NotSet)
        s += 'E';
    else
        s += '.';

    if ((f & Flags::URG) != Flags::NotSet)
        s += 'U';
    else
        s += '.';

    if ((f & Flags::ACK) != Flags::NotSet)
        s += 'A';
    else
        s += '.';

    if ((f & Flags::PSH) != Flags::NotSet)
        s += 'P';
    else
        s += '.';

    if ((f & Flags::RST) != Flags::NotSet)
        s += 'R';
    else
        s += '.';

    if ((f & Flags::SYN) != Flags::NotSet)
        s += 'S';
    else
        s += '.';

    if ((f & Flags::FIN) != Flags::NotSet)
        s += 'F';
    else
        s += '.';

    return s;
}

string PacketLayer4(const uint8_t* packetL4, int packetType) {
    enum class Layer4 { TCP = 6, UDP = 17 };

    switch (static_cast<Layer4>(packetType)) {
        case Layer4::TCP: 
        {
            const tcphdr& tcp {*(tcphdr*)packetL4};
            ostringstream ss;
            ss  << "TCP: " << ntohs(tcp.th_sport) << ' ' << ntohs(tcp.th_dport) << ' '
                << ntohl(tcp.th_seq) << ' ' << ntohl(tcp.th_ack) << ' ' << TcpFlagsString(tcp.th_flags);
            return ss.str();
        }
        case Layer4::UDP: 
        {
            const udphdr& udp {*(udphdr*)packetL4};
            ostringstream ss;
            ss << "UDP: " << ntohs(udp.uh_sport) << ' ' << ntohs(udp.uh_dport);
            return ss.str();
        }
        default: throw runtime_error{"Layer4: Unknown packet type: " + to_string(packetType)};
    }
}

string PacketLayer3(const uint8_t* packetL3, int packetType) {
    enum class Layer3 { IPv4 = ETHERTYPE_IP, IPv6 = ETHERTYPE_IPV6, ICMPv4 = 1 };

    string msg;

    string SrcIP;
    string DstIP;

    switch(static_cast<Layer3>(packetType)) {
        case Layer3::IPv4: 
        {
            const ip& packet {*(ip*)packetL3};

            // TODO: rfc 815 algorithm
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
                    msg += MakeIPv4StringToPrint(packet);

                    if (IsICMPv4(packet)) {
                        const icmphdr& icmp {*(icmphdr*)(packetL3 + HeaderLenIPv4(packet))};
                        return msg + " | " + PrintICMPv4(icmp.type, icmp.code);
                    }

                    packetL3 = SkipIPv4Header(packetL3);
                    packetType = packet.ip_p;
                }
            } else {
                msg += MakeIPv4StringToPrint(packet);

                if (IsICMPv4(packet)) {
                    const icmphdr& icmp {*(icmphdr*)(packetL3 + HeaderLenIPv4(packet))};
                    return msg + " | " + PrintICMPv4(icmp.type, icmp.code);
                }

                packetL3 = SkipIPv4Header(packetL3);
                packetType = packet.ip_p;
            }

            break;
        }
        case Layer3::IPv6: 
        {
            const ip6_hdr& packetIP {*(ip6_hdr*)packetL3};

            msg += MakeIPv6StringToPrint(packetIP);
            
            uint8_t next {};
            tie(next, packetL3) = SkipExtensions(packetL3);

            if (NoNextProtocol(next)) {
                return msg;
            }

            if (IsICMPv6(next)) {
                const icmp6_hdr& icmp {*(icmp6_hdr*)(packetL3)};
                return msg + " | " + PrintICMPv6(icmp.icmp6_type, icmp.icmp6_code);
            }

            packetType = next;
            break;
        }
        default: throw runtime_error{"Layer3: Unknown packet type: " + to_string(packetType)};
    }

    if (!IsProtocolFromL4(packetType)) return msg;

    return msg + " | " + PacketLayer4(packetL3, packetType);
}

string PrintSrcDstMAC(const uint8_t* packet) {
    string SrcMAC;
    string DstMAC;
    tie(SrcMAC, DstMAC) = SrcDstMAC(packet);
    return "Ethernet: " + SrcMAC + ' ' + DstMAC;
}

string PacketLayer2(const uint8_t* packet) {
    enum class Layer2 { IEEE_802_1q  = 0x8100, IEEE_802_1ad = 0x88a8 };

    string msg;

    msg += PrintSrcDstMAC(packet);

    auto packetType = EtherType(packet);
    switch (static_cast<Layer2>(packetType)) {
        case Layer2::IEEE_802_1q:
        {
            msg += InfoVLAN(packet);
            tie(packet, packetType) = SkipVLAN(packet);
            break;
        }
        case Layer2::IEEE_802_1ad: 
        {
            msg += InfoVLAN(packet);
            tie(packet, packetType) = SkipVLAN(packet);
            msg += InfoVLAN(packet);
            tie(packet, packetType) = SkipVLAN(packet);
            break;
        }
        default: runtime_error{"Unknown frame type: " + to_string(packetType)};
    }

    constexpr auto ipOffset {14};
    return msg + " | " + PacketLayer3(packet+ipOffset, packetType);
}

string PrintHeader(const pcap_pkthdr& header) {
    return to_string(ToMicroSeconds(header.ts)) +' ' + to_string(header.len);
}

string PrintPacket( const uint8_t* packet) {
    return PacketLayer2(packet);
}

void PrintAllPacketsInFile(const string& name ) {
    static size_t packetsCount {1};

    for (PCAP::Analyzer a {name}; a.NextPacket(); ++packetsCount) {
        // TODO: do not print fragmented packet
        if (true) {
            cout    << packetsCount << ": " 
                    << PrintHeader(a.Header()) << " | " 
                    << PrintPacket(a.Packet()) << '\n';
        }
    }
}

int main(int argc, char* argv[]) {
    try {
        Arguments::Parser ap {argc, argv, "ha:s:l:f:"};
        if (Arguments::print_help(ap.get<string>("-h"))) return 1; 
    
        //print_all(ap);

        const string& l {ap.get<string>("-l")};
        if (!l.empty())
            size_t limit {ap.get<size_t>("-l")};
        else
            cout << "Limit set!\n";



        for (const auto& name : ap.files()) {
            PrintAllPacketsInFile(name);
        }

        /*
        for (const auto& p : fragments)
            cout << p.second.maxSize << " : " <<p.second.currentSize << '\n';
            */
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
