#include <iostream>
#include <string>
#include <stdexcept>
#include <utility>
#include <algorithm>
#include <limits>

extern "C" {
#include <pcap.h>
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
#include "layer2.h"

using namespace packet_analyzer;
using namespace packet_analyzer::parameters;
using namespace std;

string HeaderInfo(const pcap_pkthdr* header) {
    // microseconds
    auto f = [](const timeval& ts) { return 1'000'000UL * ts.tv_sec + ts.tv_usec; };
    return to_string(f(header->ts)) + ' ' + to_string(header->len);
}

string PacketDissection(size_t n, const pcap_pkthdr* header, const uint8_t* packet) {
    ostringstream ss;
    ss << n << ": "  
       << HeaderInfo(header) << " | " 
       << layer2::Layer2(packet, header->len);
    return ss.str();
}

bool PacketsCompare(const pair<string,AggrInfo>& l, const pair<string,AggrInfo>& r) { return l.second.first > r.second.first; }
bool BytesCompare(const pair<string,AggrInfo>& l, const pair<string,AggrInfo>& r) { return l.second.second > r.second.second; }

int main(int argc, char* argv[]) {
    try {
        argumentsParser = {argc, argv, "ha:s:l:f:"};

        arguments.help        = argumentsParser.arguments["h"];
        arguments.aggregation = argumentsParser.arguments["a"];
        arguments.sortBy      = argumentsParser.arguments["s"];
        arguments.limit       = argumentsParser.arguments["l"];
        arguments.filter      = argumentsParser.arguments["f"];

        // need help
        if (argumentsParser.IsSet("h")) {
            cerr << arguments.help << '\n';
            return 1;
        }

        // elevate limit
        size_t limit = numeric_limits<size_t>::max();
        if (argumentsParser.IsSet("l")) limit = utils::to<size_t>(arguments.limit);

        // packet counter
        size_t packetsCount = 1;

        // where packet dissection is stored, AggrInfo -> because of sorting
        vector<pair<string, AggrInfo>> v; 

        bool IsAggregationSet = argumentsParser.IsSet("a");
        bool IsSortBySet = argumentsParser.IsSet("s");

        // traverse all files
        for (const auto& name : argumentsParser.files) {
            bpf_program filter;
            char errbuffer[PCAP_ERRBUF_SIZE];
            pcap_t* handle = pcap_open_offline(name.c_str(), errbuffer);
            
            // open file, compile filter, set filter
            if (handle) {
                if (pcap_compile(handle, &filter, arguments.filter.c_str(), 0, 0) == -1) {
                    cerr << "pcap_compile(): failed to compile: " << arguments.filter << '\n';
                    pcap_close(handle);
                    continue;
                }

                if (pcap_setfilter(handle, &filter) == -1) {
                    cerr << "pcap_setfilter(): failed to set filter\n";
                    pcap_close(handle);
                    continue;
                }
            } else {
                cerr << "pcap_open_offline() failed: " << errbuffer << '\n';
                continue;
            }

            const uint8_t* packet;
            pcap_pkthdr header;

            // traverse packets in file
            for (; (packet = pcap_next(handle, &header)) != NULL; ++packetsCount) {
                try {
                    // no aggregation, just put packet info into vector
                    if (!IsAggregationSet) {
                        auto p = make_pair(PacketDissection(packetsCount, &header, packet), 
                                           make_pair(1, header.len));
                        v.push_back(p);
                    } else {
                        // aggreagation is set, need to process packet
                        PacketDissection(packetsCount, &header, packet);
                    }
                } catch (const InvalidProtocol& e) {
                    cerr << e.what() << '\n';
                }
            }

            pcap_freecode(&filter);
        }

        // copy map with aggregations into vector because of sort
        if (IsAggregationSet) {
            copy(aggregationsStatistics.begin(), aggregationsStatistics.end(), back_inserter(v));
        }

        if (IsSortBySet) {
            sort(v.begin(), v.end(), (arguments.sortBy == "packets") ? PacketsCompare : BytesCompare);
        }

        // print all info
        size_t i = 1;
        if (IsAggregationSet) {
            for (const auto& p : v) {
                if (i <= limit) {
                    cout << p.first << ": " << p.second.first << ' ' << p.second.second << '\n';
                    i++;
                }
            }
        } else {
            for (const auto& p : v) {
                if (i <= limit) {
                    cout << p.first << '\n';
                    i++;
                }
            }
        }
    } catch (const runtime_error& e) {
        cerr << "Runtime error caught: " << e.what() << '\n';
        return 4;
    }
}
