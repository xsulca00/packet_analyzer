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
#include "analyzer.h"
#include "layer2.h"

using namespace packet_analyzer;
using namespace packet_analyzer::parameters;
using namespace std;

string PrintHeader(const pcap_pkthdr& header) {
    return to_string(utils::ToMicroSeconds(header.ts)) +' ' + to_string(header.len);
}

string PacketDissection(size_t n, const pcap_pkthdr& header, const uint8_t* packet) {
    return to_string(n) + ": " + 
           PrintHeader(header) + " | " +
           layer2::Layer2(packet, header.len);
}

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

        size_t limit = numeric_limits<size_t>::max();
        if (argumentsParser.IsSet("l")) limit = utils::to<size_t>(arguments.limit);

        size_t packetsCount = 1;

        vector<pair<string, AggrInfo>> v; 

        bool IsAggregationSet = argumentsParser.IsSet("a");
        bool IsSortBySet = argumentsParser.IsSet("s");

        for (const auto& name : argumentsParser.files) {
            for (pcap::Analyzer a {name, arguments.filter}; a.NextPacket(); ++packetsCount) {
                try {
                    if (!IsAggregationSet) {
                        auto p = make_pair(PacketDissection(packetsCount, a.Header(), a.Packet()), 
                                           make_pair(1, a.Header().len));
                        v.push_back(p);
                    } else {
                        PacketDissection(packetsCount, a.Header(), a.Packet());
                    }
                } catch (const utils::BadProtocolType bpt) {
                    cerr << bpt.what() << '\n';
                }
            }
        }

        if (IsAggregationSet) {
            copy(aggregationsStatistics.begin(), aggregationsStatistics.end(), back_inserter(v));
        }

        if (IsSortBySet) {
            const string& sortBy = arguments.sortBy;
            if (sortBy == "packets") {
                auto f = [](const pair<string,AggrInfo>& l, const pair<string,AggrInfo>& r) { return l.second.first > r.second.first; };
                sort(v.begin(), v.end(), f);
            } else if (sortBy == "bytes") {
            auto f = [](const pair<string,AggrInfo>& l, const pair<string,AggrInfo>& r) { return l.second.second > r.second.second; };
                sort(v.begin(), v.end(), f);
            }
        }

        if (IsAggregationSet) {
            size_t i {1};
            for (const auto& p : v) {
                if (i++ <= limit)
                    cout << p.first << ": " << p.second.first << ' ' << p.second.second << '\n';
            }
        } else {
            size_t i {1};
            for (const auto& p : v) {
                if (i++ <= limit)
                    cout << p.first << '\n';
            }
        }
    } catch (const runtime_error& e) {
        cerr << "Runtime error caught: " << e.what() << '\n';
        return 4;
    }
}
