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
        arguments::Parser ap {argc, argv, "ha:s:l:f:"};

        using arguments::options;
        using arguments::Aggregation;

        options.help        = ap.get<string>("-h");
        options.aggregation = ap.get<string>("-a");
        options.sortBy      = ap.get<string>("-s");
        options.limit       = ap.get<size_t>("-l");
        options.filter      = ap.get<string>("-f");

        if (options.help.second) {
            cerr << options.help.first << '\n';
            return 1;
        }

        size_t limit {numeric_limits<size_t>::max()};
        if (options.limit.second) limit = options.limit.first;

        size_t packetsCount {1};

        vector<pair<string, Aggregation>> v; 


        for (const auto& name : ap.files()) {
            for (pcap::Analyzer a {name, options.filter.first}; a.NextPacket(); ++packetsCount) {
                try {
                    if (!options.aggregation.second) {
                        auto p = make_pair(PacketDissection(packetsCount, a.Header(), a.Packet()), 
                                           Aggregation{1, a.Header().len});
                        v.push_back(p);
                    } else {
                        PacketDissection(packetsCount, a.Header(), a.Packet());
                    }
                } catch (const utils::BadProtocolType bpt) {
                    cerr << bpt.what() << '\n';
                }
            }
        }

        if (options.aggregation.second) {
            using arguments::aggregations;
            copy(aggregations.begin(), aggregations.end(), back_inserter(v));
        }

        if (options.sortBy.second) {
            const string& sortBy = options.sortBy.first;
            if (sortBy == "packets") {
                auto f = [](const pair<string,Aggregation>& l, const pair<string,Aggregation>& r) { return l.second.packets > r.second.packets; };
                sort(v.begin(), v.end(), f);
            } else if (sortBy == "bytes") {
            auto f = [](const pair<string,Aggregation>& l, const pair<string,Aggregation>& r) { return l.second.bytes > r.second.bytes; };
                sort(v.begin(), v.end(), f);
            }
        }

        if (options.aggregation.second) {
            size_t i {1};
            for (const auto& p : v) {
                if (i++ <= limit)
                    cout << p.first << ": " << p.second.packets << ' ' << p.second.bytes << '\n';
            }
        } else {
            size_t i {1};
            for (const auto& p : v) {
                if (i++ <= limit)
                    cout << p.first << '\n';
            }
        }
    } catch (arguments::Parser::BadArgsStructure) {
        // no message because getopt writes error by itself
        return 2;
    } catch (arguments::Parser::BadArgsNum) {
        cerr << "Invalid arguments count!\n";
        return 3;
    } catch (const runtime_error& e) {
        cerr << "Runtime error caught: " << e.what() << '\n';
        return 4;
    }
}
