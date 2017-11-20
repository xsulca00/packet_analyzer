#pragma once

#include <string>
#include <stdexcept>

extern "C" {
#include <pcap.h>
}

#include "pcap_ptr.h"

namespace packet_analyzer::pcap {
    using namespace std;

    class PcapFilter {
    public:
        explicit PcapFilter(pcap_t* handle, const string& filter) {
            if (pcap_compile(handle, &compiledFilter, filter.c_str(), 0, 0) == -1) {
                throw runtime_error{"PcapFilter::pcap_compile() failed to compile: '" + filter + "'"};
            }

            if (pcap_setfilter(handle, &compiledFilter) == -1) {
                throw runtime_error{"PcapFilter::pcap_setfilter() failed to set compiled filter: " + filter};
            }
        }

        ~PcapFilter() { pcap_freecode(&compiledFilter); }
    private:
        bpf_program compiledFilter;
    };

    class Analyzer {
    public:
        Analyzer(const string& name, const string& filter)
            : pcapFile{name}, pcapFilter{pcapFile, filter}
        {}

        bool NextPacket() {
            packet = pcap_next(pcapFile, &header);
            return packet;
        }

        const u_char* Packet() const { return packet; }
        const pcap_pkthdr& Header() const { return header; };

    private:
        const u_char* packet {nullptr};
        pcap_pkthdr header {};
        PcapPtr pcapFile;
        PcapFilter pcapFilter;
    };
}
