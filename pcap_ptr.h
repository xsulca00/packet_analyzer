#pragma once

#include <array>
#include <string>
#include <stdexcept>

extern "C" {
#include <pcap.h>
}

namespace PacketAnalyzer { namespace PCAP {
    using namespace std;

    class PcapPtr {
    public:
        explicit PcapPtr(const string& name)
            : handle {pcap_open_offline(name.c_str(), errbuf.data())}
        {
            if (!handle) throw runtime_error{"PcapPtr: Can't open pcap with name "s + errbuf.data()};
        }

        operator pcap_t*() { return handle; }

        ~PcapPtr() { pcap_close(handle); }
    private:
        array<char, PCAP_ERRBUF_SIZE> errbuf;
        pcap_t* handle;
    };
}}
