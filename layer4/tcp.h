#pragma once

#include <string>

namespace packet_analyzer::layer4 {
    using namespace std;

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

    string TcpFlagsString(uint8_t flags);
}
