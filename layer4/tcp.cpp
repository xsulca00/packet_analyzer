#include <string>

#include "tcp.h"

namespace packet_analyzer::layer4 {
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
}
