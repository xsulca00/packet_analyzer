#pragma once 

#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits> 

namespace PacketAnalyzer { namespace Utils {
    using namespace std;

    template<typename T, typename U>
    constexpr bool Is_same() { return is_same<T,U>::value; }

    template<typename Target = string, typename Source = string>
    Target to(Source arg) {
        stringstream s;
        Target t;

        if (!(s << arg) || !(s >> t) || !(s >> ws).eof())
            // TODO: not sure if this is correct
            if (!Is_same<Target,Source>())
                throw runtime_error {"to<>() failed!"};

        return t;
    }

}}

