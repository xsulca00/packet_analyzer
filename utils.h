#pragma once 

#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits> 
#include <iostream>

namespace packet_analyzer::utils {
    using namespace std;

    template<typename Target = string, typename Source = string>
    enable_if_t<!is_same<Target, Source>::value, Target> to(Source arg) {
        stringstream s;
        Target t;

        if (!(s << arg) || 
            !(s >> t) || 
            !(s >> ws).eof())
            throw runtime_error {"to<>() failed!"};

        return t;
    }

    template<typename Target = string, typename Source = string>
    enable_if_t<is_same<Target,Source>::value, Source> to(Source arg) {
        return arg;
    }
}

