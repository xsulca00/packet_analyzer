#pragma once 

#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits> 
#include <iostream>

namespace PacketAnalyzer { namespace Utils {
    using namespace std;

    template<typename T, typename U>
    constexpr bool Is_same() { return is_same<T,U>::value; }


    template<typename Target = string, typename Source = string>
    enable_if_t<!Is_same<Target, Source>(), Target> to(Source arg) {
        stringstream s;
        Target t;

        //cerr << "Source: '" << arg << "'" << '\n';
        //cerr << "Target: '" << t <<  "'" << '\n';

        if (!(s << arg) || !(s >> t) || !(s >> ws).eof())
            throw runtime_error {"to<>() failed!"};

        return t;
    }

    template<typename Target = string, typename Source = string>
    enable_if_t<Is_same<Target,Source>(), Source> to(Source arg) {
        return arg;
    }

    inline time_t ToMicroSeconds(const timeval& ts) {
        return 1'000'000UL * ts.tv_sec + ts.tv_usec;
    }

    /*
    template<>
    inline string to(string arg) {
        return arg;
    }
    */
}}

