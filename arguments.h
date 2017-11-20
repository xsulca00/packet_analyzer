#pragma once

extern "C" {
#include <unistd.h>
}

#include <iostream>
#include <unordered_map>
#include <string>
#include <map>
#include <vector>

#include "utils.h"

namespace packet_analyzer::parameters {
    using namespace std;

    // pair -> {packets, bytes}
    using AggrInfo = pair<size_t, size_t>;

    extern map<string, AggrInfo> aggregationsStatistics;

    void addAggr(const string& key, size_t size);

    struct Arguments {
        string help;
        string aggregation;
        string sortBy;
        string filter;
        string limit;
    };

    // program arguments passed via console
    extern Arguments arguments;

    struct ArgumentParser {
        ArgumentParser() = default;
        ArgumentParser(int argc, char* argv[], const char* getoptstr);

        bool IsSet(const string& s) { 
            const auto& o = arguments[s];
            if (o.empty()) return false;
            return true;
        }

        unordered_map<string, string> arguments;
        vector<string> files;
    };

    // parsing program arguments
    extern ArgumentParser argumentsParser;

    string CheckAggrKey(const string& s);
    string CheckSortKey(const string& s);
    string CheckLimit(const string& s);
    string CheckFilter(const string& s);
}
