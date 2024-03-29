#include <utility>

#include "arguments.h"
#include "utils.h"

namespace PacketAnalyzer { namespace Arguments {
    Parser::Parser(int argc, char* argv[], const char* arguments) {
        if (argc <= 0) throw BadArgsNum{};

        // process options
        for (int c {getopt(argc, argv, arguments)}; c != -1; c = getopt(argc, argv, arguments)) {
            switch(c) {
                case 'h': options["-h"] = help; break;
                case 'a': options["-a"] = aggr_key(optarg); break;
                case 's': options["-s"] = sort_key(optarg); break;
                case 'l': options["-l"] = limit(optarg); break;
                case 'f': options["-f"] = filter_expression(optarg); break;
                default: throw BadArgsStructure{};
            }
        }

        // process file names
        for(int i {optind}; i != argc; ++i)
            fileNames.emplace_back(argv[i]);

        if (fileNames.empty()) throw runtime_error{"No files specified!"};
    }
    
    string Parser::aggr_key(const string& s) const {
        if (s == "srcmac"  || s == "dstmac" ||
            s == "srcip"   || s == "dstip"  ||
            s == "srcport" || s == "dstport") { 
            return s;
        }

        throw runtime_error{"Invalid aggr-key: " + s};
    }

    string Parser::sort_key(const string& s) const {
        if (s == "packets"  || s == "bytes") return s;

        throw runtime_error{"Invalid sort-key: " + s};
    }

    string Parser::limit(const string& s) const {
        try { 
            Utils::to<unsigned>(s); 
        } catch(const runtime_error&) { 
            throw runtime_error {"Invalid limit number: " + s}; 
        }
        if (!s.empty() && s.front() == '-') throw runtime_error{"Limit number is negative!"};
        return s;
    }

    string Parser::filter_expression(const string& s) const {
        // TODO: check filter syntax
        return s;
    }

    bool print_help(Arguments::Parser& ap) {
        string help;
        bool set;
        tie(help,set) = ap.get<string>("-h");

        if (set) {
            cerr << help << '\n';
            return true;
        }
        return false;
    }
}}
