#include <CLI11.hpp>
#include <iostream>
#include <thread>
#include <print>

#include "listener.h"
#include "config.h"

using namespace std;


struct CLIOptions {
    bool verbose = false;
    bool quiet = false;
    vector<string> throttle_rules;
    vector<string> block_rules;
    vector<string> exclude_rules;
};


int main(int argc, char** argv) {
    CLI::App app{"netregu - WinDivert-based per-process network bandwidth limiter for Windows"};

    CLIOptions options;

    app.add_flag("-v,--verbose", options.verbose, "Enable verbose output (shows all packets)");
    app.add_flag("-q,--quiet", options.quiet, "Suppress non-error output");

    app.add_option("-t,--throttle", options.throttle_rules,
        "Add throttle rule\n"
        "\n"
        "Format: target:rate[:burst][:mode]\n"
        "\n"
        "Target options:\n"
        "  <PID>       - Specific process ID\n"
        "  <exe>       - Executable name\n"
        "  system      - All system processes\n"
        "  unknown     - Processes that couldn't be identified\n"
        "  global      - All network traffic (shared limiter)\n"
        "  each        - Each process gets individual limit\n"
        "\n"
        "Rate/Burst format:\n"
        "  Number with optional suffix: K (KiB/s), M (MiB/s), G (GiB/s)\n"
        "\n"
        "Throttle mode (optional, default shared limiter):\n"
        "  u           - Only limit upload\n"
        "  d           - Only limit download\n"
        "  s           - Shared limiter for both upload and download\n"
        "  i           - Individual limiters for upload and download\n")
        ->expected(0, -1);

    app.get_option("--throttle")->check([](const string& rule) -> string {
        if (rule.empty()) {
            return "Rule cannot be empty";
        }

        size_t first_colon = rule.find(':');
        if (first_colon == string::npos) {
            return "Invalid format. Expected 'target:rate[:burst]'";
        }

        string target = rule.substr(0, first_colon);
        if (target.empty()) {
            return "Target cannot be empty";
        }

        string remainder = rule.substr(first_colon + 1);
        if (remainder.empty()) {
            return "Rate cannot be empty";
        }

        return "";
    });

    app.add_option("-b,--block", options.block_rules,
        "Block traffic\n"
        "\n"
        "Format: target[:mode]\n"
        "\n"
        "Target options:\n"
        "  <PID>       - Specific process ID\n"
        "  <exe>       - Executable name\n"
        "  system      - All system processes\n"
        "  unknown     - Processes that couldn't be identified\n"
        "  global      - All network traffic\n"
        "\n"
        "Block mode (optional, default both):\n"
        "  u           - Only block upload\n"
        "  d           - Only block download\n"
        "  b           - Block both upload and download\n")
        ->expected(0, -1);

    app.get_option("--block")->check([](const string& rule) -> string {
        if (rule.empty()) {
            return "Rule cannot be empty";
        }

        size_t first_colon = rule.find(':');
        string target;

        if (first_colon == string::npos) {
            target = rule;
        } else {
            target = rule.substr(0, first_colon);
            if (target.empty()) {
                return "Target cannot be empty";
            }
        }

        return "";
    });

    app.add_option("-e,--exclude", options.exclude_rules,
        "Exclude from all rules\n"
        "\n"
        "Format: target\n"
        "\n"
        "Target options:\n"
        "  <PID>       - Specific process ID\n"
        "  <exe>       - Executable name\n"
        "  system      - All system processes\n"
        "  unknown     - Processes that couldn't be identified\n")
        ->expected(0, -1);

    app.get_option("--exclude")->check([](const string& rule) -> string {
        if (rule.empty()) {
            return "Rule cannot be empty";
        }
        return "";
    });

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    if (options.verbose && options.quiet) {
        println("Error: Cannot use both --verbose and --quiet");
        return 1;
    }

    g_config.verbose = options.verbose;
    g_config.quiet = options.quiet;


    thread flow_thread(flow_layer_listener);
    thread network_thread(network_layer_listener);
    thread queue_thread(packet_queue_processor);

    this_thread::sleep_for(chrono::milliseconds(500));


    for (auto& rule : options.exclude_rules) {
        if (rule.empty()) continue;
        transform(rule.begin(), rule.end(), rule.begin(), ::tolower);
        bool has_exe_suffix = rule.size() >= 4 && rule.substr(rule.size() - 4) == ".exe";
        if (!has_exe_suffix) {
            char first = rule.front();
            if (first == 's') {
                rule = "system";
            } else if (first == 'u') {
                rule = "unknown";
            }
        }
        println("Ignoring all rules for {}", 
            (all_of(rule.begin(), rule.end(), ::isdigit)) ? format("PID: {}", rule) : rule
        );
    }
    g_config.exclude_targets = options.exclude_rules;

    if (!options.throttle_rules.empty() || !options.block_rules.empty()) {
        for (const auto& rule : options.throttle_rules) {
            parse_and_apply_throttle_rule(rule);
        }
        for (const auto& rule : options.block_rules) {
            parse_and_apply_block_rule(rule);
        }
    } else {
        if (!options.quiet) {
            println("No throttle rules specified. Monitoring traffic only.");
            println("Use --help for more information about parameters.");
        }
    }

    if (!options.quiet) {
        println("\nPress Ctrl+C to stop...");
    }

    flow_thread.join();
    network_thread.join();
    queue_thread.join();

    return 0;
}