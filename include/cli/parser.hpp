#pragma once
#include "../config.hpp"
#include <expected>
#include <string>

class CLIParser {
public:
    // "HELP" é retornado como erro especial — main trata.
    static std::expected<RawOptions, std::string> parse(int argc, char* argv[]);
};
