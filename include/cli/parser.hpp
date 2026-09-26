#pragma once
#include <expected>
#include <string>

#include "../config.hpp"

class CLIParser {
   public:
    // "HELP" é retornado como erro especial — main trata.
    static std::expected<RawOptions, std::string> parse(int argc, char* argv[]);
};
