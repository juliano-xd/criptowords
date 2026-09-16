#pragma once
#include "../config.hpp"
#include <expected>
#include <string>

class ConfigValidator {
public:
    static std::expected<AppConfig, std::string> validate(const RawOptions& raw);
};
