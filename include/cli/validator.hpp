#pragma once
#include <expected>
#include <string>

#include "../config.hpp"

namespace cryptowords {

class ConfigValidator {
   public:
    static std::expected<AppConfig, std::string> validate(const RawOptions& raw);
};

}  // namespace cryptowords
