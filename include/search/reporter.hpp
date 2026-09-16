#pragma once
#include "../config.hpp"
#include "plan.hpp"

class SearchReporter {
public:
    static void print_plan(const OptimizedMnemonics& opt, const AppConfig& cfg);
};
