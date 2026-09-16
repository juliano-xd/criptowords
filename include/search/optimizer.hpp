#pragma once
#include "../config.hpp"
#include "plan.hpp"

class SearchOptimizer {
public:
    static OptimizedMnemonics build_plan(const AppConfig& cfg);
};
