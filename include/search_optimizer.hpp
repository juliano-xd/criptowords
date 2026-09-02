#pragma once
#include "app_config.hpp"
#include "search_plan.hpp"

class SearchOptimizer {
  public:
    static OptimizedMnemonics build_plan(const AppConfig& cfg);
    static void print_report(const OptimizedMnemonics& opt, const AppConfig& cfg);
};
