#pragma once
#include "../config.hpp"
#include "plan.hpp"

namespace cryptowords {

// Fase 5 — Reporta o plano antes da busca começar.
class SearchReporter {
   public:
    static void print_plan(const OptimizedMnemonics& opt, const AppConfig& cfg);
};

}  // namespace cryptowords
