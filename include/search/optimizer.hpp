#pragma once
#include "../config.hpp"
#include "plan.hpp"

namespace cryptowords {

// Fase 3 — Otimização da busca. Recebe AppConfig validado e produz
// OptimizedMnemonics com wheels, estrutura de frase, modo de enumeração,
// ChecksumMode e contagens de espaço.
class SearchOptimizer {
   public:
    static OptimizedMnemonics build_plan(const AppConfig& cfg);
};

}  // namespace cryptowords
