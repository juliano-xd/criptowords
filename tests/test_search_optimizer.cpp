#include "../include/search_optimizer.hpp"
#include "../include/app_config.hpp"
#include <iostream>
#include <cassert>


void test_optimizer_auto_deduce() {
    std::cout << "[TDD] Testing SearchOptimizer Auto-Deduce Logic...\n";
    
    AppConfig config;
    config.coin = CoinTarget::BTC;
    config.pbkdf2_rounds = 2048;
    config.only_valids = true;
    config.use_gpu = false;
    config.unknows = 1;
    
    // Simulate 12 word mnemonic: last word unknown
    // 1031, 0, 382, 1437, 1408, 649, 1223, 496, 1252, 954, 3, ?
    config.mnemonics.push_back((uint16_t)1031);
    config.mnemonics.push_back((uint16_t)0);
    config.mnemonics.push_back((uint16_t)382);
    config.mnemonics.push_back((uint16_t)1437);
    config.mnemonics.push_back((uint16_t)1408);
    config.mnemonics.push_back((uint16_t)649);
    config.mnemonics.push_back((uint16_t)1223);
    config.mnemonics.push_back((uint16_t)496);
    config.mnemonics.push_back((uint16_t)1252);
    config.mnemonics.push_back((uint16_t)954);
    config.mnemonics.push_back((uint16_t)3);
    // Unknown is a full vector of 0-2047
    std::vector<uint16_t> unknown_wheel;
    for(uint16_t i=0; i<2048; ++i) unknown_wheel.push_back(i);
    config.mnemonics.push_back(unknown_wheel);
    
    config.wordlist.assign(2048, "word");
    
    OptimizedMnemonics plan = SearchOptimizer::build_plan(config);
    
    assert(plan.auto_deduce_last_word == true);
    assert(plan.wheels.size() == 1);
    assert(plan.wheels[0].size() == 128);
    assert(plan.total_combinations == 128);
    
    std::cout << "  -> Auto-Deduce logic passed.\n";
}

void test_optimizer_normal_search() {
    std::cout << "[TDD] Testing SearchOptimizer Normal Search (Middle Words)...\n";
    
    AppConfig config;
    config.coin = CoinTarget::BTC;
    config.only_valids = true;
    config.unknows = 2;
    
    std::vector<uint16_t> unknown_wheel;
    for(uint16_t i=0; i<2048; ++i) unknown_wheel.push_back(i);
    
    config.mnemonics.push_back((uint16_t)1031);
    config.mnemonics.push_back((uint16_t)0);
    config.mnemonics.push_back(unknown_wheel); // ?
    config.mnemonics.push_back(unknown_wheel); // ?
    config.mnemonics.push_back((uint16_t)1408);
    config.mnemonics.push_back((uint16_t)649);
    config.mnemonics.push_back((uint16_t)1223);
    config.mnemonics.push_back((uint16_t)496);
    config.mnemonics.push_back((uint16_t)1252);
    config.mnemonics.push_back((uint16_t)954);
    config.mnemonics.push_back((uint16_t)3);
    config.mnemonics.push_back((uint16_t)32); // advice
    
    config.wordlist.assign(2048, "word");
    
    OptimizedMnemonics plan = SearchOptimizer::build_plan(config);
    
    assert(plan.auto_deduce_last_word == false);
    assert(plan.wheels.size() == 2);
    assert(plan.wheels[0].size() == 2048);
    assert(plan.wheels[1].size() == 2048);
    assert(plan.total_combinations == 4194304);
    
    std::cout << "  -> Normal search logic passed.\n";
}

int main() {
    std::cout << "Running SearchOptimizer TDD Suite...\n";
    test_optimizer_auto_deduce();
    test_optimizer_normal_search();
    std::cout << "All tests passed!\n";
    return 0;
}
