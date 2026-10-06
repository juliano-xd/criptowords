#include "test_framework.hpp"

#include <array>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <variant>
#include <vector>

#include "../include/config.hpp"
#include "../include/search/checkpoint.hpp"
#include "../include/search/context.hpp"
#include "../include/search/odometer.hpp"
#include "../include/search/optimizer.hpp"
#include "../include/search/plan.hpp"

using namespace cryptowords;

namespace {

AppConfig make_test_config(size_t n_words = 12) {
    AppConfig cfg;
    cfg.wordlist.resize(2048);
    for (size_t i = 0; i < 2048; ++i) cfg.wordlist[i] = "w" + std::to_string(i);
    cfg.separator = " ";
    cfg.pbkdf2_rounds = 2048;
    cfg.only_valids = true;
    cfg.mnemonics.assign(n_words, static_cast<uint16_t>(0));
    return cfg;
}

void set_unknowns(AppConfig& cfg, std::initializer_list<size_t> positions) {
    for (size_t p : positions) cfg.mnemonics[p] = AppConfig::UNKNOWN_WORD;
    size_t raw = 0;
    for (const auto& w : cfg.mnemonics)
        if (std::holds_alternative<uint16_t>(w) &&
            std::get<uint16_t>(w) == AppConfig::UNKNOWN_WORD) ++raw;
    cfg.raw_unknowns = raw;
    cfg.n_unknowns   = raw;
}

}  // namespace

// =========================================================================
// Wheel — bitset + lista
// =========================================================================
TEST_CASE(wheel_bitset_operations) {
    Wheel w;
    w.push_back(10);
    w.push_back(42);
    w.push_back(2047);

    REQUIRE_EQ(w.size(), size_t{3});
    REQUIRE(w.contains(10));
    REQUIRE(w.contains(42));
    REQUIRE(w.contains(2047));
    REQUIRE(!w.contains(0));
    REQUIRE(!w.contains(100));
    REQUIRE(!w.contains(2046));

    w.words.clear();
    w.rebuild_mask();
    REQUIRE(!w.contains(10));
    REQUIRE_EQ(w.size(), size_t{0});
}

// =========================================================================
// build_plan — sem incógnitas
// =========================================================================
TEST_CASE(build_plan_no_unknowns) {
    auto cfg = make_test_config();
    auto opt = SearchOptimizer::build_plan(cfg);

    REQUIRE(opt.unknown_positions.empty());
    REQUIRE(opt.total_combinations == 1.0);
    REQUIRE(opt.mode == SearchMode::Mixed);
    REQUIRE(opt.checksum_mode == ChecksumMode::None);
    REQUIRE(opt.count_eliminations);
}

// =========================================================================
// build_plan — K=1, última palavra conhecida
// =========================================================================
TEST_CASE(build_plan_one_unknown_last_known) {
    auto cfg = make_test_config();
    set_unknowns(cfg, {0});
    auto opt = SearchOptimizer::build_plan(cfg);

    REQUIRE_EQ(opt.unknown_positions.size(), size_t{1});
    REQUIRE(opt.mode == SearchMode::Mixed);
    REQUIRE(opt.checksum_mode == ChecksumMode::Expected);
    REQUIRE(opt.count_eliminations);
    REQUIRE_EQ(opt.original_wheels.size(), opt.wheels.size());
    REQUIRE_EQ(opt.wheels[0].size(), size_t{2048});
}

// =========================================================================
// build_plan — K=1, única incógnita é a última palavra
// =========================================================================
TEST_CASE(build_plan_one_unknown_last_unknown) {
    auto cfg = make_test_config();
    set_unknowns(cfg, {11});
    auto opt = SearchOptimizer::build_plan(cfg);

    REQUIRE_EQ(opt.unknown_positions.size(), size_t{1});
    REQUIRE(opt.mode == SearchMode::Mixed);
    REQUIRE(opt.checksum_mode == ChecksumMode::SelfVerify);
    REQUIRE_EQ(opt.wheels[0].size(), size_t{2048});
}

// =========================================================================
// build_plan — K=2, última palavra conhecida
// =========================================================================
TEST_CASE(build_plan_two_unknowns_last_known) {
    auto cfg = make_test_config();
    set_unknowns(cfg, {2, 5});
    auto opt = SearchOptimizer::build_plan(cfg);

    REQUIRE_EQ(opt.unknown_positions.size(), size_t{2});
    REQUIRE(opt.mode == SearchMode::Mixed);
    REQUIRE(opt.checksum_mode == ChecksumMode::Expected);
    REQUIRE(opt.count_eliminations);
}

// =========================================================================
// build_plan — K=2, última incógnita é a última palavra (entropy trick)
// =========================================================================
TEST_CASE(build_plan_two_unknowns_last_unknown) {
    auto cfg = make_test_config();
    set_unknowns(cfg, {3, 11});
    auto opt = SearchOptimizer::build_plan(cfg);

    REQUIRE_EQ(opt.unknown_positions.size(), size_t{2});
    REQUIRE(opt.mode == SearchMode::Mixed);
    REQUIRE(opt.checksum_mode == ChecksumMode::AutoDeduce);
    REQUIRE(opt.has_cascade_deduction);
    REQUIRE(opt.count_eliminations);

    REQUIRE_EQ(opt.wheels.back().size(), size_t{128});
    REQUIRE_EQ(opt.original_wheels.size(), opt.wheels.size());
    REQUIRE_EQ(opt.original_wheels.back().size(), size_t{2048});
    REQUIRE(opt.allowed_last_words.any());
}

// =========================================================================
// build_plan — K=2, --invalid_too: sem entropy trick, sem filtro
// =========================================================================
TEST_CASE(build_plan_invalid_too_no_filter) {
    auto cfg = make_test_config();
    cfg.only_valids = false;
    set_unknowns(cfg, {3, 11});
    auto opt = SearchOptimizer::build_plan(cfg);

    REQUIRE(opt.mode == SearchMode::Mixed);
    REQUIRE(opt.checksum_mode == ChecksumMode::None);
    REQUIRE(!opt.count_eliminations);
    REQUIRE_EQ(opt.wheels.back().size(), size_t{2048});
}

// =========================================================================
// build_plan — K=3, última incógnita na última posição, --only_valids
// =========================================================================
TEST_CASE(build_plan_three_unknowns_streaming) {
    auto cfg = make_test_config();
    set_unknowns(cfg, {0, 1, 11});
    auto opt = SearchOptimizer::build_plan(cfg);

    REQUIRE_EQ(opt.unknown_positions.size(), size_t{3});
    REQUIRE(opt.mode == SearchMode::Streaming);
    REQUIRE(opt.has_cascade_deduction);
    REQUIRE_EQ(opt.wheels.back().size(), size_t{128});
    REQUIRE_EQ(opt.original_wheels.back().size(), size_t{2048});
}

// =========================================================================
// build_plan — --checksum sobrepõe --only_valids e --invalid_too
// =========================================================================
TEST_CASE(build_plan_user_checksum_overrides) {
    auto cfg = make_test_config();
    cfg.has_checksum_filter = true;
    cfg.checksum_repr = "0b*1*0";
    ChecksumPattern p;
    p.mask  = 0b0101;
    p.value = 0b0100;
    cfg.checksum_patterns.push_back(p);

    set_unknowns(cfg, {3, 11});
    auto opt = SearchOptimizer::build_plan(cfg);

    REQUIRE(opt.mode == SearchMode::Mixed);
    REQUIRE(opt.checksum_mode == ChecksumMode::UserPattern);
    REQUIRE(opt.count_eliminations);
    REQUIRE_EQ(opt.allowed_checksum_bits.count(), size_t{4});
}

// =========================================================================
// build_plan — reorder por tamanho: wheels menores primeiro (Mixed)
// =========================================================================
TEST_CASE(build_plan_reorder_by_size) {
    auto cfg = make_test_config();
    // Duas incógnitas com tamanhos desiguais. K=2 fica em Mixed (reorder
    // completo — em Streaming o último wheel é preservado).
    cfg.mnemonics[0] = std::vector<uint16_t>{100};
    cfg.mnemonics[1] = std::vector<uint16_t>{200, 201, 202, 203, 204, 205,
                                             206, 207, 208, 209, 210};
    cfg.n_unknowns = 0;
    for (const auto& w : cfg.mnemonics)
        if (std::holds_alternative<std::vector<uint16_t>>(w)) cfg.n_unknowns++;
    cfg.raw_unknowns = cfg.n_unknowns;

    auto opt = SearchOptimizer::build_plan(cfg);

    REQUIRE(opt.mode == SearchMode::Mixed);
    REQUIRE_EQ(opt.wheels[0].size(), size_t{1});
    REQUIRE_EQ(opt.wheels[1].size(), size_t{11});
    REQUIRE_EQ(opt.unknown_positions[0], size_t{0});
    REQUIRE_EQ(opt.unknown_positions[1], size_t{1});
}

// =========================================================================
// Odometer — Mixed enumera todos os candidatos e volta done
// =========================================================================
TEST_CASE(odometer_mixed_enumerates_all) {
    auto cfg = make_test_config();
    set_unknowns(cfg, {0, 5});
    auto opt = SearchOptimizer::build_plan(cfg);

    opt.wheels[0] = Wheel{};
    opt.wheels[0].push_back(1);
    opt.wheels[0].push_back(2);
    opt.wheels[1] = Wheel{};
    opt.wheels[1].push_back(10);
    opt.wheels[1].push_back(11);
    opt.wheels[1].push_back(12);

    auto odom = make_odometer(opt);
    PipelineThreadContext ctx;
    odom->init_state(ctx, 0, 1, opt);

    REQUIRE(!ctx.cursor.done);
    size_t count = 0;
    do { ++count; } while (odom->advance(ctx, opt));

    REQUIRE_EQ(count, size_t{6});
    REQUIRE(ctx.cursor.done);
    REQUIRE_EQ(odom->total_space(opt), uint64_t{6});
}

// =========================================================================
// Odometer — Streaming enumera todos os outer states
// =========================================================================
TEST_CASE(odometer_streaming_enumerates_all_outer_states) {
    auto cfg = make_test_config();
    set_unknowns(cfg, {0, 1, 11});
    auto opt = SearchOptimizer::build_plan(cfg);

    opt.wheels[0] = Wheel{};
    opt.wheels[0].push_back(1);
    opt.wheels[0].push_back(2);
    opt.wheels[1] = Wheel{};
    opt.wheels[1].push_back(3);
    opt.wheels[1].push_back(4);
    opt.wheels[1].push_back(5);

    auto odom = make_odometer(opt);
    PipelineThreadContext ctx;
    odom->init_state(ctx, 0, 1, opt);

    std::vector<uint64_t> outer_seen;
    outer_seen.push_back(odom->linear_position(ctx, opt));
    while (odom->advance(ctx, opt)) {
        const uint64_t li = odom->linear_position(ctx, opt);
        if (outer_seen.empty() || outer_seen.back() != li) outer_seen.push_back(li);
    }

    REQUIRE_EQ(outer_seen.size(), size_t{6});
    REQUIRE_EQ(odom->total_space(opt), uint64_t{6});
}

// =========================================================================
// CoverageSnapshot — hash determinístico e usa wheels originais
// =========================================================================
TEST_CASE(coverage_snapshot_uses_original_wheels) {
    auto cfg = make_test_config();
    set_unknowns(cfg, {3, 11});
    auto opt = SearchOptimizer::build_plan(cfg);

    auto s1 = make_coverage_snapshot(opt, cfg);
    auto s2 = make_coverage_snapshot(opt, cfg);

    REQUIRE_EQ(s1.hash, s2.hash);
    REQUIRE_EQ(s1.allowed_at_position.size(), opt.original_wheels.size());

    const auto& last_bs = s1.allowed_at_position.back();
    size_t popcount = 0;
    for (uint64_t w : last_bs) popcount += __builtin_popcountll(w);
    REQUIRE_EQ(popcount, size_t{2048});
}

// =========================================================================
// CoverageSnapshot — um candidato do plano é coberto
// =========================================================================
TEST_CASE(coverage_snapshot_covers_candidate) {
    auto cfg = make_test_config();
    set_unknowns(cfg, {0, 5});
    auto opt = SearchOptimizer::build_plan(cfg);

    auto snap = make_coverage_snapshot(opt, cfg);

    auto candidate = opt.base_mnemonic;
    candidate[opt.unknown_positions[0]] = opt.wheels[0].words[0];
    candidate[opt.unknown_positions[1]] = opt.wheels[1].words[0];

    REQUIRE(snapshot_covers(snap, candidate));
    REQUIRE(covered_by_any({snap}, candidate));
}
