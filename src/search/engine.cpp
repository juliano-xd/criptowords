#include "../../include/search/engine.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <deque>
#include <print>
#include <thread>
#include <vector>

#include "../../include/cli/ui.hpp"
#include "../../include/hardware/host_probe.hpp"
#include "../../include/search/checkpoint.hpp"

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif

using namespace cryptowords::ui;

namespace cryptowords {
namespace {

    SearchState* g_state_for_signal = nullptr;

    extern "C" void ckpt_signal_handler(int sig) {
        if (g_state_for_signal)
            g_state_for_signal->save_requested.store(true, std::memory_order_relaxed);
        if (sig == SIGINT || sig == SIGTERM) return;
        std::signal(sig, SIG_DFL);
        std::raise(sig);
    }

// -------------------------------------------------------------------------
// Formatação de taxas de rejeição. Unidade "elim/s" em vez de "keys/s".
// -------------------------------------------------------------------------
std::string format_elim_rate(double n_per_sec) {
    if (n_per_sec < 0.5)  return "0/s";
    if (n_per_sec >= 1e9) return std::format("{:.2f} G/s", n_per_sec / 1e9);
    if (n_per_sec >= 1e6) return std::format("{:.2f} M/s", n_per_sec / 1e6);
    if (n_per_sec >= 1e3) return std::format("{:.2f} K/s", n_per_sec / 1e3);
    return std::format("{:.0f}/s", n_per_sec);
}

// SpeedTracker — média móvel exponencial em janela deslizante (~1.2 s).
class SpeedTracker {
   public:
    explicit SpeedTracker(std::chrono::steady_clock::time_point start) : history_{{start, 0}} {}

    double update(std::chrono::steady_clock::time_point now, uint64_t count) {
        history_.push_back({now, count});
        while (history_.size() > 2) {
            const double age = std::chrono::duration<double>(now - history_.front().time).count();
            if (age > 1.2) history_.pop_front();
            else break;
        }
        const double dt = std::chrono::duration<double>(now - history_.front().time).count();
        const uint64_t dn = (count >= history_.front().count) ? (count - history_.front().count) : 0;
        const double raw = (dt > 0.02) ? (static_cast<double>(dn) / dt) : 0.0;

        if (smoothed_ <= 0.0) {
            smoothed_ = raw;
        } else if (raw > 0.0) {
            constexpr double alpha = 0.25;
            smoothed_ = alpha * raw + (1.0 - alpha) * smoothed_;
        } else {
            smoothed_ *= 0.8;
            if (smoothed_ < 0.1) smoothed_ = 0.0;
        }
        return smoothed_;
    }

   private:
    struct Sample { std::chrono::steady_clock::time_point time; uint64_t count; };
    std::deque<Sample> history_;
    double smoothed_ = 0.0;
};

// -------------------------------------------------------------------------
// build_thread_line — uma linha de progresso por thread.
// -------------------------------------------------------------------------
std::string build_thread_line(const ThreadSnapshot::View& v,
                              const OptimizedMnemonics& opt,
                              const AppConfig& cfg,
                              size_t tid,
                              size_t max_width) {
    const bool num_mode = (cfg.prog_mode == ProgressMode::Num);

    struct Tok { std::string text; size_t vis; };
    std::array<Tok, 24> tokens;
    size_t n_tokens = 0;

    for (size_t i = 0; i < v.mnemonic_len; ++i) {
        const bool is_fixed = (opt.base_mnemonic[i] != AppConfig::UNKNOWN_WORD);
        Tok tok;
        if (num_mode && !is_fixed) {
            int k = -1;
            for (size_t j = 0; j < opt.unknown_positions.size(); ++j)
                if (opt.unknown_positions[j] == i) { k = static_cast<int>(j); break; }

            uint32_t I = 0, N = 0;
            if (k >= 0) {
                N = static_cast<uint32_t>(opt.wheels[k].size());
                const bool is_last_unknown =
                    (static_cast<size_t>(k) + 1 == opt.unknown_positions.size());
                if (is_last_unknown && v.k_last_w_count > 0) {
                    I = v.k_last_w_idx + 1;
                    N = v.k_last_w_count;
                } else if (static_cast<size_t>(k) < v.state_len) {
                    I = v.state[k] + 1;
                }
            }
            const int w = static_cast<int>(std::to_string(N).size());
            auto pad = [w](uint32_t val) -> std::string {
                std::string sv = std::to_string(val);
                if (static_cast<int>(sv.size()) < w)
                    sv.insert(0, static_cast<size_t>(w) - sv.size(), '0');
                return sv;
            };
            std::string s = "[" + pad(I) + "/" + pad(N) + "]";
            tok.vis  = s.size();
            tok.text = "\033[1;37m" + s + "\033[0m";
        } else {
            const uint16_t wid = static_cast<uint16_t>(v.current_words[i]);
            if (is_fixed) {
                tok.text = num_mode ? "\033[1;33m[" : "\033[1;37m[";
                tok.text += cfg.wordlist[wid];
                tok.text += "]\033[0m";
                tok.vis = cfg.wordlist[wid].size() + 2;
            } else {
                tok.text = "\033[1;33m" + cfg.wordlist[wid] + "\033[0m";
                tok.vis  = cfg.wordlist[wid].size();
            }
        }
        tokens[n_tokens++] = std::move(tok);
    }

    std::string out = std::format("\033[1;36m T{:<2}\033[0m ", tid);
    size_t total_vis = 5;
    for (size_t i = 0; i < n_tokens; ++i) {
        const size_t sep_vis = (i > 0) ? 1 : 0;
        if (total_vis + sep_vis + tokens[i].vis > max_width - 1) {
            if (i > 0) out += ' ';
            out += "\033[90m…\033[0m";
            return out;
        }
        if (i > 0) { out += ' '; total_vis += 1; }
        out += tokens[i].text;
        total_vis += tokens[i].vis;
    }
    return out;
}

// -------------------------------------------------------------------------
// monitor_progress — frame ao vivo enquanto os workers rodam.
// -------------------------------------------------------------------------
void monitor_progress(const SearchState& state,
                      const AppConfig& cfg,
                      const OptimizedMnemonics& opt,
                      size_t num_threads,
                      bool show_elim,
                      std::chrono::steady_clock::time_point start) {
    SpeedTracker speed(start);
    SpeedTracker elim_speed(start);

    const double total_eff = opt.valid_combinations;
    const std::string tot_str = format_num(opt.exact_math_valid);

    const size_t term_w = terminal_width();
    const size_t line_width = std::min<size_t>(118, term_w > 8 ? term_w - 6 : 60);

    static constexpr int    bar_width = 20;
    static constexpr size_t max_threads_display = 8;

    const size_t n_display = std::min(num_threads, max_threads_display);
    const bool has_extra   = (num_threads > max_threads_display);

    LiveFrame frame;

    auto should_exit = [&]() {
        return state.found.load(std::memory_order_relaxed) ||
               state.all_done.load(std::memory_order_relaxed) ||
               state.save_requested.load(std::memory_order_relaxed);
    };

    while (!should_exit()) {
        for (int s = 0; s < 5; ++s) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (should_exit()) break;
        }
        if (should_exit()) break;

        const auto now = std::chrono::steady_clock::now();
        const double elap = std::chrono::duration<double>(now - start).count();
        const uint64_t cur = state.tested_count.load(std::memory_order_relaxed);
        const double spd = speed.update(now, cur);

        std::string elim_str;
        if (show_elim) {
            const uint64_t elim = state.eliminated.load(std::memory_order_relaxed);
            const double rate = elim_speed.update(now, elim);
            elim_str = std::format(" elim \033[1;35m{}\033[0m │", format_elim_rate(rate));
        }

        const double pct = (total_eff > 0)
                               ? std::clamp((static_cast<double>(cur) / total_eff) * 100.0,
                                            0.0, 100.0)
                               : 0.0;
        const int filled = std::clamp(static_cast<int>(pct / 5.0), 0, bar_width);
        std::string bar;
        bar.reserve(bar_width * 3);
        for (int i = 0; i < filled; ++i) bar += "█";
        for (int i = filled; i < bar_width; ++i) bar += "░";

        const double eta_sec = (spd > 0.1 && cur < total_eff)
                                   ? (total_eff - cur) / spd
                                   : (cur >= total_eff ? 0.0 : -1.0);

        const std::string cur_str = format_num(static_cast<double>(cur));

        std::string pct_str;
        if (pct >= 10.0)        pct_str = std::format("{:6.2f}%", pct);
        else if (pct >= 1.0)    pct_str = std::format("{:7.3f}%", pct);
        else if (pct >= 0.01)   pct_str = std::format("{:8.4f}%", pct);
        else if (pct >= 0.0001) pct_str = std::format("{:9.6f}%", pct);
        else if (pct >= 1e-15)  pct_str = std::format("{:.3e}%", pct);
        else if (pct > 0.0)     pct_str = std::format("{:.1e}%", pct);
        else                    pct_str = "  0.0000000000%";

        const std::string spd_str = std::format("\033[1;32m{}\033[0m", format_speed(spd));

        std::vector<std::string> lines;
        lines.reserve(1 + n_display + 3);

        lines.push_back(
            "\033[90m  ╭─ Engrenagem (workers em paralelo) "
            "─────────────────────────────────\033[0m");

        for (size_t tid = 0; tid < n_display; ++tid) {
            ThreadSnapshot::View v;
            if (!state.snapshots[tid]->read(v) || v.mnemonic_len == 0) {
                lines.push_back(std::format(
                    "\033[1;36m T{:<2}\033[0m \033[90m(aguardando...)\033[0m", tid));
            } else {
                lines.push_back(build_thread_line(v, opt, cfg, tid, line_width));
            }
        }

        if (has_extra) {
            lines.push_back(std::format(
                "\033[90m     ... {} threads no total (exibindo as primeiras {})\033[0m",
                num_threads, max_threads_display));
        }

        lines.push_back(
            "\033[90m  ╰────────────────────────────────────────────────────────────────────\033[0m");

        lines.push_back(std::format(
            "  [\033[36m{}\033[0m] \033[1;37m{}\033[0m │ {} │{} "
            "\033[33mETA {:>9}\033[0m │ \033[90m{}/{}\033[0m │ \033[90m{}\033[0m",
            bar, pct_str, spd_str, elim_str,
            format_eta(eta_sec), cur_str, tot_str, format_eta(elap)));

        const std::string feas = format_feasibility(eta_sec);
        if (!feas.empty()) {
            lines.push_back(std::format(
                "  {} \033[90m·\033[0m 1h: \033[1;33m{}\033[0m "
                "\033[90m·\033[0m 1d: \033[1;33m{}\033[0m",
                feas,
                format_probability(spd, total_eff, 3600.0),
                format_probability(spd, total_eff, 86400.0)));
        } else {
            lines.push_back("");
        }

        frame.render(lines);
    }

    frame.clear();
}

// -------------------------------------------------------------------------
// autosave_loop — salva o checkpoint periodicamente.
// -------------------------------------------------------------------------
void autosave_loop(const SearchState& state,
                   const ExecutionPipeline& pipeline,
                   int interval_sec) {
    const auto& opt = pipeline.plan();
    const auto& cfg = pipeline.config();
    if (cfg.save_path.empty() || interval_sec <= 0) return;

    auto last = std::chrono::steady_clock::now();
    while (!state.found.load(std::memory_order_relaxed) &&
           !state.all_done.load(std::memory_order_relaxed) &&
           !state.save_requested.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        const auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last).count() < interval_sec)
            continue;
        last = now;

        std::vector<uint64_t> li(state.snapshots.size());
        std::vector<uint64_t> pr(state.snapshots.size());
        for (size_t t = 0; t < state.snapshots.size(); ++t) {
            ThreadSnapshot::View v;
            if (state.snapshots[t]->read(v)) {
                li[t] = v.linear_index;
                pr[t] = v.cumulative_tested;
            }
        }
        (void)save_checkpoint(cfg.save_path, opt, cfg, li, pr,
                              pipeline.coverage_snapshots());
    }
}

// -------------------------------------------------------------------------
// Coleta o progresso das threads para o save final.
// -------------------------------------------------------------------------
struct ThreadProgress {
    std::vector<uint64_t> linear_indices;
    std::vector<uint64_t> processed;
};

ThreadProgress collect_progress(const SearchState& state) {
    ThreadProgress p;
    p.linear_indices.resize(state.snapshots.size());
    p.processed.resize(state.snapshots.size());
    for (size_t t = 0; t < state.snapshots.size(); ++t) {
        ThreadSnapshot::View v;
        if (state.snapshots[t]->read(v)) {
            p.linear_indices[t] = v.linear_index;
            p.processed[t]      = v.cumulative_tested;
        }
    }
    return p;
}

// -------------------------------------------------------------------------
// Publica o estado do cursor no snapshot. Escolhe state/outer_state
// conforme o modo (Streaming usa outer_state).
// -------------------------------------------------------------------------
inline void publish_snapshot(const ExecutionPipeline& pipeline,
                             ThreadSnapshot& snap,
                             PipelineThreadContext& ctx) {
    const auto& cur = ctx.cursor;
    const size_t* st = cur.state.empty() ? cur.outer_state.data() : cur.state.data();
    const size_t  st_len = cur.state.empty() ? cur.outer_state.size()
                                             : cur.state.size();
    snap.publish(cur.current_ids.data(), cur.current_ids.size(),
                 st, st_len,
                 static_cast<uint32_t>(cur.k_last_w_idx),
                 static_cast<uint32_t>(cur.k_last_w_count),
                 ctx.counters.cumulative_tested,
                 ctx.counters.cumulative_valid,
                 pipeline.odometer_position(ctx));
}

}  // namespace

// =========================================================================
// save_snapshot — chamado com todos os workers parados.
// =========================================================================
void BruteForceEngine::save_snapshot(const ExecutionPipeline& pipeline,
                                     const SearchState& state,
                                     const std::string& path) {
    const auto& opt = pipeline.plan();
    const auto& cfg = pipeline.config();
    auto p = collect_progress(state);
    (void)save_checkpoint(path, opt, cfg, p.linear_indices, p.processed,
                          pipeline.coverage_snapshots());
}

// =========================================================================
// worker — loop de busca por thread.
// =========================================================================
void BruteForceEngine::worker(ExecutionPipeline& pipeline, size_t thread_idx,
                              size_t num_threads, SearchState& state) {
#if defined(__linux__)
    static const auto cpu_ids = hardware::HostProbe::get_physical_cpu_ids();
    if (!cpu_ids.empty() && pipeline.config().pin_cores) {
        const int target_cpu = cpu_ids[thread_idx % cpu_ids.size()];
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(target_cpu, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    }
#endif

    auto ctx = pipeline.create_thread_context(thread_idx, num_threads);
    if (!ctx) return;

    // Reposiciona o odômetro se um checkpoint compatível foi carregado.
    if (state.checkpoint_loaded) {
        const uint64_t start = state.checkpoint_start_idx;
        const uint64_t end   = state.checkpoint_total_idx;
        if (end > start) {
            const auto& plan = pipeline.plan();
            const bool contiguous = (plan.mode == SearchMode::Triplets) ||
                                    (plan.mode == SearchMode::Pairs);
            const uint64_t my_start = contiguous
                ? start + (thread_idx * (end - start)) / num_threads
                : start + thread_idx;
            if (my_start < end) pipeline.odometer_seek(*ctx, my_start);
            else                ctx->cursor.done = true;
        }
    }

    ThreadSnapshot& snap = *state.snapshots[thread_idx];
    uint32_t publish_counter = 0;

    auto stop = [&]() {
        return state.found.load(std::memory_order_relaxed) ||
               state.save_requested.load(std::memory_order_relaxed) ||
               ctx->cursor.done;
    };

    while (!stop()) {
        pipeline.process(*ctx, state.found, state.tested_count, state.valid_count,
                         state.result_mutex, state.success, state.result_mnemonic);

        if (ctx->counters.local_eliminated >= 128) {
            state.eliminated.fetch_add(ctx->counters.local_eliminated,
                                       std::memory_order_relaxed);
            ctx->counters.local_eliminated = 0;
        }

        if (ctx->cursor.last_candidate_accepted && ++publish_counter >= 16) {
            publish_counter = 0;
            publish_snapshot(pipeline, snap, *ctx);
        }

        pipeline.advance(*ctx);
    }

    // Flush final de contadores e do último snapshot.
    if (ctx->counters.local_eliminated > 0) {
        state.eliminated.fetch_add(ctx->counters.local_eliminated,
                                   std::memory_order_relaxed);
        ctx->counters.local_eliminated = 0;
    }
    if (ctx->cursor.last_candidate_accepted)
        publish_snapshot(pipeline, snap, *ctx);

    if (!state.save_requested.load(std::memory_order_relaxed))
        pipeline.flush(*ctx, state.found, state.tested_count, state.valid_count,
                       state.result_mutex, state.success, state.result_mnemonic);
}

// =========================================================================
// run — orquestra fases 4 e 5.
// =========================================================================
void BruteForceEngine::run(ExecutionPipeline& pipeline, size_t num_threads) {
    const auto& cfg = pipeline.config();
    const auto& plan = pipeline.plan();
    const bool quiet = cfg.quiet;
    const bool show_elim = plan.count_eliminations;

    // Reduz threads para GPU pura ou espaços muito pequenos.
    const double total = pipeline.total_combinations();
    if (cfg.use_gpu && !cfg.use_hybrid) num_threads = 1;
    else if (total < num_threads * 128) num_threads = 1;

    if (!quiet) {
        const std::string pin_str = cfg.pin_cores ? "Ativo (Pinning Físico)"
                                                  : "Desativado";
        std::println("Iniciando busca SIMD (Motor: \033[1;36m{}\033[0m │ "
                     "Threads: \033[1;37m{}\033[0m │ Afinidade: {})\n",
                     pipeline.architecture_name(), num_threads, pin_str);
    }

    const auto start = std::chrono::steady_clock::now();
    SearchState state;

    // ---- Checkpoint ----
    if (!cfg.load_path.empty()) {
        Checkpoint ckpt;
        if (load_checkpoint(cfg.load_path, ckpt, plan, cfg)) {
            const size_t n_snaps = ckpt.snapshots.size();
            pipeline.set_coverage_snapshots(std::move(ckpt.snapshots));

            if (ckpt.config_compatible) {
                state.checkpoint_loaded    = true;
                state.checkpoint_start_idx = checkpoint_frontier(ckpt);
                state.checkpoint_total_idx = ckpt.header.total_space;

                if (!quiet) {
                    const uint64_t processed = ckpt.header.total_processed;
                    const uint64_t remaining = (ckpt.header.total_space >
                                                state.checkpoint_start_idx)
                        ? (ckpt.header.total_space - state.checkpoint_start_idx)
                        : 0;
                    std::println("[✓] Checkpoint carregado: \033[1;33m{}\033[0m threads, "
                                 "\033[1;33m{}\033[0m candidatos processados, "
                                 "faltam \033[1;33m{}\033[0m de \033[1;33m{}\033[0m "
                                 "estados (config compatível)",
                                 ckpt.header.n_threads, processed, remaining,
                                 ckpt.header.total_space);
                    if (n_snaps > 0)
                        std::println("[✓] \033[1;36m{}\033[0m snapshot(s) de cobertura ativos.",
                                     n_snaps);
                    std::println();
                }
            } else if (cfg.resume_strict) {
                std::println(std::cerr,
                             "\n[\033[1;31m✗\033[0m] --resume-strict: checkpoint '{}' tem "
                             "config incompatível.\n"
                             "    Remova --resume-strict para continuar do zero usando "
                             "apenas os snapshots de cobertura.",
                             cfg.load_path);
                return;
            } else {
                state.checkpoint_loaded = false;
                if (!quiet)
                    std::println("[i] Configuração mudou desde o checkpoint — iniciando "
                                 "do zero, mas \033[1;36m{}\033[0m snapshot(s) ativos.\n",
                                 n_snaps);
            }
        } else {
            std::println(std::cerr,
                         "[!] Falha ao carregar checkpoint '{}' — iniciando do zero.\n",
                         cfg.load_path);
        }
    }

    state.snapshots.resize(num_threads);
    for (auto& s : state.snapshots) s = std::make_unique<ThreadSnapshot>();

    g_state_for_signal = &state;
    std::signal(SIGINT,  ckpt_signal_handler);
    std::signal(SIGTERM, ckpt_signal_handler);

    // ---- Workers ----
    std::vector<std::thread> workers;
    workers.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i)
        workers.emplace_back(&BruteForceEngine::worker, std::ref(pipeline), i,
                             num_threads, std::ref(state));

    std::thread progress(monitor_progress, std::cref(state),
                         std::cref(cfg), std::cref(plan),
                         num_threads, show_elim, start);

    std::thread autosave;
    if (!cfg.save_path.empty() && cfg.save_interval_sec > 0)
        autosave = std::thread(autosave_loop, std::cref(state),
                               std::cref(pipeline), cfg.save_interval_sec);

    for (auto& t : workers) t.join();
    state.all_done.store(true, std::memory_order_relaxed);
    if (autosave.joinable()) autosave.join();
    progress.join();

    const bool interrupted = state.save_requested.load(std::memory_order_relaxed);
    const bool found       = state.found.load(std::memory_order_relaxed);

    // ---- Registro de cobertura (só se terminou naturalmente sem match) ----
    if (!interrupted && !found) {
        auto snap = make_coverage_snapshot(plan, cfg);
        pipeline.add_coverage_snapshot(std::move(snap));
        if (!quiet)
            std::println("[✓] Espaço de busca registrado como coberto "
                         "({} snapshot(s) total).", pipeline.coverage_snapshots().size());
    } else if (found && !quiet) {
        std::println("[i] Busca encontrou a chave — snapshot de cobertura NÃO registrado.");
    } else if (interrupted && !quiet) {
        std::println("[i] Busca interrompida — snapshot de cobertura NÃO registrado.");
    }

    // ---- Save final ----
    if (!cfg.save_path.empty()) {
        save_snapshot(pipeline, state, cfg.save_path);
        if (interrupted)
            std::println("\n[\033[1;33m!\033[0m] Ctrl+C recebido — progresso salvo em "
                         "\033[1;33m{}\033[0m\n", cfg.save_path);
    } else if (interrupted) {
        std::println("\n[\033[1;33m!\033[0m] Ctrl+C recebido (nenhum --save configurado).\n");
    }

    g_state_for_signal = nullptr;
    std::signal(SIGINT, SIG_DFL);
    std::signal(SIGTERM, SIG_DFL);

    if (interrupted) return;

    // ---- Estatísticas finais ----
    const auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start);
    const double total_sec = elapsed.count();
    const uint64_t total_tested = state.tested_count.load();
    const double avg_spd = (total_sec > 0)
                               ? (static_cast<double>(total_tested) / total_sec) : 0.0;

    if (!quiet) {
        std::println();
        print_box_top("ESTATÍSTICAS DA BUSCA", DEFAULT_INNER_WIDTH);
        print_box_line(std::format("Tempo decorrido   : \033[1;37m{:.4f} segundos\033[0m ({})",
                                   total_sec, format_eta(total_sec)),
                       DEFAULT_INNER_WIDTH);
        print_box_line(std::format("Velocidade média  : \033[1;32m{}\033[0m",
                                   format_speed(avg_spd)),
                       DEFAULT_INNER_WIDTH);
        print_box_line(std::format("Chaves testadas   : {} (PBKDF2)",
                                   format_num(static_cast<double>(total_tested))),
                       DEFAULT_INNER_WIDTH);
        print_box_line(std::format("Checksums OK      : {} chaves",
                                   format_num(static_cast<double>(state.valid_count.load()))),
                       DEFAULT_INNER_WIDTH);
        if (show_elim) {
            const uint64_t total_elim = state.eliminated.load();
            const double elim_spd = (total_sec > 0)
                                        ? (static_cast<double>(total_elim) / total_sec) : 0.0;
            print_box_line(std::format("Eliminados        : {} chaves (\033[1;35m{}\033[0m)",
                                       format_num(static_cast<double>(total_elim)),
                                       format_elim_rate(elim_spd)),
                           DEFAULT_INNER_WIDTH);
        }
        print_box_bottom(DEFAULT_INNER_WIDTH);
    }

    if (state.success) pipeline.verify_and_print_result(state.result_mnemonic);
    else               std::println("\n[!] Busca finalizada. Chave não encontrada.\n");
}

}  // namespace cryptowords
