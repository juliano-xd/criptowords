#pragma once
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "checkpoint.hpp"
#include "context.hpp"
#include "odometer.hpp"
#include "processor.hpp"

namespace cryptowords {

// Orquestra as fases 3→4:
//   - constrói o processador SIMD adequado (factory) e o odômetro (make_odometer)
//   - cria o contexto por thread (salt + buffers persistentes mínimos)
//   - processa / descarrega lotes
//   - fase 5: deriva e imprime o resultado final
class ExecutionPipeline {
   public:
    ExecutionPipeline(const AppConfig& cfg, const OptimizedMnemonics& opt);
    ~ExecutionPipeline();

    // Cria o contexto por thread. Copia o salt pré-computado e inicializa
    // o cursor do odômetro na posição da thread.
    std::unique_ptr<PipelineThreadContext> create_thread_context(size_t thread_idx,
                                                                  size_t num_threads);

    // --- Odômetro (posição / seek / tamanho) ---
    bool advance(PipelineThreadContext& ctx) { return odometer_->advance(ctx, opt_); }

    uint64_t odometer_position(const PipelineThreadContext& ctx) const noexcept {
        return odometer_->linear_position(ctx, opt_);
    }
    void odometer_seek(PipelineThreadContext& ctx, uint64_t idx) const {
        odometer_->seek_linear(ctx, opt_, idx);
    }
    uint64_t odometer_total_space() const noexcept {
        return odometer_->total_space(opt_);
    }

    // --- Lotes ---
    void process(PipelineThreadContext& ctx, std::atomic<bool>& found,
                 std::atomic<uint64_t>& tested, std::atomic<uint64_t>& valid,
                 std::mutex& mutex, bool& success, std::vector<uint16_t>& result);

    void flush(PipelineThreadContext& ctx, std::atomic<bool>& found,
               std::atomic<uint64_t>& tested, std::atomic<uint64_t>& valid,
               std::mutex& mutex, bool& success, std::vector<uint16_t>& result);

    // --- Consulta ---
    const std::string& architecture_name() const noexcept { return arch_name_; }
    double total_combinations() const noexcept { return opt_.total_combinations; }
    const AppConfig& config() const noexcept { return cfg_; }
    const OptimizedMnemonics& plan() const noexcept { return opt_; }

    // --- Cobertura ---
    void set_coverage_snapshots(std::vector<CoverageSnapshot>&& v) noexcept;
    void add_coverage_snapshot(CoverageSnapshot&& s);
    const std::vector<CoverageSnapshot>& coverage_snapshots() const noexcept {
        return coverage_snapshots_;
    }

    // --- Fase 5: reporta mnemônico, checksum, endereço e chave privada ---
    void verify_and_print_result(const std::vector<uint16_t>& mnemonic) const;

   private:
    const AppConfig& cfg_;
    const OptimizedMnemonics& opt_;

    std::unique_ptr<IOdometer> odometer_;
    std::unique_ptr<IBatchProcessor> processor_;
    std::string arch_name_;

    // Salt HMAC pré-computado uma vez por execução. Copiado para cada thread.
    SaltCache salt_shared_;

    std::vector<CoverageSnapshot> coverage_snapshots_;

    std::mutex gpu_post_mutex_;
    bool use_gpu_post_ = false;
    bool use_nvidia_   = false;   // reservado; sem efeito por enquanto

    void build_salt_tables_();
};

}  // namespace cryptowords
