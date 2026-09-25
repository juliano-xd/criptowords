import json
import os
import subprocess
import sys
import time

candidates = ["./build/criptowords", "./criptowords", "./build/release/criptowords"]
BINARY = next((c for c in candidates if os.path.exists(c)), "./build/criptowords")
if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    BINARY = sys.argv[1]

# Escala de timeouts: CPUs de nuvem mais lentas (ex.: Vast.ai) podem levar 2-4x
# mais tempo nas buscas. Defina QA_TIMEOUT_SCALE=4 no host remoto; o padrão (1)
# mantém o comportamento local inalterado.
TIMEOUT_SCALE = float(os.environ.get("QA_TIMEOUT_SCALE", "1") or "1")

HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".qa_history.json")


def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_history(data):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"  \033[93m[AVISO] Falha ao salvar histórico de QA: {e}\033[0m")


class QARunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []
        self.prev_history = load_history()
        self.prev_cases = self.prev_history.get("cases", {})
        self.prev_total_time = self.prev_history.get("total_time")
        self.current_cases = {}
        self.faster_count = 0
        self.slower_count = 0
        self.same_count = 0

    def run_case(self, name, category, args, expected_exit=0, expect_stdout=None, expect_stderr=None, timeout_sec=15, allow_timeout=False, binary=None):
        cmd = [binary or BINARY] + args
        timeout_sec = timeout_sec * TIMEOUT_SCALE
        start = time.perf_counter()
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=timeout_sec)
            elapsed = time.perf_counter() - start
            exit_code = res.returncode
            stdout = res.stdout
            stderr = res.stderr
            timed_out = False
        except subprocess.TimeoutExpired as te:
            elapsed = time.perf_counter() - start
            exit_code = -999
            stdout = te.stdout.decode('utf-8', errors='replace') if isinstance(te.stdout, bytes) else (te.stdout or "")
            stderr = te.stderr.decode('utf-8', errors='replace') if isinstance(te.stderr, bytes) else (te.stderr or "")
            timed_out = True

        ok = True
        reason = ""

        if timed_out and not allow_timeout:
            ok = False
            reason = f"Timeout ({timeout_sec}s excedido)"
        elif not timed_out and exit_code != expected_exit:
            ok = False
            reason = f"Exit code incompatível: obtido {exit_code}, esperado {expected_exit}. stderr: {stderr.strip()}"
        elif expect_stdout:
            for s in expect_stdout:
                if s.lower() not in stdout.lower():
                    ok = False
                    reason = f"Texto esperado ausente em stdout: '{s}'"
                    break
        elif expect_stderr:
            for s in expect_stderr:
                if s.lower() not in stderr.lower():
                    ok = False
                    reason = f"Texto esperado ausente em stderr: '{s}'"
                    break

        if ok:
            self.passed += 1
            status = "PASS"
        else:
            self.failed += 1
            status = "FAIL"

        self.current_cases[name] = {
            "elapsed": elapsed,
            "status": status,
            "category": category
        }

        # Comparação de velocidade em relação ao teste anterior
        prev_entry = self.prev_cases.get(name)
        prev_elapsed = prev_entry.get("elapsed") if isinstance(prev_entry, dict) else prev_entry
        comp_str = ""
        if prev_elapsed is not None and prev_elapsed > 0:
            diff = prev_elapsed - elapsed
            pct = (diff / prev_elapsed) * 100.0
            if abs(pct) < 1.0:
                self.same_count += 1
                comp_str = f"vs ant: {prev_elapsed:.3f}s | \033[94m~0.0% =\033[0m"
            elif pct > 0:
                self.faster_count += 1
                comp_str = f"vs ant: {prev_elapsed:.3f}s | \033[92m+{pct:.1f}% ⚡\033[0m"
            else:
                self.slower_count += 1
                comp_str = f"vs ant: {prev_elapsed:.3f}s | \033[93m{pct:.1f}% 🔻\033[0m"
        else:
            comp_str = "\033[90m[primeiro registro]\033[0m"

        self.results.append({
            "name": name,
            "category": category,
            "status": status,
            "elapsed": elapsed,
            "prev_elapsed": prev_elapsed,
            "reason": reason,
            "stdout": stdout,
            "stderr": stderr
        })

        tag = "\033[92m[PASS]\033[0m" if ok else "\033[91m[FAIL]\033[0m"
        print(f"  {tag} {name} ({elapsed:.3f}s | {comp_str})")
        if not ok and reason:
            print(f"         \033[93m└─> {reason}\033[0m")

    def print_summary(self):
        total = self.passed + self.failed
        total_elapsed = sum(r["elapsed"] for r in self.results)
        print("\n" + "="*75)
        print("                 RELATÓRIO DA BATERIA DE TESTES (QA)")
        print("="*75)
        print(f" Total de Casos Executados : {total}")
        print(f" Casos Aprovados           : \033[92m{self.passed}\033[0m")
        print(f" Casos Reprovados          : \033[91m{self.failed}\033[0m")
        print(f" Taxa de Sucesso           : {(self.passed/total)*100:.1f}%")

        if self.prev_total_time is not None and self.prev_total_time > 0:
            diff_total = self.prev_total_time - total_elapsed
            pct_total = (diff_total / self.prev_total_time) * 100.0
            if pct_total > 0:
                trend_str = f"\033[92m+{pct_total:.1f}% mais rápido ⚡\033[0m"
            elif pct_total < -1.0:
                trend_str = f"\033[93m{pct_total:.1f}% mais lento 🔻\033[0m"
            else:
                trend_str = f"\033[94m~0.0% estável ⚖️\033[0m"
            print(f" Tempo Total da Execução   : {total_elapsed:.3f}s (vs ant: {self.prev_total_time:.3f}s | {trend_str})")
            print(f" Variação de Velocidade    : \033[92m{self.faster_count} acelerados\033[0m | \033[94m{self.same_count} estáveis\033[0m | \033[93m{self.slower_count} desacelerados\033[0m")
        else:
            print(f" Tempo Total da Execução   : {total_elapsed:.3f}s \033[90m(primeiro registro salvo para próximas comparações)\033[0m")
        print("="*75)

        save_history({
            "timestamp": time.time(),
            "total_time": total_elapsed,
            "cases": self.current_cases
        })

def main():
    runner = QARunner()

    print("\n--- SUÍTE 1: Vetores Golden BIP-39 / BIP-44 (Precisão Criptográfica) ---")

    # 1.1 12 Palavras (Vetor do Usuário) BTC & ETH
    runner.run_case(
        "12w Golden BTC (arena...annual)",
        "Golden Vectors",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        expect_stdout=["CHAVE ENCONTRADA", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"]
    )
    runner.run_case(
        "12w Golden ETH (arena...annual)",
        "Golden Vectors",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "eth", "--target", "0x097c5d7c127ae542723d4bd35a6529ce66c3dc29"],
        expect_stdout=["CHAVE ENCONTRADA", "0x097c5d7c127ae542723d4bd35a6529ce66c3dc29"]
    )

    # 1.2 12 Palavras (Vetor Oficial BIP-39 Spec: abandon...about) BTC & ETH
    runner.run_case(
        "12w Spec Vector BTC (abandon...about)",
        "Golden Vectors",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
         "--coin", "btc", "--target", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"],
        expect_stdout=["CHAVE ENCONTRADA", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"]
    )
    runner.run_case(
        "12w Spec Vector ETH (abandon...about)",
        "Golden Vectors",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
         "--coin", "eth", "--target", "0x9858effd232b4033e47d90003d41ec34ecaeda94"],
        expect_stdout=["CHAVE ENCONTRADA", "0x9858effd232b4033e47d90003d41ec34ecaeda94"]
    )

    # 1.3 Passphrase Personalizada ("TREZOR")
    runner.run_case(
        "12w Passphrase 'TREZOR' BTC",
        "Passphrase Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "btc", "--passphrase", "TREZOR", "--target", "14c98QWfnKy8hk4tSYyAwEXea1mfyggM9t"],
        expect_stdout=["CHAVE ENCONTRADA", "14c98QWfnKy8hk4tSYyAwEXea1mfyggM9t"]
    )
    runner.run_case(
        "12w Passphrase 'TREZOR' ETH",
        "Passphrase Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "eth", "--passphrase", "TREZOR", "--target", "0x8a369c7ab1ebc6b65b4b2bca817358fc8acf15fe"],
        expect_stdout=["CHAVE ENCONTRADA", "0x8a369c7ab1ebc6b65b4b2bca817358fc8acf15fe"]
    )

    # 1.4 Modo de Derivação Direta (Sem Target)
    runner.run_case(
        "Modo Derivação Direta BTC (sem target)",
        "Direct Derivation",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"]
    )
    runner.run_case(
        "Modo Derivação Direta ETH (sem target)",
        "Direct Derivation",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "eth"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "0x097c5d7c127ae542723d4bd35a6529ce66c3dc29"]
    )

    print("\n--- SUÍTE 2: Recuperação de Incógnitas '?' & Dedução Reversa ---")

    # 2.1 1 Incógnita na última posição (Dedução Reversa de Checksum)
    runner.run_case(
        "Recuperação: 1 incógnita no fim (Dedução Reversa)",
        "Unknowns Recovery",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk ?",
         "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "desk annual", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"]
    )

    # 2.2 1 Incógnita na primeira posição (Pos 0)
    runner.run_case(
        "Recuperação: 1 incógnita no início (pos 0)",
        "Unknowns Recovery",
        ["--mnemonics", "? huge owner legend diet smart spread truth file peanut desk annual",
         "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "arena huge", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"]
    )

    # 2.3 1 Incógnita no meio (Pos 4 - 'diet')
    runner.run_case(
        "Recuperação: 1 incógnita no meio (pos 4)",
        "Unknowns Recovery",
        ["--mnemonics", "arena huge owner legend ? smart spread truth file peanut desk annual",
         "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "legend diet smart", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"]
    )

    # 2.4 Restrição com --allow (Pos 10 restrita)
    runner.run_case(
        "Recuperação: Restrição com --allow (pos 10)",
        "Constraint Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut ? annual",
         "--allow", "10:desk|door|dog",
         "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "peanut desk annual", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"]
    )

    # 2.5 2 Incógnitas Finais (Força Bruta + Dedução Reversa)
    runner.run_case(
        "Recuperação: 2 incógnitas (arena...peanut ? ?)",
        "Unknowns Recovery",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut ? ?",
         "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "desk annual", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=60
    )

    # 2.6 2 Incógnitas Intermediárias em 15w com última fixa (OTM-02 Pruning F_2^C - 32x)
    # Vetor Realista: 'dad waste holiday enroll rebel pact adjust few ? trumpet arrest danger begin ? street'
    # Palavras alvo: 'silent' (ID 1606) e 'ladder' (ID 1006)
    runner.run_case(
        "Recuperação: 2 incógnitas intermediárias 15w (OTM-02 Pruning F_2^C - 32x)",
        "Unknowns Recovery",
        ["--mnemonics", "dad waste holiday enroll rebel pact adjust few ? trumpet arrest danger begin ? street",
         "--target", "17SJnwGfVxqiTQTJcsXiC7bYvBhy2HCCrc", "--coin", "btc", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "OTM-02", "17SJnwGfVxqiTQTJcsXiC7bYvBhy2HCCrc"],
        timeout_sec=25
    )

    # 2.7 2 Incógnitas Intermediárias em 24w com última fixa (OTM-02 Pico Máximo - 256x)
    # Vetor Realista: palavras alvo 'mimic' (pos 8) e 'chair' (pos 21)
    runner.run_case(
        "Recuperação: 2 incógnitas intermediárias 24w (OTM-02 Pico Máximo - 256x)",
        "Unknowns Recovery",
        ["--mnemonics", "jeans outer satoshi embody luggage warm credit bachelor ? imitate chicken winner foot expire snack hold parent base image dawn resist ? soft merry",
         "--target", "1GUJzdvZFBzGRn9piHhu6PkEuyBWzPHyBr", "--coin", "btc", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "OTM-02", "1GUJzdvZFBzGRn9piHhu6PkEuyBWzPHyBr"],
        timeout_sec=15
    )

    # 2.8 3 Incógnitas Intercaladas com Topologia Complexa (OTM-09 N-Slices - 7 Fatias)
    # Vetor Realista: palavras alvo 'luggage' (pos 4), 'chicken' (pos 10), 'parent' (pos 16)
    runner.run_case(
        "Topologia: 3 incógnitas intercaladas (OTM-09 N-Slices 7 Fatias)",
        "Unknowns Recovery",
        ["--mnemonics", "jeans outer satoshi embody ? warm credit bachelor mimic imitate ? winner foot expire snack hold ? base image dawn resist chair soft merry",
         "--allow", "4:luggage|lamp|leaf,10:chicken|chest|cherry,16:parent|paper|panel",
         "--target", "1GUJzdvZFBzGRn9piHhu6PkEuyBWzPHyBr", "--coin", "btc", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "OTM-09", "1GUJzdvZFBzGRn9piHhu6PkEuyBWzPHyBr"],
        timeout_sec=15
    )

    # 2.9 Modo Aberto --invalid_too com N-Slices (100% das Chaves no Patching de Memória)
    runner.run_case(
        "Modo Aberto: --invalid_too com N-Slices (Two-Sided Memory Patching)",
        "Unknowns Recovery",
        ["--invalid_too",
         "--mnemonics", "abandon ? abandon ? abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
         "--allow", "1:abandon|cat,3:abandon|dog",
         "--target", "1KBdbBJRVYffWHWWZ1moECfdVBSEnDpLHi", "--coin", "btc", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "OTM-09", "1KBdbBJRVYffWHWWZ1moECfdVBSEnDpLHi"],
        timeout_sec=15
    )

    # 2.10 3 Incógnitas Intermediárias em 12w com última fixa (OTM-03 Pruning F_2^C - 16x)
    # Vetor Realista: 'truth' (pos 7), 'file' (pos 8), 'peanut' (pos 9), última 'annual' fixa
    runner.run_case(
        "Recuperação: 3 incógnitas intermediárias 12w (OTM-03 Pruning F_2^C - 16x)",
        "Unknowns Recovery",
        ["--mnemonics", "arena huge owner legend diet smart spread ? ? ? desk annual",
         "--allow", "7:truth|train,8:file|film,9:peanut|peace",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "OTM-03", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    # 2.11 3 Incógnitas Intermediárias em 15w com última fixa (OTM-03 Pruning F_2^C - 32x)
    # Vetor Realista: 'silent' (pos 8), 'trumpet' (pos 9), 'arrest' (pos 10), última 'street' fixa
    runner.run_case(
        "Recuperação: 3 incógnitas intermediárias 15w (OTM-03 Pruning F_2^C - 32x)",
        "Unknowns Recovery",
        ["--mnemonics", "dad waste holiday enroll rebel pact adjust few ? ? ? danger begin ladder street",
         "--allow", "8:silent|silver,9:trumpet|truck,10:arrest|arrow",
         "--coin", "btc", "--target", "17SJnwGfVxqiTQTJcsXiC7bYvBhy2HCCrc", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "OTM-03", "17SJnwGfVxqiTQTJcsXiC7bYvBhy2HCCrc"],
        timeout_sec=15
    )

    # 2.12 3 Incógnitas Intermediárias em 24w com última fixa (OTM-03 Pico Máximo - 256x)
    # Vetor Realista: 'mimic' (pos 8), 'imitate' (pos 9), 'chicken' (pos 10), última 'merry' fixa
    runner.run_case(
        "Recuperação: 3 incógnitas intermediárias 24w (OTM-03 Pico Máximo - 256x)",
        "Unknowns Recovery",
        ["--mnemonics", "jeans outer satoshi embody luggage warm credit bachelor ? ? ? winner foot expire snack hold parent base image dawn resist chair soft merry",
         "--allow", "8:mimic|mirror,9:imitate|impact,10:chicken|child",
         "--coin", "btc", "--target", "1GUJzdvZFBzGRn9piHhu6PkEuyBWzPHyBr", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "OTM-03", "1GUJzdvZFBzGRn9piHhu6PkEuyBWzPHyBr"],
        timeout_sec=15
    )

    # 2.13 4 Incógnitas Intermediárias em 12w com última fixa (OTM-03 Pruning F_2^C - K=4, 16x)
    # Vetor Realista: 'spread' (pos 6), 'truth' (pos 7), 'file' (pos 8), 'peanut' (pos 9), última 'annual' fixa
    runner.run_case(
        "Recuperação: 4 incógnitas intermediárias 12w (Streaming Pruning F_2^C - K=4 - 16x)",
        "Unknowns Recovery",
        ["--mnemonics", "arena huge owner legend diet smart ? ? ? ? desk annual",
         "--allow", "6:spread|spring,7:truth|train,8:file|film,9:peanut|peace",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "K=4", "OTM-23", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    # 2.14 4 Incógnitas Intermediárias em 24w com última fixa (Pico Máximo - K=4, 256x)
    # Vetor Realista: 'bachelor' (pos 7), 'mimic' (pos 8), 'imitate' (pos 9), 'chicken' (pos 10), última 'merry' fixa
    runner.run_case(
        "Recuperação: 4 incógnitas intermediárias 24w (Streaming Pruning F_2^C - K=4 - 256x)",
        "Unknowns Recovery",
        ["--mnemonics", "jeans outer satoshi embody luggage warm credit ? ? ? ? winner foot expire snack hold parent base image dawn resist chair soft merry",
         "--allow", "7:bachelor|badge,8:mimic|mirror,9:imitate|impact,10:chicken|child",
         "--coin", "btc", "--target", "1GUJzdvZFBzGRn9piHhu6PkEuyBWzPHyBr", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "K=4", "OTM-23", "1GUJzdvZFBzGRn9piHhu6PkEuyBWzPHyBr"],
        timeout_sec=15
    )

    print("\n--- SUÍTE 3: Concorrência e Multithreading ---")
    for th in [1, 2, 4]:
        runner.run_case(
            f"Escalonamento Multithread ({th} threads)",
            "Concurrency",
            ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk ?",
             "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", str(th)],
            expect_stdout=["CHAVE ENCONTRADA", "desk annual"]
        )

    print("\n--- SUÍTE 4: Suporte a Múltiplos Idiomas (BIP-39 Multi-Language) ---")

    # 4.1 Português (--lang pt / portuguese)
    runner.run_case(
        "Idioma: Português Derivação BTC (--lang pt)",
        "Multi-Language",
        ["--lang", "pt", "--mnemonics", "abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abater", "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1Abxtia7yV5vj5ShyCd7mvK1eBvQAQDfUt"]
    )
    runner.run_case(
        "Idioma: Português Recuperação com incógnita '?'",
        "Multi-Language",
        ["--lang", "portuguese", "--mnemonics", "abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate ?",
         "--target", "1Abxtia7yV5vj5ShyCd7mvK1eBvQAQDfUt", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "abacate abater", "1Abxtia7yV5vj5ShyCd7mvK1eBvQAQDfUt"]
    )

    # 4.2 Espanhol com acentuação NFC (ábaco com acento)
    runner.run_case(
        "Idioma: Espanhol com acento NFC (--lang es)",
        "Multi-Language",
        ["--lang", "es", "--mnemonics", "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco abierto", "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1JP6MnWeAa1N6bh2LnGeUVnZAohjWfbFVe"]
    )
    runner.run_case(
        "Idioma: Espanhol Recuperação com incógnita '?'",
        "Multi-Language",
        ["--lang", "spanish", "--mnemonics", "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ?",
         "--target", "1JP6MnWeAa1N6bh2LnGeUVnZAohjWfbFVe", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "abierto", "1JP6MnWeAa1N6bh2LnGeUVnZAohjWfbFVe"]
    )

    # 4.3 Francês com acentuação NFC
    runner.run_case(
        "Idioma: Francês Derivação BTC (--lang fr)",
        "Multi-Language",
        ["--lang", "fr", "--mnemonics", "abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abeille", "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1PesMexMnMhnneWex5NGukvuCSL4ApdaLD"]
    )
    runner.run_case(
        "Idioma: Francês Recuperação com incógnita '?'",
        "Multi-Language",
        ["--lang", "french", "--mnemonics", "abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser ?",
         "--target", "1PesMexMnMhnneWex5NGukvuCSL4ApdaLD", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "abeille", "1PesMexMnMhnneWex5NGukvuCSL4ApdaLD"]
    )

    # 4.4 Italiano (--lang it / italian)
    runner.run_case(
        "Idioma: Italiano Derivação BTC (--lang it)",
        "Multi-Language",
        ["--lang", "it", "--mnemonics", "abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abete", "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "16sisK5QAu6e1GHBLLEmZAHGQ9uj9He8SY"]
    )

    # 4.5 Tcheco (--lang cs / czech)
    runner.run_case(
        "Idioma: Tcheco Derivação BTC (--lang cs)",
        "Multi-Language",
        ["--lang", "cs", "--mnemonics", "abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace agrese", "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "17kbtk6nn6cT6E4hTygKPqHGTa1kLJgLoa"]
    )

    # 4.6 Japonês com separador ideográfico U+3000
    runner.run_case(
        "Idioma: Japonês com separador ideográfico U+3000 (--lang ja)",
        "Multi-Language",
        ["--lang", "ja", "--mnemonics", "あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あおぞら", "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1MKBt4zk1g9YeVKNxqkxreZJJhmrk3gCCf"]
    )
    runner.run_case(
        "Idioma: Japonês Recuperação com incógnita '?'",
        "Multi-Language",
        ["--lang", "japanese", "--mnemonics", "あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000?",
         "--target", "1MKBt4zk1g9YeVKNxqkxreZJJhmrk3gCCf", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "あおぞら", "1MKBt4zk1g9YeVKNxqkxreZJJhmrk3gCCf"]
    )

    # 4.7 Coreano com sílabas NFC (Hangul Composed)
    runner.run_case(
        "Idioma: Coreano com sílabas NFC (--lang ko)",
        "Multi-Language",
        ["--lang", "ko", "--mnemonics", "가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가능", "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1D34Shi6zjSEPsvxzMobUgJFEPZKcvWmJA"]
    )

    # 4.8 Chinês Simplificado (--lang zh / chinese_simplified)
    runner.run_case(
        "Idioma: Chinês Simplificado (--lang zh)",
        "Multi-Language",
        ["--lang", "zh", "--mnemonics", "的 的 的 的 的 的 的 的 的 的 的 在", "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1JXk8UVrEQ7K7hh6XTHfLRfcofYcrDQXW2"]
    )

    # 4.9 Chinês Tradicional (--lang zh_tw / chinese_traditional)
    runner.run_case(
        "Idioma: Chinês Tradicional (--lang zh_tw)",
        "Multi-Language",
        ["--lang", "zh_tw", "--mnemonics", "的 的 的 的 的 的 的 的 的 的 的 在", "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1JXk8UVrEQ7K7hh6XTHfLRfcofYcrDQXW2"]
    )

    print("\n--- SUÍTE 5: Suporte a Todos os Tamanhos BIP-39 (12, 15, 18, 21 e 24 Palavras) ---")

    # 5.1 15 Palavras: Derivação BTC e ETH
    runner.run_case(
        "15w Golden BTC (abandon...address)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
         "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "13DiA1cRqsuxbeNRhyu7GNMZyTGyD5uKXS"]
    )
    runner.run_case(
        "15w Golden ETH (abandon...address)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
         "--coin", "eth"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "0x54be88525b024a20229fe7f6f62dc0884e4aaa0a"]
    )
    runner.run_case(
        "15w Recuperação com incógnita '?' (Dedução Reversa)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
         "--target", "13DiA1cRqsuxbeNRhyu7GNMZyTGyD5uKXS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "address", "13DiA1cRqsuxbeNRhyu7GNMZyTGyD5uKXS"]
    )

    # 5.2 18 Palavras: Derivação BTC e ETH
    runner.run_case(
        "18w Golden BTC (abandon...agent)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
         "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1LfuPLgJd2sAe5QNNt4tDNYvgQAe12YDr2"]
    )
    runner.run_case(
        "18w Golden ETH (abandon...agent)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
         "--coin", "eth"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "0x197a1bee163923815ba58ead0f14b3fcd8c5926d"]
    )
    runner.run_case(
        "18w Recuperação com incógnita '?' (Dedução Reversa)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
         "--target", "1LfuPLgJd2sAe5QNNt4tDNYvgQAe12YDr2", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "agent", "1LfuPLgJd2sAe5QNNt4tDNYvgQAe12YDr2"]
    )

    # 5.3 21 Palavras: Derivação BTC e ETH
    runner.run_case(
        "21w Golden BTC (abandon...admit)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
         "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1DL4Vr6z7GKyAdfTWRdsmnXtZTmxoQPomR"]
    )
    runner.run_case(
        "21w Golden ETH (abandon...admit)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
         "--coin", "eth"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "0x15cc2210a0afbb1a2d80dd3d585aa94eba6c10e0"]
    )
    runner.run_case(
        "21w Recuperação com incógnita '?' (Dedução Reversa)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
         "--target", "1DL4Vr6z7GKyAdfTWRdsmnXtZTmxoQPomR", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "admit", "1DL4Vr6z7GKyAdfTWRdsmnXtZTmxoQPomR"]
    )

    # 5.4 24 Palavras: Derivação BTC e ETH
    runner.run_case(
        "24w Golden BTC (abandon...art)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
         "--coin", "btc"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1KBdbBJRVYffWHWWZ1moECfdVBSEnDpLHi"]
    )
    runner.run_case(
        "24w Golden ETH (abandon...art)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
         "--coin", "eth"],
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb"]
    )
    runner.run_case(
        "24w Recuperação com incógnita '?' (Dedução Reversa)",
        "Mnemonic Sizes",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
         "--target", "1KBdbBJRVYffWHWWZ1moECfdVBSEnDpLHi", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "art", "1KBdbBJRVYffWHWWZ1moECfdVBSEnDpLHi"]
    )

    print("\n--- SUÍTE 6: Testes Negativos & Validação Robusta de Parâmetros ---")

    # 6.1 Ausência de argumentos principais
    runner.run_case(
        "Validação: Ausência total de argumentos principais",
        "Negative Tests",
        [],
        expected_exit=1,
        expect_stderr=["Forneça um '--mnemonics' ou um '--target'"]
    )

    # 6.2 Mnemônico com incógnita sem fornecer --target
    runner.run_case(
        "Validação: Mnemônico com incógnitas sem --target",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk ?"],
        expected_exit=1,
        expect_stderr=["'--target' é obrigatório quando há posições desconhecidas"]
    )

    # 6.3 Tamanho inválido de mnemônico (11 palavras)
    runner.run_case(
        "Validação: Tamanho inválido (11 palavras)",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk",
         "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        expected_exit=1,
        expect_stderr=["Tamanho incorreto"]
    )

    # 6.4 Tamanho inválido de mnemônico (13 palavras)
    runner.run_case(
        "Validação: Tamanho inválido (13 palavras)",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual extra",
         "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        expected_exit=1,
        expect_stderr=["Tamanho incorreto"]
    )

    # 6.5 Palavra inexistente no dicionário BIP-39
    runner.run_case(
        "Validação: Palavra inexistente no dicionário",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk invalidwordxyz",
         "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        expected_exit=1,
        expect_stderr=["não existe na wordlist"]
    )

    # 6.6 Endereço Bitcoin com Base58 inválido (caractere '0')
    runner.run_case(
        "Validação: Endereço Bitcoin com Base58 corrompido",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmy0"],
        expected_exit=1,
        expect_stderr=["Endereço Bitcoin inválido"]
    )

    # 6.7 Endereço Ethereum com Hex inválido (caractere 'ZZ')
    runner.run_case(
        "Validação: Endereço Ethereum com caractere não-hexadecimal",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "eth", "--target", "0x097C5D7c127Ae542723D4bd35A6529Ce66C3dcZZ"],
        expected_exit=1,
        expect_stderr=["Endereço Ethereum inválido"]
    )

    # 6.8 Endereço Ethereum com comprimento incorreto (< 40 caracteres)
    runner.run_case(
        "Validação: Endereço Ethereum curto",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "eth", "--target", "0x12345678"],
        expected_exit=1,
        expect_stderr=["Endereço Ethereum inválido"]
    )

    # 6.9 Moeda não suportada (--coin solana)
    runner.run_case(
        "Validação: Moeda não suportada (--coin solana)",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "solana", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        expected_exit=1,
        expect_stderr=["--coin"]
    )

    # 6.10 Flag --size com valor não permitido (--size 16)
    runner.run_case(
        "Validação: Flag --size não suportada (16)",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--size", "16", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        expected_exit=1,
        expect_stderr=["--size"]
    )

    # 6.11 Passphrase com mais de 99 caracteres
    runner.run_case(
        "Validação: Passphrase > 99 caracteres",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS",
         "--passphrase", "a" * 105],
        expected_exit=1,
        expect_stderr=["Passphrase suporta no máximo 99 caracteres"]
    )

    # 6.12 De-duplicação de palavras em --allow
    runner.run_case(
        "Validação: De-duplicação em --allow",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut ? annual",
         "--allow", "10:desk|desk|desk",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        expected_exit=0,
        expect_stdout=["CHAVE ENCONTRADA", "desk"]
    )

    # 6.13 Mnemônico com tabs e quebras de linha (\t, \n, \r)
    runner.run_case(
        "Validação: Mnemônico com tabs e quebras de linha",
        "Negative Tests",
        ["--mnemonics", "arena\thuge\nowner\rlegend diet smart spread truth file peanut desk annual",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        expected_exit=0,
        expect_stdout=["CHAVE ENCONTRADA", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"]
    )

    # 6.14 Palavra em Espanhol com acento em NFC e NFD
    runner.run_case(
        "Validação: Palavra acentuada com composição NFC/NFD",
        "Negative Tests",
        ["--lang", "es", "--invalid_too",
         "--mnemonics", "a\u0301baco a\u0301baco a\u0301baco a\u0301baco a\u0301baco a\u0301baco a\u0301baco a\u0301baco a\u0301baco a\u0301baco a\u0301baco a\u0301baco"],
        expected_exit=0,
        expect_stdout=["DERIVAÇÃO CONCLUÍDA", "1M6N2woQQ7Bmudp8tP2JLomk43xvecX8pX"]
    )

    # 6.15 Espaço combinatório gigante (6 incógnitas) sem estouro de formatação
    runner.run_case(
        "Validação: Espaço combinatório gigante sem overflow",
        "Negative Tests",
        ["--mnemonics", "arena huge owner legend diet smart ? ? ? ? ? ?",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=2,
        allow_timeout=True,
        expect_stdout=["AFUNILAMENTO COMBINATÓRIO", "Espaço Bruto Total"]
    )

    # 6.16 Endereço Bitcoin com excesso de '1's (Underflow guard)
    runner.run_case(
        "Validação: Endereço Bitcoin com excesso de '1's (Underflow guard)",
        "Negative Tests",
        ["--target", "11111111111111111111111111",
         "--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk ?"],
        expected_exit=1,
        expect_stderr=["Endereço Bitcoin inválido"]
    )

    # =========================================================================
    # SUÍTE 7: Estratégias de Afunilamento e Busca (--strategy)
    # =========================================================================
    print("\n--- SUÍTE 7: Estratégias de Afunilamento e Busca (--strategy) ---")

    # 7.1 Estratégia de Gradiente de Hamming (OTM-29)
    runner.run_case(
        "Estratégia: Gradiente de Hamming (OTM-29)",
        "Strategies",
        ["--mnemonics", "arena huge owner legend diet smart spread ? ? ? desk annual",
         "--allow", "7:truth|train,8:file|film,9:peanut|peace",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS",
         "--strategy", "hamming", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "OTM-29", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    # 7.2 Estratégia de Frequência Linguística (Zipf)
    runner.run_case(
        "Estratégia: Frequência Linguística (Zipf)",
        "Strategies",
        ["--mnemonics", "arena huge owner legend diet smart spread ? ? ? desk annual",
         "--allow", "7:truth|train,8:file|film,9:peanut|peace",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS",
         "--strategy", "frequency", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "Zipf", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    # 7.3 Estratégia de Autômatos de Levenshtein (Typo)
    runner.run_case(
        "Estratégia: Autômatos de Levenshtein (Typo)",
        "Strategies",
        ["--mnemonics", "arena huge owner legend diet smart spread ? ? ? desk annual",
         "--allow", "7:truth|train,8:file|film,9:peanut|peace",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS",
         "--strategy", "typo", "--max-distance", "2", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "Levenshtein", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    # 7.4 Validação: Estratégia inválida
    runner.run_case(
        "Validação: Estratégia inválida (--strategy quantum)",
        "Strategies",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk annual",
         "--strategy", "quantum"],
        expected_exit=1,
        expect_stderr=["Estratégia de busca inválida"]
    )

    # 7.5 Estratégia Combinada: Hamming + Frequência (Vírgula)
    runner.run_case(
        "Estratégia Combinada: Hamming + Frequência (Vírgula)",
        "Strategies",
        ["--mnemonics", "arena huge owner legend diet smart spread ? ? ? desk annual",
         "--allow", "7:truth|train,8:file|film,9:peanut|peace",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS",
         "--strategy", "hamming,frequency", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "Combinada", "OTM-29", "Zipf", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    # 7.6 Estratégia Combinada: Hamming + Typo (Sinal de Mais)
    runner.run_case(
        "Estratégia Combinada: Hamming + Typo (Sinal de Mais)",
        "Strategies",
        ["--mnemonics", "arena huge owner legend diet smart spread ? ? ? desk annual",
         "--allow", "7:truth|train,8:file|film,9:peanut|peace",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS",
         "--strategy", "hamming+typo", "--max-distance", "2", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "Combinada", "OTM-29", "Levenshtein", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    print("\n--- SUÍTE 8: Novas Otimizações Matemáticas (Distinct, Gray Code, Beam, Cascade) ---")

    # 8.1 Restrição de Não-Repetição (--distinct)
    runner.run_case(
        "Restrição de Não-Repetição (--distinct)",
        "Distinct Pruning",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut ? ?",
         "--allow", "10:desk|door|dog|arena,11:annual|animal|arena",
         "--distinct", "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "Restrição Não-Repetição", "desk annual", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    # 8.2 Dedução Cascata de Checksum (w_{N-1} = ?)
    runner.run_case(
        "Dedução Cascata de Checksum (w_N-1 = ?)",
        "Cascade Deduction",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut ? ?",
         "--allow", "10:desk|door|dog,11:annual|animal",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "Dedução Cascata", "desk annual", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    # 8.3 Beam Search Heurístico + Agendador Gray-Code
    runner.run_case(
        "Beam Search & Agendador Gray-Code",
        "Beam and Gray",
        ["--mnemonics", "arena huge owner legend diet smart spread ? ? ? desk annual",
         "--allow", "7:truth|train,8:file|film,9:peanut|peace",
         "--strategy", "hamming,frequency",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--threads", "4"],
        expect_stdout=["CHAVE ENCONTRADA", "Beam Search", "Agendador Gray-Code", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    # 8.4 Dedução Cascata Streaming com --distinct (K=3)
    runner.run_case(
        "Dedução Cascata Streaming com --distinct (K=3)",
        "Distinct Streaming Cascade",
        ["--distinct", "--cpu",
         "--mnemonics", "arena huge owner legend diet smart spread truth file ? ? ?",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=2,
        allow_timeout=True,
        expect_stdout=["532.162.688 chaves", "Restrição Não-Repetição", "Dedução Cascata"]
    )

    # =========================================================================
    # SUÍTE 9: Aceleração por GPU OpenCL (--gpu)
    # =========================================================================
    print(f"\n--- SUÍTE 9: Aceleração por GPU OpenCL (--gpu, --list-gpus) ---")

    # 9.1 Listagem de GPUs
    runner.run_case(
        "GPU: Listagem de dispositivos (--list-gpus)",
        "GPU Listing",
        ["--list-gpus"],
        expect_stdout=["DISPOSITIVOS OPENCL DETECTADOS NO SISTEMA", "Plat"],
        timeout_sec=10
    )

    # 9.2 Recuperação via GPU (12 palavras)
    runner.run_case(
        "GPU: Recuperação 12w OpenCL (--gpu)",
        "GPU Recovery",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut ? ?",
         "--allow", "10:desk|door|dog,11:annual|animal",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--gpu"],
        expect_stdout=["CHAVE ENCONTRADA", "ACELERAÇÃO POR HARDWARE", "OpenCL", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    # 9.3 Recuperação via GPU (15 palavras)
    runner.run_case(
        "GPU: Recuperação 15w OpenCL (--gpu)",
        "GPU Recovery",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
         "--coin", "btc", "--target", "13DiA1cRqsuxbeNRhyu7GNMZyTGyD5uKXS", "--gpu"],
        expect_stdout=["CHAVE ENCONTRADA", "address", "13DiA1cRqsuxbeNRhyu7GNMZyTGyD5uKXS"],
        timeout_sec=15
    )

    # 9.4 Recuperação via GPU (24 palavras)
    runner.run_case(
        "GPU: Recuperação 24w OpenCL (--gpu)",
        "GPU Recovery",
        ["--mnemonics", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
         "--coin", "btc", "--target", "1KBdbBJRVYffWHWWZ1moECfdVBSEnDpLHi", "--gpu"],
        expect_stdout=["CHAVE ENCONTRADA", "art", "1KBdbBJRVYffWHWWZ1moECfdVBSEnDpLHi"],
        timeout_sec=15
    )

    # 9.5 Recuperação via GPU com Passphrase
    runner.run_case(
        "GPU: Recuperação com Passphrase (--gpu --passphrase)",
        "GPU Recovery",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk ?",
         "--passphrase", "TREZOR",
         "--coin", "btc", "--target", "14c98QWfnKy8hk4tSYyAwEXea1mfyggM9t", "--gpu"],
        expect_stdout=["CHAVE ENCONTRADA", "annual", "14c98QWfnKy8hk4tSYyAwEXea1mfyggM9t"],
        timeout_sec=15
    )

    # 9.6 Recuperação via GPU em Japonês
    runner.run_case(
        "GPU: Recuperação em Japonês com UTF-8 (--gpu --lang ja)",
        "GPU Recovery",
        ["--lang", "ja",
         "--mnemonics", "あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000?",
         "--coin", "btc", "--target", "1MKBt4zk1g9YeVKNxqkxreZJJhmrk3gCCf", "--gpu"],
        expect_stdout=["CHAVE ENCONTRADA", "あおぞら", "1MKBt4zk1g9YeVKNxqkxreZJJhmrk3gCCf"],
        timeout_sec=15
    )

    # 9.7 Recuperação via GPU com Profiling Ativo
    runner.run_case(
        "GPU: Profiling de Latência e Largura de Banda (--profile-gpu)",
        "GPU Recovery",
        ["--mnemonics", "arena huge owner legend diet smart spread truth file peanut desk ?",
         "--coin", "btc", "--target", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS", "--gpu", "--profile-gpu"],
        expect_stdout=["CHAVE ENCONTRADA", "annual", "1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS"],
        timeout_sec=15
    )

    print("\n--- SUÍTE 10: Comparação Contínua SHA-512 (Nativo vs UInt<8> SIMD) ---")

    # 10.1 Suíte Comparativa Exaustiva SHA-512
    test_bin = "./build/test_sha512_comparison" if os.path.exists("./build/test_sha512_comparison") else "./test_sha512_comparison"
    runner.run_case(
        "SHA-512 Comparativo: NIST + 10k Fuzzing + SIMD",
        "Comparativo SHA512",
        [],
        binary=test_bin,
        expect_stdout=["SUCESSO TOTAL"],
        timeout_sec=30
    )

    # 10.2 Verificação do Benchmark Integrado de SHA-512
    runner.run_case(
        "Benchmark: SHA-512 Escalar vs Rota SIMD",
        "Benchmark SHA512",
        ["--benchmark"],
        expect_stdout=["[6/6] BENCHMARK: SHA-512", "BIT-EXACT MATCH", "Rota SIMD do host"],
        timeout_sec=120
    )

    runner.print_summary()
    return runner.failed

if __name__ == "__main__":
    sys.exit(main())
