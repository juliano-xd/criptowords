
<header class="hero">
  <h1>CriptoWords v2.0</h1>
  <p class="tagline">Motor C++23 de Alta Performance para Recuperação, Poda Analítica e Derivação de Frases Mnemônicas BIP-39 / BIP-44 (Bitcoin &amp; Ethereum).</p>
  <p class="sub">
    <span class="badge blue">Poda em 𝔽₂ᶜ</span>
    <span class="badge green">SHA-NI</span>
    <span class="badge purple">AVX-512</span>
    <span class="badge yellow">HIP / ROCm</span>
  </p>
</header>

<p>O <strong>CriptoWords</strong> é uma ferramenta de engenharia reversa e recuperação de chaves criptográficas projetada para restaurar frases sementes (<em>seed phrases</em>) BIP-39 com palavras perdidas, corrompidas ou desconhecidas (<code>?</code>).</p>

<p>Diferente de ferramentas de força bruta convencionais que testam combinações de forma cega, o CriptoWords adota uma abordagem fundamentada em <strong>Teoria da Informação e Poda Analítica em 𝔽₂ᶜ</strong>. O motor analisa a estrutura algébrica do checksum do BIP-39 antes de despachar qualquer combinação para o gargalo computacional pesado (<strong>PBKDF2 com 2048 rodadas de HMAC-SHA512</strong>), descartando antecipadamente até <strong>99,6%</strong> do espaço de busca em nanossegundos via instruções nativas de hardware (<strong>SHA-NI</strong>, <strong>SIMD AVX2</strong> e <strong>AVX-512</strong>), com suporte a aceleração massiva por <strong>GPU AMD via HIP/ROCm</strong> e modo cooperativo <strong>Híbrido (CPU + GPU)</strong>.</p>

<hr class="divider">

<h2 id="sumario">Sumário</h2>
<ul class="toc">
  <li><a href="#visao-geral">Visão Geral e Filosofia de Projeto</a></li>
  <li><a href="#funcionalidades">Funcionalidades Detalhadas</a>
    <ul>
      <li><a href="#f1">1. Recuperação de Incógnitas e Poda Matemática em 𝔽₂ᶜ</a></li>
      <li><a href="#f2">2. Restrições Combinatórias e Afunilamento</a></li>
      <li><a href="#f3">3. Filtro Explícito de Checksum (<code>--checksum</code>)</a></li>
      <li><a href="#f4">4. Modo Pseudoaleatório (<code>--random</code> / <code>--seed</code>)</a></li>
      <li><a href="#f5">5. Checkpoint, Save/Resume e Cobertura Persistente</a></li>
      <li><a href="#f6">6. Multi-Target com Cuckoo Filter (<code>--target-file</code>)</a></li>
      <li><a href="#f7">7. Suporte Multi-Idioma BIP-39 Oficial com Unicode NFC/NFD</a></li>
      <li><a href="#f8">8. Suporte a Todos os Tamanhos de Frase (12 a 24 palavras)</a></li>
      <li><a href="#f9">9. Derivação Criptográfica BIP-32 / BIP-44 (BTC e ETH)</a></li>
      <li><a href="#f10">10. Filtro Precoce C1-64</a></li>
      <li><a href="#f11">11. Aceleração de Hardware: CPU SIMD e GPU HIP/ROCm</a></li>
      <li><a href="#f12">12. Otimizações de Microarquitetura e Cache L1i / µOP</a></li>
      <li><a href="#f13">13. Sondagem Profunda de Hardware e Auto-Tuning</a></li>
    </ul>
  </li>
  <li><a href="#compilacao">Compilação e Instalação</a></li>
  <li><a href="#uso">Guia de Uso e Exemplos Práticos Reais</a></li>
  <li><a href="#metricas">Métricas Reais de Desempenho e Comparativo de Hardware</a></li>
  <li><a href="#qa">Garantia de Qualidade e Testes Automatizados</a></li>
  <li><a href="#limitacoes">Fraquezas Conhecidas e Limitações Atuais</a></li>
  <li><a href="#roadmap">Metas de Futuras Otimizações (Roadmap Técnico)</a></li>
  <li><a href="#licenca">Licença</a></li>
</ul>

<hr class="divider">

<h2 id="visao-geral">Visão Geral e Filosofia de Projeto</h2>

<p>A especificação oficial BIP-39 define a derivação da semente mestre através de:</p>

<div class="math-block">
  Seed = PBKDF2( senha = frase mnemônica,&nbsp;
  salt = <span style="font-style: normal;">"mnemonic"</span> + passphrase,&nbsp;
  rounds = 2048,&nbsp; prf = HMAC-SHA512 )
</div>

<p>Cada candidato requer <strong>4.098 blocos de compressão SHA-512</strong>. Em um espaço de busca com apenas 2 palavras desconhecidas (<span class="math">2048<sup>2</sup> = 4.194.304</span> combinações), uma busca cega convencional exigiria calcular mais de <strong>17,1 bilhões de blocos SHA-512</strong>, tornando o processo inviável em computadores comuns.</p>

<p>O CriptoWords inverte esse paradigma por meio de três pilares fundamentais:</p>

<ol>
  <li>
    <strong>Poda Analítica em 𝔽₂ᶜ</strong> — O checksum do BIP-39 consiste nos <span class="math">C = N/3</span> bits mais significativos de <span class="math">SHA256(entropia)</span>. Para qualquer topologia de incógnitas, o CriptoWords resolve o checksum antes de tocar no PBKDF2, reduzindo o volume de cálculo em <strong>16× (12 palavras)</strong> até <strong>256× (24 palavras)</strong>.
  </li>
  <li>
    <strong>Zero-Copy e Montagem Pré-Computada da Frase</strong> — As partes conhecidas da frase residem imutáveis no cache L1. O motor pré-computa <code>PhraseSegment</code>s (segmentos estáticos + índice da palavra variável) e escreve apenas os bytes correspondentes às incógnitas dentro do slot da senha, eliminando concatenações no loop crítico.
  </li>
  <li>
    <strong>Paralelismo em Camadas e Microarquitetura Estrita</strong>
    <ul>
      <li>Vetorização SIMD na CPU (<strong>AVX-512 + AVX512BW/VL</strong>, <strong>AVX2</strong>, <strong>SSE4.1</strong> e <strong>SHA-NI</strong>).</li>
      <li>Dimensionamento de loops para caber <strong>100% no µOP Cache</strong> e no <strong>Cache L1 de Instruções (32 KB)</strong>.</li>
      <li>Fixação estrita de afinidade a núcleos físicos reais (<code>HostProbe::get_physical_cpu_ids</code>), eliminando penalidades de SMT.</li>
      <li>Aceleração assíncrona por GPU <strong>AMD via HIP/ROCm</strong> com kernels compilados offline (<code>hipcc</code> + <code>--offload-arch</code> nativa), evitando cache binário e overhead de runtime.</li>
    </ul>
  </li>
</ol>

<hr class="divider">

<h2 id="funcionalidades">Funcionalidades Detalhadas</h2>

<h3 id="f1">1. Recuperação de Incógnitas e Poda Matemática em 𝔽₂ᶜ</h3>

<ul>
  <li><strong>Dedução Reversa da Última Palavra (<span class="math">w<sub>N−1</sub> = ?</span>)</strong> — Quando a última palavra da semente é desconhecida, seus <span class="math">C</span> bits de checksum são determinados unicamente pela entropia das palavras anteriores. O algoritmo deduz o checksum diretamente via hardware SHA-NI e sintetiza a palavra correta em <span class="math">O(1)</span>, sem testar palavras inválidas.</li>
  <li><strong>Pruning Analítico de Pares em 𝔽₂ᶜ (<span class="math">K=2</span>)</strong> — Para 2 palavras perdidas em qualquer posição, o motor pré-computa o bloco base e sintetiza uma tabela de pares válidos antes do início da busca. Em 12 palavras, das 4.194.304 combinações possíveis, apenas <strong>262.144</strong> pares matematicamente válidos são processados (redução exata de 16×).</li>
  <li><strong>Poda Streaming e Dedução Cascata (<span class="math">K ≥ 3</span>)</strong> — Para 3 ou mais incógnitas, emprega geração sob demanda com descarte prévio de candidatos que não satisfazem o checksum, mantendo consumo de memória constante (<span class="math">O(1)</span> em RAM) e saltos instantâneos de subárvores. A síntese do último slot usa SHA-NI, em pares vetorizados (2 por chamada) sobre as primeiras mensagens SHA-256 que permanecem invariantes.</li>
</ul>

<h3 id="f2">2. Restrições Combinatórias e Afunilamento</h3>

<table>
  <thead>
    <tr><th>Flag</th><th>Efeito</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><code>--distinct</code></td>
      <td>Remove palavras já fixadas de outros wheels de incógnitas; respeita <code>max_count</code> por palavra quando combinado com <code>--repeat</code>.</td>
    </tr>
    <tr>
      <td><code>--allow &lt;pos&gt;:&lt;w1&gt;|&lt;w2&gt;|…</code></td>
      <td>Restringe posições específicas a um subconjunto de palavras. De-duplicação e ordenação canônica automáticas.</td>
    </tr>
    <tr>
      <td><code>--allow-all &lt;w1&gt;|&lt;w2&gt;|…</code></td>
      <td>Aplica o mesmo subconjunto a <strong>todas</strong> as incógnitas ainda não fixadas.</td>
    </tr>
    <tr>
      <td><code>--repeat &lt;palavra&gt;:&lt;N&gt;</code></td>
      <td>Exige exatamente <code>N</code> ocorrências de uma palavra entre as incógnitas. <span class="math">Σ N</span> deve caber no número de incógnitas; caso contrário, o plano é marcado como impossível.</td>
    </tr>
    <tr>
      <td><code>--invalid_too</code></td>
      <td>Desativa a exigência de checksum válido (auditoria de sementes com integridade corrompida).</td>
    </tr>
  </tbody>
</table>

<p>O odômetro aplica <strong>subtree skipping</strong> (pula subárvores inteiras quando uma duplicata é detectada em posição precoce) e move palavras obrigatórias de <code>--repeat</code> para o início do wheel correspondente.</p>

<h3 id="f3">3. Filtro Explícito de Checksum (<code>--checksum</code>)</h3>

<p>Restringe os candidatos aos checksums que casam com um padrão fornecido. Aceita três formatos:</p>

<table>
  <thead>
    <tr><th>Formato</th><th>Sintaxe</th><th>Exemplo</th></tr>
  </thead>
  <tbody>
    <tr><td>Decimal</td><td><code>&lt;N&gt;</code></td><td><code>--checksum 7</code></td></tr>
    <tr><td>Hexadecimal</td><td><code>0x&lt;N&gt;</code></td><td><code>--checksum 0x7</code></td></tr>
    <tr><td>Binário com wildcard</td><td><code>0b&lt;pattern&gt;</code></td><td><code>--checksum 0b*1*0</code></td></tr>
  </tbody>
</table>

<ul>
  <li>O padrão binário deve ter <strong>exatamente <span class="math">C</span> bits</strong> (o número de bits de checksum da frase).</li>
  <li><code>*</code> representa "qualquer bit" (wildcard).</li>
  <li>Múltiplos padrões separados por vírgula são <strong>OR</strong>-ados.</li>
  <li>Sobrepõe <code>--only_valids</code> e <code>--invalid_too</code>.</li>
  <li>Quando o filtro deixa o espaço vazio, o plano é marcado como <strong>impossível</strong> antes do início da busca.</li>
</ul>

<h3 id="f4">4. Modo Pseudoaleatório (<code>--random</code> / <code>--seed</code>)</h3>

<p>Enumera o espaço de busca em ordem pseudoaleatória determinística (via permutação <strong>Feistel com cycle walking</strong> sobre o índice linear), em vez de crescente em mixed-radix. Útil para resistir a "zonas quentes" ou explorar o espaço em ordem diferente mantendo as propriedades de save/resume.</p>

<table>
  <thead><tr><th>Flag</th><th>Descrição</th></tr></thead>
  <tbody>
    <tr><td><code>--random</code></td><td>Ativa o modo.</td></tr>
    <tr><td><code>--seed &lt;uint64&gt;</code></td><td>Define a semente (implica <code>--random</code>). Padrão: <span class="math">2<sup>64</sup> − 59</span> (primo).</td></tr>
  </tbody>
</table>

<p>O progresso do checkpoint continua sendo o <strong>contador linear</strong> — retomar com <code>--load</code> reproduz exatamente a mesma sequência.</p>

<h3 id="f5">5. Checkpoint, Save/Resume e Cobertura Persistente</h3>

<details>
  <summary>Clique para expandir — flags de checkpoint</summary>
  <table>
    <thead><tr><th>Flag</th><th>Descrição</th></tr></thead>
    <tbody>
      <tr><td><code>--save &lt;PATH&gt;</code></td><td>Habilita gravação de checkpoints.</td></tr>
      <tr><td><code>--save-interval &lt;SEG&gt;</code></td><td>Intervalo entre gravações automáticas (0 = só na saída). Padrão: <strong>60 s</strong>.</td></tr>
      <tr><td><code>--load &lt;PATH&gt;</code></td><td>Retoma a busca a partir de um checkpoint.</td></tr>
      <tr><td><code>--resume-strict</code></td><td>Erro se o checkpoint for incompatível com a configuração atual. Por padrão, o progresso é ignorado, mas <strong>snapshots de cobertura</strong> compatíveis são mantidos.</td></tr>
    </tbody>
  </table>
</details>

<ul>
  <li><strong>SIGINT / SIGTERM</strong> — Uma interrupção grava progresso e é tratada de forma limpa, preservando o estado para retomada.</li>
  <li><strong>Snapshots de cobertura</strong> — Ao terminar naturalmente uma busca <strong>sem encontrar a chave</strong>, o espaço varrido é registrado. Execuções posteriores com a mesma <code>base_mnemonic</code> pulam candidatos já cobertos, potencialmente reduzindo drasticamente o tempo para espaços enormes divididos entre sessões.</li>
</ul>

<h3 id="f6">6. Multi-Target com Cuckoo Filter (<code>--target-file</code>)</h3>

<ul>
  <li><strong><code>--target-file &lt;PATH&gt;</code></strong> — Lê um arquivo com um endereço por linha (linhas vazias e iniciadas por <code>#</code> são ignoradas; CRLF-safe).</li>
  <li>Combina com <code>--target</code> e deduplica textualmente.</li>
  <li>Para <strong>N ≥ 8 alvos</strong>, um <strong>Cuckoo Filter</strong> (<code>include/crypto/cuckoo_filter.hpp</code>) pré-filtra as chaves derivadas em 1 comparação de hash antes do <code>memcmp</code> contra cada alvo, evitando custo linear em N.</li>
  <li>Em <code>--coin eth</code> com 1 alvo único, a verificação é delegada ao backend GPU (HIP), que já faz ECC + Keccak no dispositivo (<code>enqueue_post_pbkdf2</code>).</li>
</ul>

<h3 id="f7">7. Suporte Multi-Idioma BIP-39 Oficial com Unicode NFC/NFD</h3>

<table>
  <thead>
    <tr><th class="center">Idioma</th><th class="center">Código</th><th>Nota</th></tr>
  </thead>
  <tbody>
    <tr><td class="center">Inglês</td><td class="center"><code>en</code></td><td>Padrão</td></tr>
    <tr><td class="center">Português</td><td class="center"><code>pt</code></td><td></td></tr>
    <tr><td class="center">Espanhol</td><td class="center"><code>es</code></td><td>Composição de acentos agudos</td></tr>
    <tr><td class="center">Francês</td><td class="center"><code>fr</code></td><td></td></tr>
    <tr><td class="center">Italiano</td><td class="center"><code>it</code></td><td></td></tr>
    <tr><td class="center">Tcheco</td><td class="center"><code>cs</code></td><td></td></tr>
    <tr><td class="center">Japonês</td><td class="center"><code>ja</code></td><td>Separador ideográfico <code>U+3000</code></td></tr>
    <tr><td class="center">Coreano</td><td class="center"><code>ko</code></td><td>Sílabas NFC</td></tr>
    <tr><td class="center">Chinês Simplificado</td><td class="center"><code>zh</code> / <code>zh_cn</code></td><td></td></tr>
    <tr><td class="center">Chinês Tradicional</td><td class="center"><code>zh_tw</code></td><td></td></tr>
  </tbody>
</table>

<h3 id="f8">8. Suporte a Todos os Tamanhos de Frase (12 a 24 palavras)</h3>

<p>Detecção automática e configuração de limites com base na especificação BIP-39:</p>

<table>
  <thead>
    <tr>
      <th class="center">Tamanho</th>
      <th class="center">Entropia</th>
      <th class="center">Checksum (<span class="math">C</span>)</th>
      <th class="center">Fator de Poda Máx.</th>
      <th class="center">Espaço Bruto (<span class="math">2048<sup>K</sup></span>)</th>
      <th class="center">Espaço Pós-Poda (<span class="math">K=2</span>)</th>
    </tr>
  </thead>
  <tbody>
    <tr><td class="center"><strong>12 palavras</strong></td><td class="center">128 bits</td><td class="center">4 bits</td><td class="center"><strong>16×</strong> (93,75% descarte)</td><td class="center">4.194.304</td><td class="center">262.144</td></tr>
    <tr><td class="center"><strong>15 palavras</strong></td><td class="center">160 bits</td><td class="center">5 bits</td><td class="center"><strong>32×</strong> (96,87% descarte)</td><td class="center">4.194.304</td><td class="center">131.072</td></tr>
    <tr><td class="center"><strong>18 palavras</strong></td><td class="center">192 bits</td><td class="center">6 bits</td><td class="center"><strong>64×</strong> (98,43% descarte)</td><td class="center">4.194.304</td><td class="center">65.536</td></tr>
    <tr><td class="center"><strong>21 palavras</strong></td><td class="center">224 bits</td><td class="center">7 bits</td><td class="center"><strong>128×</strong> (99,21% descarte)</td><td class="center">4.194.304</td><td class="center">32.768</td></tr>
    <tr><td class="center"><strong>24 palavras</strong></td><td class="center">256 bits</td><td class="center">8 bits</td><td class="center"><strong>256×</strong> (99,61% descarte)</td><td class="center">4.194.304</td><td class="center"><strong>16.384</strong></td></tr>
  </tbody>
</table>

<h3 id="f9">9. Derivação Criptográfica BIP-32 / BIP-44 (BTC e ETH)</h3>

<details>
  <summary><strong>Bitcoin (BTC)</strong> — Clique para expandir</summary>
  <ul>
    <li>Caminho de derivação padrão BIP-44: <code>m/44'/0'/0'/0/0</code></li>
    <li>Compressão de chave pública secp256k1 (33 bytes).</li>
    <li>Hashing SHA-256 seguido de RIPEMD-160 (<strong>Hash160</strong>).</li>
    <li>Codificação <strong>Base58Check</strong> com validação de checksum de 4 bytes.</li>
  </ul>
</details>

<details>
  <summary><strong>Ethereum (ETH)</strong> — Clique para expandir</summary>
  <ul>
    <li>Caminho de derivação padrão BIP-44: <code>m/44'/60'/0'/0/0</code></li>
    <li>Chave pública não comprimida (65 bytes, descartando o prefixo <code>0x04</code>).</li>
    <li>Hashing <strong>Keccak-256</strong> nos 64 bytes de coordenadas <span class="math">(X, Y)</span> da curva.</li>
    <li>Endereço hexadecimal de 20 bytes (40 caracteres hex com prefixo <code>0x</code>).</li>
  </ul>
</details>

<ul>
  <li><strong>Passphrase BIP-39 Arbitrária (<code>--passphrase</code>)</strong> — Suporte completo a carteiras protegidas com senha de extensão de semente (<em>salt</em> dinâmico).</li>
  <li><strong>Modo Derivação Direta</strong> — Se a frase é completamente conhecida e não há alvo, o programa deriva e exibe instantaneamente o endereço <strong>e a chave privada</strong> gerados.</li>
</ul>

<h3 id="f10">10. Filtro Precoce C1-64 (Rejeição em 64 bits em 1 ciclo)</h3>

<p>Para evitar chamadas desnecessárias a <code>memcmp(20)</code> e reconstruções de string, o CriptoWords pré-computa um token de <strong>64 bits</strong> correspondente aos primeiros 8 bytes do alvo decodificado:</p>

<pre><code>uint64_t ripemd_fast64;
std::memcpy(&amp;ripemd_fast64, ripemd_buf.data(), 8);
if (__builtin_expect(ripemd_fast64 != target_fast64, 1)) return false; // Falso positivo: 2⁻⁶⁴
return std::memcmp(ripemd_buf.data() + 8, target_ripemd + 8, 12) == 0;</code></pre>

<h3 id="f11">11. Aceleração de Hardware: CPU SIMD e GPU HIP/ROCm</h3>

<h4>CPU SIMD (auto-vectorizado por arquitetura)</h4>

<table>
  <thead>
    <tr><th>ISA</th><th class="center">Lanes / batch</th><th>Notas</th></tr>
  </thead>
  <tbody>
    <tr><td><strong>AVX-512 (F/BW/VL)</strong></td><td class="center">16</td><td>Rotações em 1 ciclo (<code>vprorq</code>), lógica ternária (<code>vpternlogq</code>), byte-swap via <code>vpshufb</code>.</td></tr>
    <tr><td><strong>AVX2</strong></td><td class="center">8</td><td>Interleaving <code>x2</code> que sobrepõe duas cadeias independentes de SHA-512.</td></tr>
    <tr><td><strong>SSE4.1</strong></td><td class="center">4</td><td>Fallback mínimo compilado sempre.</td></tr>
    <tr><td><strong>SHA-NI</strong></td><td class="center">1</td><td><code>_mm_sha256rnds2_epu32</code> — checksum a <strong>&gt;10,30 Mop/s</strong>.</td></tr>
  </tbody>
</table>

<h4>GPU AMD ROCm / HIP</h4>

<ul>
  <li>Kernel HIP customizado (<code>src/gpu/hip/hip_engine.hip</code>) compilado <strong>offline</strong> por <code>hipcc</code> com <code>--offload-arch=&lt;gfx&gt;</code> nativa.</li>
  <li>Detecção de arquitetura via <code>rocminfo</code> com fallback a <code>hipcc --print-target-id</code>.</li>
  <li>Compilação desacoplada do CMake de C++ puro: flags HIP <strong>não vazam</strong> para targets C++ (PCH, etc.).</li>
  <li>Modo <strong>Post-PBKDF2 na GPU</strong> — Os seeds de 64 bytes produzidos pelo PBKDF2 SIMD na CPU são enviados em ping-pong para o dispositivo, que faz ECC secp256k1 + Keccak-256 + comparação com o alvo (ideal para <strong>ETH</strong>, 1 alvo).</li>
  <li><code>--list-gpus</code> lista os dispositivos AMD detectados via HIP.</li>
</ul>

<h4>Modo Híbrido Cooperativo (<code>--hybrid</code>)</h4>

<p>Combina CPU e GPU simultaneamente sobre o mesmo espaço de busca.</p>

<aside class="note">
  <strong>Nota:</strong> O backend anterior era <strong>OpenCL</strong>. A migração para <strong>HIP/ROCm</strong> elimina o cache binário OpenCL e o overhead de runtime, ao custo de exigir um runtime ROCm funcional no host. GPUs integradas podem não ter suporte ROCm oficial; nesse caso, use o modo CPU SIMD (padrão) ou compile com <code>-DCRYPTOWORDS_ENABLE_HIP=OFF</code>.
</aside>

<h3 id="f12">12. Otimizações de Microarquitetura e Cache L1i / µOP</h3>

<ul>
  <li><strong>Adequação Estrita ao µOP Cache</strong> — Remoção do unrolling forçado nas rotinas de bloco do SHA-512, reduzindo a pegada de código de cada função de <strong>22,8 KB</strong> para <strong>5,3 KB</strong>. O loop do PBKDF2 de 2048 iterações passa a residir <strong>100% dentro do Cache de Instruções L1i (32 KB)</strong> e do µOP Cache, eliminando paradas de decodificação no pipeline.</li>
  <li><strong>Afinidade de Núcleos Físicos Reais (<code>HostProbe::get_physical_cpu_ids</code>)</strong> — Identificação precisa dos núcleos físicos primários via <code>/sys/devices/system/cpu/cpu*/topology/core_id</code> e aplicação de <code>pthread_setaffinity_np</code>. A contenção de recursos do SMT (Hyper-Threading) é eliminada, derrubando o jitter multithread de <strong>69,3%</strong> para <strong>14,7%</strong>.</li>
  <li><strong>Curva Elíptica Secp256k1 via Tabela Comb de 8 bits Constexpr</strong> — Geração em tempo de compilação de <strong>32 pontos geradores</strong> (<span class="math">G<sub>256i</sub>, i = 0..31</span>) alinhados em L1D, e uma tabela de combinação por byte (<span class="math">32 × 256</span> pontos afins) montada em runtime com <strong>batch-normalize</strong> (1 inversão por byte em vez de 255). Substitui o algoritmo clássico de 128 adições por apenas 32 adições mistas afins.</li>
</ul>

<h3 id="f13">13. Sondagem Profunda de Hardware e Auto-Tuning Adaptativo (<code>HostProbe</code>)</h3>

<ul>
  <li>Extração automática de fabricante, modelo, frequências e topologia de processador (<code>Zen 2/3/4/5</code>, <code>Intel Core/Xeon</code>).</li>
  <li>Medição exata da hierarquia de memórias cache L1d, L1i, L2 e L3.</li>
  <li>Detecção e classificação de todos os dispositivos AMD ROCm/HIP disponíveis no sistema com pontuação de relevância.</li>
  <li>Relatório técnico estruturado via <code>--host-info</code> (alias <code>--probe</code>) com recomendação automática da melhor orquestração de hardware.</li>
  <li><code>--quiet</code> / <code>-q</code> suprime banners e estatísticas finais; o diagnóstico explícito de <code>--host-info</code> sempre imprime.</li>
</ul>

<hr class="divider">

<h2 id="compilacao">Compilação e Instalação</h2>

<h3>Pré-requisitos</h3>

<ul>
  <li>Compilador C++ com suporte a <strong>C++23</strong> (GCC 14+ ou Clang 17+).</li>
  <li><strong>CMake</strong> versão 3.25 ou superior.</li>
  <li><strong>GMP</strong> (<code>libgmp-dev</code> no Debian/Ubuntu, <code>gmp-devel</code> no Fedora/RHEL). <em>Obrigatório</em> — usado para contagens exatas em <code>mpz_class</code> no planejador.</li>
  <li><strong>pkg-config</strong> (recomendado).</li>
  <li>
    <strong>HIP / ROCm</strong> (Opcional, para aceleração GPU em placas AMD):
    <ul>
      <li><code>hipcc</code>, <code>rocminfo</code> e bibliotecas <code>libamdhip64</code> / <code>hsa-runtime64</code> em <code>/opt/rocm</code>.</li>
      <li>Ver <a href="https://rocm.docs.amd.com/projects/install-on-linux/en/latest/">ROCm installation guide</a>.</li>
      <li>Para desabilitar o backend: <code>-DCRYPTOWORDS_ENABLE_HIP=OFF</code>.</li>
    </ul>
  </li>
</ul>

<aside class="note">
  <strong>Compilação Otimizada por Padrão</strong> — O sistema de build CMake habilita automaticamente <code>-march=native -mtune=native</code> e <strong>Link-Time Optimization (LTO / IPO)</strong> em compilações <code>Release</code>, garantindo que o compilador utilize todas as extensões do seu processador (AVX-512, AVX2, SHA-NI, BMI2) com inlining inter-procedural entre arquivos fonte.
</aside>

<aside class="note">
  <strong>Download Automático de Dependências</strong> — Se <code>CLI11</code> não estiver presente no sistema operacional, o CMake baixará, configurará e compilará a biblioteca oficial via <code>FetchContent</code>.
</aside>

<h3>Passo a Passo de Compilação</h3>

<pre><code># 1. Clone o repositório
git clone https://github.com/juliano-xd/criptowords.git
cd criptowords

# 2. Configure o build em modo Release
cmake -B build -DCMAKE_BUILD_TYPE=Release

# (opcional) Desabilitar o backend HIP se você não tem ROCm instalado
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_ENABLE_HIP=OFF

# 3. Compile utilizando todos os núcleos do processador
cmake --build build -j$(nproc)</code></pre>

<p>O binário executável otimizado será gerado em <code>build/criptowords</code>.</p>

<h3>Testes</h3>

<p>O projeto integra o CTest via <code>BUILD_TESTING</code> (habilitado por padrão):</p>

<pre><code>cd build
ctest --output-on-failure</code></pre>

<hr class="divider">

<h2 id="uso">Guia de Uso e Exemplos Práticos Reais</h2>

<h3>1. Derivação Direta (Conferência de Endereço)</h3>

<p>Caso possua todas as palavras e queira conferir o endereço gerado sem efetuar busca:</p>

<pre><code>./build/criptowords --mnemonics "arena huge owner legend diet smart spread truth file peanut desk annual" --coin btc</code></pre>

<p><em>Gera o endereço Bitcoin correspondente:</em> <code>1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS</code>.</p>

<h3>2. Recuperação de 1 Palavra Perdida no Fim (Dedução Instantânea em <span class="math">O(1)</span>)</h3>

<p>A última palavra contém o checksum. O CriptoWords utiliza SHA-NI para derivar a palavra em menos de 0,01 segundos:</p>

<pre><code>./build/criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut desk ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS</code></pre>

<h3>3. Recuperação de 2 Palavras Perdidas com Poda Analítica (16× mais rápida)</h3>

<pre><code>./build/criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS \
  --threads 4</code></pre>

<h3>4. Recuperação com Restrição de Não-Repetição (<code>--distinct</code>)</h3>

<pre><code>./build/criptowords \
  --distinct \
  --mnemonics "arena huge owner legend diet smart spread truth file ? ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS</code></pre>

<h3>5. Recuperação com Restrição Pontual (<code>--allow</code>) e Global (<code>--allow-all</code>)</h3>

<pre><code># Restrição por posição específica
./build/criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? annual" \
  --allow "10:desk|door|dog|dark" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS

# Mesmo subconjunto aplicado a todas as incógnitas
./build/criptowords \
  --mnemonics "arena huge owner legend diet smart ? ? ? ? desk annual" \
  --allow-all "truth|file|peanut|spread" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS</code></pre>

<h3>6. Filtro por Padrão de Checksum (<code>--checksum</code>)</h3>

<pre><code># Aceita apenas checksums com o bit mais significativo em 1 (4 bits em 12 palavras)
./build/criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut desk ?" \
  --checksum 0b1*** \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS</code></pre>

<h3>7. Recuperação com Restrição de Contagem (<code>--repeat</code>)</h3>

<pre><code># A palavra "abandon" deve aparecer exatamente 3 vezes entre as 4 incógnitas
./build/criptowords \
  --mnemonics "abandon abandon abandon abandon abandon abandon abandon abandon abandon ? ? ? ?" \
  --repeat "abandon:3" \
  --coin btc \
  --target &lt;ADDRESS&gt;</code></pre>

<h3>8. Recuperação de Carteira Ethereum com Passphrase</h3>

<pre><code>./build/criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut desk ?" \
  --passphrase "MinhaSenhaSegura" \
  --coin eth \
  --target 0x71C8084A3B4380Dfc51F5FCE874b348EFeC0179F</code></pre>

<h3>9. Recuperação Multi-Target com Arquivo (<code>--target-file</code>)</h3>

<pre><code># enderecos.txt: um endereço BTC por linha; linhas com # são ignoradas
./build/criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" \
  --coin btc \
  --target-file enderecos.txt</code></pre>

<p>Com N ≥ 8 alvos, o Cuckoo Filter entra automaticamente.</p>

<h3>10. Busca com Checkpoint, Save e Resume</h3>

<pre><code># Salva checkpoint a cada 30s
./build/criptowords \
  --mnemonics "arena huge owner legend diet smart ? ? ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS \
  --save progresso.ckpt --save-interval 30

# Ctrl+C grava e sai limpo. Para retomar:
./build/criptowords \
  --load progresso.ckpt \
  --mnemonics "arena huge owner legend diet smart ? ? ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS

# Se quiser exigir compatibilidade estrita de configuração:
./build/criptowords --load progresso.ckpt --resume-strict ...</code></pre>

<h3>11. Enumeração Pseudoaleatória (<code>--random</code> / <code>--seed</code>)</h3>

<pre><code>./build/criptowords \
  --random --seed 123456789 \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS \
  --save random.ckpt</code></pre>

<h3>12. Aceleração por GPU HIP e Modo Híbrido</h3>

<pre><code># Listar GPUs AMD detectadas via HIP
./build/criptowords --list-gpus

# Busca acelerada por GPU (AMD ROCm)
./build/criptowords \
  --gpu \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" \
  --coin eth \
  --target 0x... \
  --threads 1

# Modo híbrido cooperativo (CPU SIMD + GPU simultâneos)
./build/criptowords \
  --hybrid \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS</code></pre>

<h3>13. Diagnóstico Arquitetural do Host e Auto-Tuning</h3>

<pre><code>./build/criptowords --host-info
# (equivalente) ./build/criptowords --probe</code></pre>

<h3>14. Saída Silenciosa (Automação)</h3>

<pre><code># Apenas o endereço derivado é impresso em stdout
./build/criptowords -q --mnemonics "arena huge owner legend diet smart spread truth file peanut desk annual" --coin btc</code></pre>

<h3>15. Formato de Progresso (<code>--prog</code>)</h3>

<pre><code># Progresso por palavra (padrão): mostra os mnemônicos sendo testados
./build/criptowords ... --prog word

# Progresso por índice numérico dos wheels: "[i/N]"
./build/criptowords ... --prog num</code></pre>

<hr class="divider">

<h2 id="metricas">Métricas Reais de Desempenho e Comparativo de Hardware</h2>

<p>As tabelas a seguir refletem medições em ambiente de desenvolvimento local e em servidor dedicado. <strong>Números de GPU são históricos da era OpenCL</strong> e podem variar sob HIP; os de CPU SIMD permanecem representativos da arquitetura atual.</p>

<h3>1. Máquina Local (AMD Ryzen 5 7520U + Radeon 610M)</h3>

<ul>
  <li><strong>CPU:</strong> AMD Ryzen 5 7520U (4 Núcleos Físicos / 8 Threads Zen 2 @ 2.80 – 4.30 GHz, TDP de 15W, AVX2, SSE4.1, SHA-NI, BMI2).</li>
  <li><strong>GPU:</strong> AMD Radeon 610M (2 Compute Units RDNA2 @ 1899 MHz / VRAM compartilhada).</li>
</ul>

<h4>A. Throughput PBKDF2-HMAC-SHA512 (2048 Rodadas — Medição com Core Pinning)</h4>

<table>
  <thead>
    <tr>
      <th class="center">Threads Ativas</th>
      <th class="center">Lote/Thread</th>
      <th class="center">Tempo (ms)</th>
      <th class="center">Throughput Efetivo</th>
      <th class="center">Jitter</th>
      <th class="center">Speedup</th>
      <th class="center">Eficiência / Núcleo</th>
    </tr>
  </thead>
  <tbody>
    <tr><td class="center"><strong>1 Thread</strong></td><td class="center">128</td><td class="center">64,05 ms</td><td class="center"><strong>1.998,35 keys/s</strong></td><td class="center">18,5%</td><td class="center">1,00×</td><td class="center">100,0%</td></tr>
    <tr><td class="center"><strong>2 Threads</strong></td><td class="center">128</td><td class="center">69,42 ms</td><td class="center"><strong>3.687,63 keys/s</strong></td><td class="center">6,7%</td><td class="center">1,85×</td><td class="center">92,3%</td></tr>
    <tr><td class="center"><strong>4 Threads</strong></td><td class="center">128</td><td class="center">67,29 ms</td><td class="center"><strong>7.608,42 keys/s</strong></td><td class="center">17,2%</td><td class="center"><strong>3,81×</strong></td><td class="center"><strong>95,2%</strong></td></tr>
    <tr><td class="center"><strong>8 Threads (SMT)</strong></td><td class="center">128</td><td class="center">137,00 ms</td><td class="center"><strong>7.474,37 keys/s</strong></td><td class="center">16,3%</td><td class="center">3,74×</td><td class="center">46,8%</td></tr>
  </tbody>
</table>

<aside class="note">
  <strong>Nota de Arquitetura:</strong> 4 núcleos físicos operando a <strong>7.608 keys/s</strong> equivalem a processar <strong>2,49 bilhões de rodadas SHA-512 por segundo</strong>. Como o Zen 2 possui 2 portas vetoriais de 256 bits (FP0 e FP1), a CPU está retirando <strong>~2,05 instruções vetoriais por ciclo de clock</strong>, atingindo 100% da sua capacidade máxima de silício em 15W.
</aside>

<h4>B. Poda de Checksum BIP-39 e SHA-256 (SHA-NI Hardware)</h4>

<table>
  <thead>
    <tr><th>Operação</th><th class="center">Iterações</th><th class="center">Throughput</th><th class="center">Latência Média</th><th class="center">Ganho vs Escalar</th></tr>
  </thead>
  <tbody>
    <tr><td><strong>BIP-39 Checksum (12 palavras)</strong></td><td class="center">500.000</td><td class="center"><strong>10,30 Mop/s</strong></td><td class="center"><strong>97,06 ns/op</strong></td><td class="center"><strong>2,89× mais rápido</strong></td></tr>
    <tr><td><strong>SHA-256 Escalar Software (64B)</strong></td><td class="center">100.000</td><td class="center">1,47 Mhash/s</td><td class="center">681,92 ns/bloco</td><td class="center">1,00×</td></tr>
    <tr><td><strong>SHA-256 Hardware SHA-NI (64B)</strong></td><td class="center">100.000</td><td class="center"><strong>17,31 Mhash/s</strong></td><td class="center"><strong>57,77 ns/bloco</strong> (1056 MB/s)</td><td class="center"><strong>11,80× speedup</strong></td></tr>
  </tbody>
</table>

<h4>C. Microbenchmarks de Curva Elíptica Secp256k1 &amp; BIP-32</h4>

<table>
  <thead>
    <tr><th>Operação</th><th class="center">Custo / Latência</th><th class="center">Throughput</th><th class="center">Comparativo</th></tr>
  </thead>
  <tbody>
    <tr><td><strong>Adição Escalar libsecp256k1</strong></td><td class="center">37,52 ns/op</td><td class="center">26,65 Mop/s</td><td class="center">1,00× (referência histórica)</td></tr>
    <tr><td><strong>Adição Escalar UInt&lt;4&gt; Nativa</strong></td><td class="center"><strong>13,10 ns/op</strong></td><td class="center"><strong>76,33 Mop/s</strong></td><td class="center"><strong>2,86× speedup</strong></td></tr>
    <tr><td><strong>Multiplicação <span class="math">F<sub>p</sub></span> (<code>mul_mod_p</code>)</strong></td><td class="center">26,79 ns/op</td><td class="center">37,32 Mop/s</td><td class="center">—</td></tr>
    <tr><td><strong>Quadratura <span class="math">F<sub>p</sub></span> (<code>sqr_mod_p</code>)</strong></td><td class="center">23,58 ns/op</td><td class="center">42,40 Mop/s</td><td class="center">1,14× speedup vs mul</td></tr>
    <tr><td><strong>Inversão Modular <span class="math">F<sub>p</sub></span></strong></td><td class="center">6.788,56 ns/op</td><td class="center">0,15 Mop/s</td><td class="center">—</td></tr>
    <tr><td><strong>Pubkey Create libsecp256k1</strong></td><td class="center">17,19 µs/op</td><td class="center">58.173 ops/s</td><td class="center">1,00× (referência histórica)</td></tr>
    <tr><td><strong>Pubkey Create Comb 8-bit Nativa</strong></td><td class="center"><strong>12,97 µs/op</strong></td><td class="center"><strong>77.100 ops/s</strong></td><td class="center"><strong>1,33× speedup</strong></td></tr>
    <tr><td><strong>Derivação Completa BIP-32/BIP-44</strong></td><td class="center"><strong>52,24 µs/chave</strong></td><td class="center"><strong>19.140,60 deriv/s</strong></td><td class="center"><strong>1,17× speedup</strong></td></tr>
  </tbody>
</table>

<h4>D. Throughput Efetivo com Poda Analítica (projeção)</h4>

<ul>
  <li><strong>Throughput Efetivo (com Poda 16× em 12w):</strong> <strong>267,65 Kkeys/s</strong></li>
  <li><strong>Throughput Efetivo (com Poda 256× em 24w):</strong> <strong>4,28 Mkeys/s</strong></li>
</ul>

<h3>2. Servidor Cloud (Intel Xeon Platinum 8180M + NVIDIA RTX A4000)</h3>

<ul>
  <li><strong>CPU:</strong> Intel Xeon Platinum 8180M (28 Núcleos / 56 Threads @ 2.50 – 3.80 GHz, com extensões <strong>AVX-512 F/CD/BW/DQ/VL</strong>, 32 registradores ZMM de 512 bits).</li>
  <li><strong>GPU:</strong> NVIDIA RTX A4000 (16 GB GDDR6, 6144 CUDA Cores, PCIe Gen4) — utilizada via OpenCL na medição original.</li>
</ul>

<table>
  <thead>
    <tr><th>Métrica / Benchmark</th><th class="center">Intel Xeon 8180M (AVX-512)</th><th class="center">vs Ryzen 5 7520U (AVX2)</th></tr>
  </thead>
  <tbody>
    <tr><td><strong>PBKDF2 1 Thread (AVX-512)</strong></td><td class="center"><strong>5.392,81 keys/s</strong></td><td class="center"><strong>2,69× mais rápido</strong> por núcleo</td></tr>
    <tr><td><strong>PBKDF2 4 Threads (AVX-512)</strong></td><td class="center"><strong>21.515,06 keys/s</strong> (99,7% efic., 3,7% jitter)</td><td class="center"><strong>2,83× mais rápido</strong></td></tr>
  </tbody>
</table>

<h3>3. Comparativo de Throughput: Commit <code>68570d3</code> vs Versão Atual</h3>

<table>
  <thead>
    <tr><th>Componente / Métrica</th><th class="center">Commit <code>68570d3</code></th><th class="center">Versão Atual</th><th class="center">Ganho</th></tr>
  </thead>
  <tbody>
    <tr><td><strong>PBKDF2 1 Thread (CPU Local)</strong></td><td class="center">1.013,68 keys/s</td><td class="center"><strong>1.998,35 – 2.004,66 keys/s</strong></td><td class="center"><strong>+97,1% (1,97×)</strong></td></tr>
    <tr><td><strong>PBKDF2 4 Threads (CPU Local)</strong></td><td class="center">2.711,71 keys/s</td><td class="center"><strong>7.608,42 keys/s</strong></td><td class="center"><strong>+180,6% (2,81×)</strong></td></tr>
    <tr><td><strong>PBKDF2 4 Threads (Xeon AVX-512)</strong></td><td class="center">—</td><td class="center"><strong>21.515,06 keys/s</strong></td><td class="center"><strong>7,93× vs commit anterior</strong></td></tr>
    <tr><td><strong>Jitter Multithread (Estabilidade)</strong></td><td class="center">69,3%</td><td class="center"><strong>14,7% / 17,2%</strong></td><td class="center"><strong>4,7× mais estável</strong></td></tr>
    <tr><td><strong>Poda de Checksum (SHA-NI)</strong></td><td class="center">3,56 Mop/s (280,8 ns)</td><td class="center"><strong>10,30 Mop/s (97,0 ns)</strong></td><td class="center"><strong>+189,3% (2,89×)</strong></td></tr>
    <tr><td><strong>Criação de Pubkey Secp256k1</strong></td><td class="center">17,19 µs/op</td><td class="center"><strong>12,97 µs/op</strong></td><td class="center"><strong>+32,5% (1,33×)</strong></td></tr>
    <tr><td><strong>Derivação BIP-32/BIP-44</strong></td><td class="center">16.403 deriv/s (60,96 µs)</td><td class="center"><strong>19.140 deriv/s (52,24 µs)</strong></td><td class="center"><strong>+16,7% mais rápida</strong></td></tr>
    <tr><td><strong>Filtro Precoce de Endereço</strong></td><td class="center">C1 (32-bit)</td><td class="center"><strong>C1-64 (64-bit)</strong></td><td class="center"><strong>Dupla Precisão em 1 Ciclo</strong></td></tr>
  </tbody>
</table>

<h3>4. Teste de Busca Real em Lote Massivo (2 Incógnitas = 4.194.304 Chaves)</h3>

<p>Executado em modo de busca real completa no servidor com processador Intel Xeon Platinum 8180M (AVX-512):</p>

<pre><code># Busca Real em Bitcoin (2 incógnitas no fim)
./build/criptowords --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" --coin btc --target 1...</code></pre>

<ul>
  <li><strong>Tempo Total Decorrido:</strong> <strong>18,65 segundos</strong></li>
  <li><strong>Throughput Efetivo de Varredura:</strong> <strong>224,89 Kkeys/s</strong> (Espaço coberto: 4.194.304 chaves brutas)</li>
  <li><strong>Throughput Sustentado PBKDF2:</strong> <strong>15,24 Kkeys/s</strong> de cálculo pesado contínuo</li>
</ul>

<pre><code># Busca Real em Ethereum (2 incógnitas no fim)
./build/criptowords --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" --coin eth --target 0x...</code></pre>

<ul>
  <li><strong>Tempo Total Decorrido:</strong> <strong>18,28 segundos</strong></li>
  <li><strong>Throughput Efetivo de Varredura:</strong> <strong>229,44 Kkeys/s</strong></li>
  <li><strong>Throughput Sustentado PBKDF2:</strong> <strong>14,35 Kkeys/s</strong> de cálculo pesado contínuo</li>
</ul>

<hr class="divider">

<h2 id="qa">Garantia de Qualidade e Testes Automatizados</h2>

<p>O CriptoWords possui uma suíte de testes de regressão e conformidade criptográfica integrada ao <strong>CTest</strong>.</p>

<pre><code>cd build
ctest --output-on-failure</code></pre>

<h3>Categorias de Teste Validadas (histórico — a suíte em Python foi descontinuada)</h3>

<ol>
  <li>
    <strong>Vetores Oficiais de Especificação BIP-39 (Trezor / Python bip-utils)</strong>
    <ul>
      <li>Derivação semente-para-chave bit a bit idêntica para 12, 15, 18, 21 e 24 palavras.</li>
      <li>Suporte a passphrases complexas (ex.: <code>'TREZOR'</code>, caracteres especiais, espaços).</li>
    </ul>
  </li>
  <li>
    <strong>Cobertura de Todos os Idiomas</strong>
    <ul>
      <li>Validação dos dicionários e normalizações Unicode para Inglês, Português, Espanhol, Francês, Italiano, Tcheco, Japonês (<code>U+3000</code>), Coreano e Chinês.</li>
    </ul>
  </li>
  <li>
    <strong>Conformidade de Endereços</strong>
    <ul>
      <li>Endereços Bitcoin Legacy P2PKH Base58Check (<code>1…</code>).</li>
      <li>Endereços Ethereum 0x com Keccak-256 (<code>0x…</code>).</li>
    </ul>
  </li>
  <li>
    <strong>Precisão da Poda Analítica em 𝔽₂ᶜ</strong>
    <ul>
      <li>Dedução reversa instantânea de 1 incógnita (<span class="math">K=1</span>).</li>
      <li>Pruning de pares exato para 2 incógnitas (<span class="math">K=2</span>).</li>
      <li>Poda streaming para <span class="math">K ≥ 3</span> com integridade de checksum mantida.</li>
    </ul>
  </li>
  <li>
    <strong>Equivalência entre rotas</strong>
    <ul>
      <li>Escalar, SSE4.1, AVX2, AVX-512 e GPU HIP produzem resultados bit a bit equivalentes.</li>
    </ul>
  </li>
</ol>

<hr class="divider">

<h2 id="limitacoes">Fraquezas Conhecidas e Limitações Atuais</h2>

<p>Com o objetivo de manter total transparência e rigor técnico, destacamos as limitações intrínsecas da implementação atual:</p>

<ol>
  <li>
    <strong>Complexidade Intratável para <span class="math">K ≥ 4</span> Incógnitas sem Restrições</strong><br>
    Apesar da redução matemática de até 256× proporcionada pelo checksum, o espaço combinatório para 4 palavras abertas sem restrições atinge <span class="math">2048<sup>4</sup> / 16 ≈ 1,09 × 10<sup>12</sup></span> chaves. A uma velocidade de ~10.000 chaves/segundo em hardware doméstico, a recuperação exigiria mais de <strong>3 anos</strong> de processamento ininterrupto. Buscas com 4 ou mais incógnitas só são viáveis caso o usuário utilize restrições com <code>--allow</code>, <code>--allow-all</code>, <code>--repeat</code>, <code>--checksum</code> ou <code>--distinct</code>.
  </li>
  <li>
    <strong>Custo Fixo Inviolável do PBKDF2 (BIP-39 Standard)</strong><br>
    O algoritmo PBKDF2 com 2048 rodadas foi deliberadamente projetado pelos autores do BIP-39 para ser lento contra ataques de força bruta. Nenhuma otimização de software ou hardware pode eliminar a dependência estrita entre as 2048 iterações de HMAC-SHA512 para um candidato válido.
  </li>
  <li>
    <strong>Mecanismo de Watchdog / TDR em Drivers Gráficos de Desktop</strong><br>
    Sistemas operacionais desktop (Linux com DRM e Windows) possuem temporizadores de detecção de travamento (TDR). Em GPUs integradas modestas, lotes longos podem exceder o watchdog, acionando o reset do driver gráfico. Por essa razão, o CriptoWords ajusta lotes conservadores automaticamente.
  </li>
  <li>
    <strong>Requisitos de Runtime para GPU AMD (ROCm)</strong><br>
    O backend HIP exige um runtime ROCm funcional com suporte oficial à GPU alvo. GPUs AMD antigas ou integradas modestas podem não estar na lista oficial de dispositivos ROCm suportados; nesse caso, o programa deve ser compilado com <code>-DCRYPTOWORDS_ENABLE_HIP=OFF</code> e executado em modo CPU SIMD.
  </li>
  <li>
    <strong>Ausência de Alvos SegWit Nativo (Bech32 / Bech32m)</strong><br>
    A versão atual possui decodificadores e derivadores nativos para endereços <strong>Bitcoin Legacy (P2PKH — formato <code>1…</code>)</strong> e <strong>Ethereum (<code>0x…</code>)</strong>. Endereços SegWit nativos (P2WPKH <code>bc1q…</code>) e Taproot (P2TR <code>bc1p…</code>) utilizam caminhos de derivação BIP-84/BIP-86 e ainda não estão integrados como alvos automáticos de busca.
  </li>
  <li>
    <strong>Comprimento Máximo de Passphrase Limitado a 99 Caracteres</strong><br>
    Para permitir que o bloco de salt do PBKDF2 seja pré-computado e processado em um único bloco de compressão SHA-512 de 128 bytes, a passphrase suporta até 99 caracteres (<span class="math">8</span> bytes de <code>"mnemonic"</code> <span class="math">+ 99</span> bytes <span class="math">+ 4</span> bytes de índice <span class="math">+ 1</span> byte de padding <span class="math">= 112</span> bytes <span class="math">≤ 112</span> bytes do bloco SHA-512).
  </li>
  <li>
    <strong>Suporte a Multi-Target em Backend GPU Ainda Restrito</strong><br>
    O caminho <code>enqueue_post_pbkdf2</code> (ECC + Keccak na GPU) aceita <strong>um único alvo</strong>. Para usar <code>--target-file</code> com N &gt; 1 alvos, a verificação cai no caminho CPU multi-target com Cuckoo Filter.
  </li>
</ol>

<hr class="divider">

<h2 id="roadmap">Metas de Futuras Otimizações (Roadmap Técnico)</h2>

<ul class="checkbox-list">
  <li class="done"><strong>Cuckoo / Bloom SIMD Multi-Alvo</strong> — já implementado em <code>include/crypto/cuckoo_filter.hpp</code> para N ≥ 8 alvos.</li>
  <li class="done"><strong>Derivação Secp256k1 Parcial na GPU</strong> — <code>enqueue_post_pbkdf2</code> já executa ECC + Keccak no dispositivo HIP para ETH (1 alvo).</li>
  <li><strong>Suporte a BIP-84 (Native SegWit Bech32) e BIP-86 (Taproot)</strong> — implementar decodificação e conferência rápida de endereços iniciados em <code>bc1q</code> e <code>bc1p</code>.</li>
  <li><strong>Multi-Target Nativo na GPU</strong> — estender <code>enqueue_post_pbkdf2</code> para comparar contra um conjunto de alvos carregados uma vez na VRAM.</li>
  <li><strong>Vetorização do BIP-32 em CPU</strong> — executar o primeiro salto do BIP-32 (<span class="math">m/44'</span>) em paralelo vetorial para as 8 (AVX2) ou 16 (AVX-512) sementes já produzidas pelo lote do PBKDF2.</li>
  <li><strong>Backend de Computação via Vulkan / Metal</strong> — suporte a aceleração gráfica em plataformas sem drivers ROCm (macOS Apple Silicon via Metal, Android/Termux via Vulkan Compute).</li>
  <li><strong>Backend CUDA</strong> — adicionar suporte a placas NVIDIA nativas (o esqueleto <code>NvidiaContext</code> já existe em <code>include/search/context.hpp</code>).</li>
</ul>

<hr class="divider">

<h2 id="licenca">Licença</h2>

<p>Distribuído sob licença <strong>MIT</strong>. Consulte o arquivo de licença correspondente para mais informações.</p>

<footer>
  <p><strong>CriptoWords v2.0</strong> · Motor BIP-39 / BIP-44 de Alta Performance</p>
  <p>Feito com C++23 · SHA-NI · AVX-512 · HIP/ROCm</p>
</footer>
