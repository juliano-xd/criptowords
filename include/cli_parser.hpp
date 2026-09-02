#pragma once
#include "app_config.hpp"
#include <expected>
#include <string>

class CLIParser {
  public:
    // O único ponto de entrada do parser.
    // Retorna a config pronta OU uma string de erro detalhada.
    static std::expected<AppConfig, std::string> parse_and_validate(int argc, char* argv[]);

    // O texto de ajuda fica aqui, mas quem decide imprimir é a CLI
    static std::string_view get_help_text();
};
