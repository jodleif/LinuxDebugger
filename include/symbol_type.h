#pragma once
#include <elf/elf++.hh>
#include <string_view>

namespace dbg {
enum class SymbolType {
    notype,
    object,
    func,
    section,
    file
};

const std::string to_string(SymbolType at)
{
    using namespace std::string_literals;
    switch (at) {
    case SymbolType::notype:
        return "notype"s;
    case SymbolType::object:
        return "object"s;
    case SymbolType::func:
        return "func"s;
    case SymbolType::section:
        return "section"s;
    case SymbolType::file:
        return "file"s;
    }
}

constexpr SymbolType to_symbol_type(elf::stt sym)
{
    switch (sym) {
    case elf::stt::notype:
        return SymbolType::notype;
    case elf::stt::object:
        return SymbolType::object;
    case elf::stt::func:
        return SymbolType::func;
    case elf::stt::section:
        return SymbolType::section;
    case elf::stt::file:
        return SymbolType::file;
    default:
        return SymbolType::notype;
    }
    static_assert(false, "Should not arrive here");
}

struct Symbol {
    SymbolType type;
    std::string name;
    std::uintptr_t addr;
};
}