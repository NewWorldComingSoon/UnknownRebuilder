#pragma once
#include <cassert>
#include <cstdint>
#include <memory>
#include <string>
#include <iostream>

#include <UnknownIR/UnknownIR.h>

namespace ufrontend {

class UnknownFrontendTranslator
{
public:
    UnknownFrontendTranslator() = default;
    virtual ~UnknownFrontendTranslator() = default;

public:
    // Static
    static std::unique_ptr<UnknownFrontendTranslator>
    createArch(uir::Context &C, const std::string &BinaryFile, const std::string &SymbolFile);
};

} // namespace ufrontend
