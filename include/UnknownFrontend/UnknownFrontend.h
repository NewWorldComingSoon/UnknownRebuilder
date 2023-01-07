#pragma once
#include <cassert>
#include <cstdint>
#include <memory>

#include <UnknownIR/Context.h>

namespace ufrontend {

class UnknownFrontendTranslator
{
public:
    virtual ~UnknownFrontendTranslator() = default;

public:
    // Static
    static std::unique_ptr<UnknownFrontendTranslator> createArch(uir::Context &C);
};

} // namespace ufrontend
