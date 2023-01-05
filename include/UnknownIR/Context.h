#pragma once
#include <cstdint>
#include <string>

#include <UnknownUtils/unknown/ADT/StringRef.h>

namespace uir {
class ContextImpl;

class Context
{
public:
    enum class Mode : uint32_t
    {
        Mode32,
        Mode64
    };

    enum class Arch : uint32_t
    {
        ArchX86,
        ArchARM,
    };

private:
    Mode mMode;
    Arch mArch;

public:
    ContextImpl *const mImpl;

public:
    Context();
    Context(Arch arch, Mode mode);
    ~Context();

public:
    // Get/Set Arch
    Arch getArch();
    unknown::StringRef getArchString();
    void setArch(Arch arch);

    // Get/Set Mode
    Mode getMode();
    unknown::StringRef getModeString();
    void setMode(Mode mode);
    uint32_t getModeBits();
};

} // namespace uir
