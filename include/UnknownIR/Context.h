#pragma once
#include <cstdint>
#include <string>

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
    void setArch(Arch arch);

    // Get/Set Mode
    Mode getMode();
    void setMode(Mode mode);
    uint32_t getModeBits();
};

} // namespace uir
