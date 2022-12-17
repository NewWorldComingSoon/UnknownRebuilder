#pragma once
#include <cstdint>
#include <string>

namespace uir {
class ContextImpl;

class Context
{
public:
    enum Mode : uint32_t
    {
        Mode32,
        Mode64
    };
    enum Arch : uint32_t
    {
        ArchX86,
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
    uint32_t getArch();
    void setArch(Arch arch);

    // Get/Set Mode
    uint32_t getMode();
    void setMode(Mode mode);
    uint32_t getModeBits();
};

} // namespace uir
