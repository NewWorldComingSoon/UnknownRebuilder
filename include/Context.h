#pragma once
#include <stdint.h>
#include <string>

namespace uir {
class ContextImpl;

class Context
{
public:
    enum Mode
    {
        Mode32,
        Mode64
    };
    enum Arch
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
