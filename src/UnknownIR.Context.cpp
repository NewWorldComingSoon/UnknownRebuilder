#include <Context.h>
#include <Type.h>

#include "ContextImpl.h"

namespace uir {
/////////////////////////////////////////////////////////
// Ctor/Dtor
Context::Context() : mImpl(new ContextImpl(*this)), mArch(ArchX86), mMode(Mode32) {}

Context::Context(Arch arch, Mode mode) : Context()
{
    mArch = arch;
    mMode = mode;
}

Context::~Context()
{
    delete mImpl;
}

/////////////////////////////////////////////////////////
// Get/Set
// Get/Set Arch
uint32_t
Context::getArch()
{
    return mArch;
}

void
Context::setArch(Arch arch)
{
    mArch = arch;
}

// Get/Set Mode
uint32_t
Context::getMode()
{
    return mMode;
}

void
Context::setMode(Mode mode)
{
    mMode = mode;
}

uint32_t
Context::getModeBits()
{
    if (mMode == Mode32)
    {
        return 32;
    }
    else if (mMode == Mode64)
    {
        return 64;
    }
    return 64;
}

} // namespace uir
