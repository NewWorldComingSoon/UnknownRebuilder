#include <Context.h>
#include <Type.h>

#include "ContextImpl/ContextImpl.h"

namespace uir {
/////////////////////////////////////////////////////////
// Ctor/Dtor
Context::Context() : Context(Arch::ArchX86, Mode::Mode32) {}

Context::Context(Arch arch, Mode mode) : mImpl(new ContextImpl(*this)), mArch(arch), mMode(mode)
{
    assert(mImpl != nullptr && "Context::Context mImpl == nullptr");
}

Context::~Context()
{
    if (mImpl)
    {
        delete mImpl;
    }
}

/////////////////////////////////////////////////////////
// Get/Set
// Get/Set Arch
Context::Arch
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
Context::Mode
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
    if (mMode == Mode::Mode32)
    {
        return 32;
    }
    else if (mMode == Mode::Mode64)
    {
        return 64;
    }
    return 64;
}

} // namespace uir
