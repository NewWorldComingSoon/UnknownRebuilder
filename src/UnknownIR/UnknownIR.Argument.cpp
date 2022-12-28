#include <Argument.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     Argument
//
Argument::Argument(Type *Ty, const unknown::StringRef &ArgName, Function *F, uint32_t ArgNo) :
    Constant(Ty, ArgName), mParent(F), mArgNo(ArgNo)
{
    //
    //
}

Argument::~Argument()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the parent function of this argument
const Function *
Argument::getParent() const
{
    return mParent;
}

Function *
Argument::getParent()
{
    return mParent;
}

// Set the parent function of this argument
void
Argument::setParent(Function *F)
{
    mParent = F;
}

// Get the argument number of this argument
const uint32_t
Argument::getArgNo() const
{
    assert(mParent && "can't get number of unparented arg");
    return mArgNo;
}

// Set the argument number of this argument
void
Argument::setArgNo(uint32_t ArgNo)
{
    mArgNo = ArgNo;
}

} // namespace uir
