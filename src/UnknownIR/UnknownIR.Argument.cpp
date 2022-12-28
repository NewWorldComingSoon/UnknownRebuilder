#include <Argument.h>
#include <Function.h>

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

////////////////////////////////////////////////////////////
// Remove/Erase
// Remove this argument from its parent, but does not delete it.
void
Argument::removeFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    if (mParent->getArgumentList().empty())
    {
        return;
    }

    mParent->getArgumentList().remove(this);
}

// Remove this argument from its parent and delete it.
void
Argument::eraseFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    if (mParent->getArgumentList().empty())
    {
        return;
    }

    for (auto It = mParent->getArgumentList().begin(); It != mParent->getArgumentList().end(); ++It)
    {
        if (*It == this)
        {
            mParent->getArgumentList().erase(It);
            this->setParent(nullptr);
            --It;
        }
    }
}

} // namespace uir
