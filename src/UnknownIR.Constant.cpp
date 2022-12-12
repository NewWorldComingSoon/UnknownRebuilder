#include <Constant.h>
#include <User.h>

#include <sstream>
#include <string>

namespace uir {
////////////////////////////////////////////////////////////
//     Constant
//
Constant::Constant(Type *Ty, const std::string ConstantName) : Value(Ty, ConstantName)
{
    //
    //
}

Constant::~Constant()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Replace
// Replaces all references to the "From" definition with references to the "To"
void
Constant::replaceUsesOfWith(Value *From, Value *To)
{
    // nothing
}

// Change all uses of this to point to a new Value.
void
Constant::replaceAllUsesWith(Value *V)
{
    if (V == this)
    {
        // We will not replace ourself.
        return;
    }

    // Replace all uses of this value with the new value.
    for (auto &User : mUsers)
    {
        User->replaceUsesOfWith(this, V);
    }
}

////////////////////////////////////////////////////////////
//     ConstantInt
//
ConstantInt::ConstantInt(Type *Ty, uint64_t Val) : Constant(Ty, std::to_string(Val))
{
    mVal = Val;
}

ConstantInt::~ConstantInt()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Replace
// Replaces all references to the "From" definition with references to the "To"
void
ConstantInt::replaceUsesOfWith(Value *From, Value *To)
{
    // nothing
}

// Change all uses of this to point to a new Value.
void
ConstantInt::replaceAllUsesWith(Value *V)
{
    // nothing
}

////////////////////////////////////////////////////////////
// Get/Set
// Get/Set the value of ConstantInt
uint64_t
ConstantInt::getValue() const
{
    return mVal;
}

void
ConstantInt::setValue(uint64_t Val)
{
    mVal = Val;
}

} // namespace uir
