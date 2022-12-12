#include <User.h>
#include <assert.h>

namespace uir {

////////////////////////////////////////////////////////////
// Ctor/Dtor
User::User() {}

User::~User() {}

////////////////////////////////////////////////////////////
// Replace
// Replaces all references to the "From" definition with references to the "To"
void
User::replaceUsesOfWith(Value *From, Value *To)
{
    // nothing
}

// Change all uses of this to point to a new Value.
void
User::replaceAllUsesWith(Value *V)
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
// Get/Set
// Get/Set the operand at the specified index.
Value *
User::getOperand(uint32_t Index) const
{
    assert(Index < mOperandList.size() && "getOperand() out of range!");
    return mOperandList[Index];
}

void
User::setOperand(uint32_t Index, Value *Val)
{
    assert(Index < mOperandList.size() && "setOperand() out of range!");
    mOperandList[Index] = Val;
}

} // namespace uir
