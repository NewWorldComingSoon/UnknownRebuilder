#include <User.h>

namespace uir {

////////////////////////////////////////////////////////////
// Ctor/Dtor
User::User() {}

User::~User() {}

////////////////////////////////////////////////////////////
// Replace
// Replaces all references to the "From" definition with references to the
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

} // namespace uir
