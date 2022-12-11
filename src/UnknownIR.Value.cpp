#include <Value.h>

namespace uir {
////////////////////////////////////////////////////////////
// Ctor/Dtor
Value::Value() : mType(nullptr), mValueName("")
{
    mUsers.clear();
}

Value::Value(Type *Ty, const std::string ValueName) : mType(Ty), mValueName(ValueName)
{
    mUsers.clear();
}

Value::~Value() {}

////////////////////////////////////////////////////////////
// Context
Context &
Value::getContext() const
{
    return mType->getContext();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get/Set the name of the value
std::string
Value::getName() const
{
    return mValueName;
}

bool
Value::hasName() const
{
    return !mValueName.empty();
}

void
Value::setName(const std::string ValueName)
{
    mValueName = ValueName;
}

// Get/Set the type of the value
Type *
Value::getType() const
{
    return mType;
}

void
Value::setType(Type *Ty)
{
    mType = Ty;
}

////////////////////////////////////////////////////////////
// Replace
// Replaces all references to the "From" definition with references to the
void
Value::replaceUsesOfWith(Value *From, Value *To)
{
    // nothing
}

// Change all uses of this to point to a new Value.
void
Value::replaceAllUsesWith(Value *V)
{
    // nothing
}

} // namespace uir
