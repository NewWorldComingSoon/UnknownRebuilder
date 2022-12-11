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
// Get/Set
// Get/Set the name of the value
std::string
Value::getName() const
{
    return mValueName;
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

} // namespace uir
