#include <Value.h>

#include <Internal/InternalConfig/InternalConfig.h>

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
// User
const std::unordered_set<User *> &
Value::getUsers() const
{
    return mUsers;
}

std::unordered_set<User *> &
Value::getUsers()
{
    return mUsers;
}

////////////////////////////////////////////////////////////
// Get/Set
// Get/Set the name of the value
std::string
Value::getName() const
{
    return mValueName;
}

std::string
Value::getReadableName() const
{
    // %var i32
    std::string ReadableName = UIR_LOCAL_VARIABLE_NAME_PREFIX;
    ReadableName += mValueName;
    ReadableName += " ";
    ReadableName += mType->getTypeName();

    return ReadableName;
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

// Get the bits/size of the value
uint32_t
Value::getValueBits() const
{
    return mType->getTypeBits();
}

uint32_t
Value::getValueSize() const
{
    return mType->getTypeBits() / 8;
}

////////////////////////////////////////////////////////////
// Iterator
Value::user_iterator
Value::user_begin()
{
    return mUsers.begin();
}

Value::const_user_iterator
Value::user_begin() const
{
    return mUsers.cbegin();
}

Value::user_iterator
Value::user_end()
{
    return mUsers.end();
}

Value::const_user_iterator
Value::user_end() const
{
    return mUsers.cend();
}

bool
Value::user_empty() const
{
    return mUsers.empty();
}

bool
Value::user_contains(User *U) const
{
    return mUsers.contains(U);
}

size_t
Value::user_size() const
{
    return mUsers.size();
}

size_t
Value::user_count(User *U) const
{
    return mUsers.count(U);
}

void
Value::user_insert(User *U)
{
    mUsers.insert(U);
}

void
Value::user_erase(User *U)
{
    auto It = mUsers.find(U);
    if (It != mUsers.end())
    {
        mUsers.erase(It);
    }
}

void
Value::user_clear()
{
    mUsers.clear();
}

////////////////////////////////////////////////////////////
// Replace
// Replaces all references to the "From" definition with references to the "To"
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
