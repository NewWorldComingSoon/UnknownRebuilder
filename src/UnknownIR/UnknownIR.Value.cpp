#include <Value.h>
#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {
////////////////////////////////////////////////////////////
// Ctor/Dtor
Value::Value() : mType(nullptr), mValueName("") {}

Value::Value(Type *Ty, const unknown::StringRef &ValueName) : mType(Ty), mValueName(ValueName) {}

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
const Value::UsersListType &
Value::getUsers() const
{
    return mUsers;
}

Value::UsersListType &
Value::getUsers()
{
    return mUsers;
}

////////////////////////////////////////////////////////////
// Get/Set
// Get/Set the name of the value
bool
Value::hasName() const
{
    return !mValueName.empty();
}

void
Value::setName(const char *ValueName)
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
    auto It = mUsers.find(U);
    if (It == mUsers.end())
    {
        mUsers.insert(U);
    }
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
// Virtual functions
// Get the name of the value
std::string
Value::getName() const
{
    return mValueName;
}

// Get the readable name of the value
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

// Print the object name
void
Value::print(unknown::raw_ostream &OS, bool NewLine) const
{
    OS << getReadableName();
    if (NewLine)
    {
        OS << "\n";
    }
}

} // namespace uir
