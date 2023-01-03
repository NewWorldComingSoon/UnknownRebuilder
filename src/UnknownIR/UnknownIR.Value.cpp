#include <Value.h>
#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {
////////////////////////////////////////////////////////////
// Ctor/Dtor
Value::Value() : Value(nullptr, "") {}

Value::Value(Type *Ty, const unknown::StringRef &ValueName) : mType(Ty), mValueName(ValueName), mComment("") {}

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

// Get the extra info of this object
const Value::ExtraInfoListType &
Value::getExtraInfoList() const
{
    return mExtraInfoList;
}

// Set the extra info of this object
void
Value::setExtraInfoList(const Value::ExtraInfoListType &ExtraInfo)
{
    mExtraInfoList = ExtraInfo;
}

// Get the comment of this object
const std::string
Value::getComment() const
{
    return mComment;
}

// Set the comment of this object
void
Value::setComment(const unknown::StringRef &Comment)
{
    mComment = Comment;
}

////////////////////////////////////////////////////////////
// Add/Remove
// Add extra info to this object
void
Value::addExtraInfo(const unknown::StringRef &ExtraInfo)
{
    auto It = std::find(mExtraInfoList.begin(), mExtraInfoList.end(), ExtraInfo);
    if (It == mExtraInfoList.end())
    {
        mExtraInfoList.push_back(ExtraInfo);
    }
}

// Remove extra info from this object
void
Value::removeExtraInfo(const unknown::StringRef &ExtraInfo)
{
    auto It = std::find(mExtraInfoList.begin(), mExtraInfoList.end(), ExtraInfo);
    if (It != mExtraInfoList.end())
    {
        mExtraInfoList.erase(It);
    }
}

// Add the comment of this object
void
Value::addComment(const unknown::StringRef &Comment)
{
    mComment += Comment;
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

// Get the property 'name' of the value
unknown::StringRef
Value::getPropertyName() const
{
    return "name";
}

// Get the property 'addr' of the value
unknown::StringRef
Value::getPropertyAddr() const
{
    return "addr";
}

// Get the property 'range' of the value
unknown::StringRef
Value::getPropertyRange() const
{
    return "range";
}

// Get the property 'extra' of the value
unknown::StringRef
Value::getPropertyExtra() const
{
    return "extra";
}

// Get the property 'comment' of the value
unknown::StringRef
Value::getPropertyComment() const
{
    return "comment";
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

// Print the extra info of this object
void
Value::printExtraInfo(unknown::raw_ostream &OS) const
{
    if (!getExtraInfoList().empty())
    {
        OS << getExtraInfoList().front();

        if (getExtraInfoList().size() > 1)
        {
            auto It = getExtraInfoList().begin();
            ++It;
            for (; It != getExtraInfoList().end(); ++It)
            {
                OS << UIR_SEPARATOR;
                OS << *It;
            }
        }
    }
}

// Print the comment info of this object
void
Value::printCommentInfo(unknown::raw_ostream &OS) const
{
    OS << mComment;
}

} // namespace uir
