#include <User.h>
#include <assert.h>

namespace uir {

////////////////////////////////////////////////////////////
// Ctor/Dtor
User::User() : Value() {}

User::User(Type *Ty, const char *UserName) : Value(Ty, UserName) {}

User::~User()
{
    for (Value *Val : mOperandList)
    {
        Val->user_erase(this);
    }
}

////////////////////////////////////////////////////////////
// OperandList
// Returns the list of operands for this instruction.
std::vector<Value *> &
User::getOperandList()
{
    return mOperandList;
}

const std::vector<Value *> &
User::getOperandList() const
{
    return mOperandList;
}

////////////////////////////////////////////////////////////
// Iterator
User::op_iterator
User::op_begin()
{
    return mOperandList.begin();
}

User::const_op_iterator
User::op_begin() const
{
    return mOperandList.cbegin();
}

User::op_iterator
User::op_end()
{
    return mOperandList.end();
}

User::const_op_iterator
User::op_end() const
{
    return mOperandList.cend();
}

Value *
User::op_back()
{
    return mOperandList.back();
}

Value *
User::op_front()
{
    return mOperandList.front();
}

void
User::op_push(Value *V)
{
    mOperandList.push_back(V);
}

void
User::op_pop()
{
    mOperandList.pop_back();
}

size_t
User::op_count() const
{
    return mOperandList.size();
}

void
User::op_erase(Value *V)
{
    for (auto It = mOperandList.begin(); It != mOperandList.end(); ++It)
    {
        if (*It == V)
        {
            mOperandList.erase(It);
            break;
        }
    }
}

bool
User::op_empty() const
{
    return mOperandList.empty();
}

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

void
User::setOperandAndUpdateUsers(uint32_t Index, Value *Val)
{
    assert(Index < mOperandList.size() && "setOperandAndUpdateUsers() out of range!");
    auto OldVal = mOperandList[Index];
    if (OldVal != Val)
    {
        // Set operand
        mOperandList[Index] = Val;

        // Update user
        OldVal->user_erase(this);
        Val->user_insert(this);
    }
}

} // namespace uir
