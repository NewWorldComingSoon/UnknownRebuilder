#pragma once
#include <UnknownIR/Value.h>

namespace uir {

class User : public Value
{
public:
    using OperandListType = std::vector<Value *>;

private:
    OperandListType mOperandList;

public:
    User();
    explicit User(Type *Ty, const unknown::StringRef &UserName);
    virtual ~User();

public:
    // OperandList
    // Returns the list of operands for this instruction.
    OperandListType &getOperandList();
    const OperandListType &getOperandList() const;

public:
    // Iterator
    using op_iterator = OperandListType::iterator;
    using const_op_iterator = OperandListType::const_iterator;
    op_iterator op_begin();
    const_op_iterator op_begin() const;
    op_iterator op_end();
    const_op_iterator op_end() const;
    Value *op_back();
    Value *op_front();
    void op_push(Value *V);
    void op_pop();
    size_t op_count() const;
    void op_erase(Value *V);
    bool op_empty() const;
    void op_clear();

public:
    // Virtual functions
    // Replaces all references to the "From" definition with references to the "To"
    virtual void replaceUsesOfWith(Value *From, Value *To) override;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) override;

public:
    // Get/Set
    // Get the operand at the specified index.
    const Value *getOperand(size_t Index) const;
    Value *getOperand(size_t Index);

    // Set the operand at the specified index.
    void setOperand(size_t Index, Value *Val);

    // Set the operand at the specified index and update the user list.
    void setOperandAndUpdateUsers(size_t Index, Value *Val);

public:
    // Insert/Erase/Drop
    // Insert the specified value.
    void insertOperand(Value *Val);

    // Insert the specified value and update the user list.
    void insertOperandAndUpdateUsers(Value *Val);

    // Erase the specified value.
    void eraseOperand(Value *Val);

    // Erase the specified value and update the user list.
    void eraseOperandAndUpdateUsers(Value *Val);

    // Drop all references to operands.
    void dropAllReferences();
};

} // namespace uir