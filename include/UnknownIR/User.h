#pragma once

#include <vector>
#include <cstdint>

#include <UnknownIR/Value.h>

namespace uir {

class User : public Value
{
private:
    std::vector<Value *> mOperandList;

public:
    User();
    explicit User(Type *Ty, const char *UserName);
    virtual ~User();

public:
    // OperandList
    // Returns the list of operands for this instruction.
    std::vector<Value *> &getOperandList();
    const std::vector<Value *> &getOperandList() const;

public:
    // Iterator
    using op_iterator = std::vector<Value *>::iterator;
    using const_op_iterator = std::vector<Value *>::const_iterator;
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

public:
    // Virtual
    // Replaces all references to the "From" definition with references to the "To"
    virtual void replaceUsesOfWith(Value *From, Value *To) override;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) override;

public:
    // Get/Set
    // Get the operand at the specified index.
    Value *getOperand(uint32_t Index) const;

    // Set the operand at the specified index.
    void setOperand(uint32_t Index, Value *Val);

    // Set the operand at the specified index and update the user list.
    void setOperandAndUpdateUsers(uint32_t Index, Value *Val);

public:
    // Insert
    // Insert the specified value.
    void insertOperand(Value *Val);

    // Insert the specified value and update the user list.
    void insertOperandAndUpdateUsers(Value *Val);
};

} // namespace uir