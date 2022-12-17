#pragma once
#include <UnknownIR/Value.h>

#include <vector>
#include <cstdint>

namespace uir {

class User : public Value
{
private:
    std::vector<Value *> mOperandList;

public:
    User();
    explicit User(Type *Ty, const std::string UserName);
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
    // Replace
    // Replaces all references to the "From" definition with references to the "To"
    virtual void replaceUsesOfWith(Value *From, Value *To) override;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) override;

public:
    // Get/Set
    // Get/Set the operand at the specified index.
    Value *getOperand(uint32_t Index) const;
    void setOperand(uint32_t Index, Value *Val);
};

} // namespace uir