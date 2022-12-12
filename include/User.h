#pragma once
#include "Value.h"

#include <vector>
#include <stdint.h>

namespace uir {

class User : public Value
{
private:
    std::vector<Value *> mOperandList;

public:
    User();
    virtual ~User();

public:
    // OperandList
    // Returns the list of operands for this instruction.
    std::vector<Value *> &getOperandList();
    const std::vector<Value *> &getOperandList() const;

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