#pragma once
#include "Value.h"

namespace uir {

class Constant : public Value
{
public:
    Constant(Type *Ty, const std::string ConstantName);
    virtual ~Constant();

public:
    // Replace
    // Replaces all references to the "From" definition with references to the "To"
    virtual void replaceUsesOfWith(Value *From, Value *To) override;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) override;
};

class ConstantInt : public Constant
{
private:
    uint64_t mVal;

public:
    ConstantInt(Type *Ty, uint64_t Val);
    virtual ~ConstantInt();

public:
    // Replace
    // Replaces all references to the "From" definition with references to the "To"
    virtual void replaceUsesOfWith(Value *From, Value *To) override;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) override;

public:
    // Get/Set the value of ConstantInt
    uint64_t getValue() const;
    void setValue(uint64_t Val);

    // Return the bitwidth of this constant.
    uint32_t getBitWidth() const;
};

} // namespace uir
