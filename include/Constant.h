#pragma once
#include "Value.h"

namespace uir {

class Constant : public Value
{
public:
    explicit Constant(Type *Ty, const std::string ConstantName);
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
    explicit ConstantInt(Type *Ty, uint64_t Val);
    virtual ~ConstantInt();

public:
    // Replace
    // Replaces all references to the "From" definition with references to the "To"
    virtual void replaceUsesOfWith(Value *From, Value *To) override;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) override;

public:
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

    // Get/Set the value of ConstantInt
    uint64_t getValue() const;
    uint64_t getZExtValue() const;
    int64_t getSExtValue() const;
    void setValue(uint64_t Val);
    uint64_t setValue(Type *Ty, uint64_t Val, bool RetNewVal);

    // Return the bitwidth of this constant.
    uint32_t getBitWidth() const;
};

} // namespace uir
