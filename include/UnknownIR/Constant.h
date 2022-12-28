#pragma once
#include <UnknownIR/User.h>

#include <UnknownUtils/unknown/ADT/APInt.h>

namespace uir {
class Context;

class Constant : public User
{
public:
    explicit Constant(Type *Ty, const unknown::StringRef &ConstantName);
    virtual ~Constant();

public:
    // Static
    // Get a Constant object
    static Constant *get(Type *Ty, const unknown::StringRef &ConstantName);
};

class ConstantInt : public Constant
{
private:
    unknown::APInt mVal;

public:
    explicit ConstantInt(Type *Ty, const unknown::APInt &Val);
    virtual ~ConstantInt();

public:
    // Get/Set the value of ConstantInt
    const unknown::APInt &getValue() const;
    uint64_t getZExtValue() const;
    int64_t getSExtValue() const;

    void setValue(const unknown::APInt &Val);

    // Return the bitwidth of this constant.
    uint32_t getBitWidth() const;

public:
    // Virtual functions
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

public:
    // Static
    // Get a ConstantInt from a value
    static ConstantInt *get(Context &Context, const unknown::APInt &Val);

    // Get a ConstantInt from a value
    static ConstantInt *get(IntegerType *Ty, const unknown::APInt &Val);
};

} // namespace uir
