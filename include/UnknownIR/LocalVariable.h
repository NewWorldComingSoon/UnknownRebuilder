#pragma once
#include <UnknownIR/Constant.h>

namespace uir {

class Context;

class LocalVariable : public Constant
{
private:
    uint64_t mLocalVariableAddress;

public:
    explicit LocalVariable(Type *Ty);
    explicit LocalVariable(Type *Ty, unknown::StringRef LocalVariableName, uint64_t LocalVariableAddress);
    virtual ~LocalVariable();

public:
    // Get/Set
    // Get the address of this local variable
    uint64_t getLocalVariableAddress() const;

    // Set the address of this local variable
    void setLocalVariableAddress(uint64_t LocalVariableAddress);

public:
    // Static
    // Generate a new value name by order
    static std::string generateOrderedLocalVarName(Context &C);

    // New a LocalVariable
    static LocalVariable *get(Type *Ty, unknown::StringRef LocalVariableName, uint64_t LocalVariableAddress);
    static LocalVariable *get(Type *Ty);
};

} // namespace uir
