#pragma once
#include <UnknownIR/Constant.h>

namespace uir {

class GlobalVariable : public Constant
{
protected:
    uint64_t mGlobalVariableAddress;

public:
    explicit GlobalVariable(Type *Ty, const char *GlobalVariableName, uint64_t GlobalVariableAddress);
    virtual ~GlobalVariable();

public:
    // Get/Set
    // Get the address of this global variable
    uint64_t getGlobalVariableAddress() const;

    // Set the address of this global variable
    void setGlobalVariableAddress(uint64_t GlobalVariableAddress);

public:
    // Virtual functions
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

public:
    // Static
    // Generate a new value name by order
    static std::string generateOrderedGlobalVarName(Context &C);
};

} // namespace uir
