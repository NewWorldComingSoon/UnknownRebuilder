#pragma once
#include <UnknownIR/Constant.h>

namespace uir {

class GlobalVariable : public Constant
{
protected:
    uint64_t mGlobalVariableAddress;

public:
    explicit GlobalVariable(Type *Ty);
    explicit GlobalVariable(Type *Ty, unknown::StringRef GlobalVariableName, uint64_t GlobalVariableAddress);
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

    // Allocate a GlobalVariable
    static GlobalVariable *get(Type *Ty, unknown::StringRef GlobalVariableName, uint64_t GlobalVariableAddress);
    static GlobalVariable *get(Type *Ty);
};

template <typename T>
class GlobalArray : public GlobalVariable
{
public:
    using GlobalArrayType = std::vector<T>;

private:
    GlobalArrayType mElements;

public:
    GlobalArray(
        Context &C,
        Type *ElmtTy,
        unknown::StringRef GlobalArrayName,
        const GlobalArrayType &GlobalArrayElements,
        uint64_t GlobalArrayAddress = 0) :
        GlobalVariable(PointerType::get(C, ElmtTy), GlobalArrayName, GlobalArrayAddress), mElements(GlobalArrayElements)
    {
    }
    virtual ~GlobalArray() {}

public:
    // Get/Set
    GlobalArrayType &getGlobalArray() { return mElements; }
    const GlobalArrayType &getGlobalArray() const { return mElements; }
    void setGlobalArray(const GlobalArrayType &GlobalArrayElements) { mElements = GlobalArrayElements; }
};

} // namespace uir
