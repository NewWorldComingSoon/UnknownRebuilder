#pragma once
#include <UnknownIR/Constant.h>

namespace uir {

class Module;

class GlobalVariable : public Constant
{
protected:
    Module *mParent;
    uint64_t mGlobalVariableAddress;

public:
    explicit GlobalVariable(Type *Ty);
    explicit GlobalVariable(
        Type *Ty,
        const unknown::StringRef &GlobalVariableName,
        uint64_t GlobalVariableAddress,
        Module *Parent = nullptr);
    virtual ~GlobalVariable();

public:
    // Get/Set
    // Get the address of this global variable
    uint64_t getGlobalVariableAddress() const;

    // Set the address of this global variable
    void setGlobalVariableAddress(uint64_t GlobalVariableAddress);

    // Get parent module
    const Module *getParent() const;

    // Set parent module
    void setParent(Module *Parent);

public:
    // Remove/Erase
    // Remove this global variable from its parent module
    void removeFromParent();

    // Erase this global variable from its parent module
    void eraseFromParent();

public:
    // Virtual functions
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

    // Get the property 'gv' of the value
    virtual unknown::StringRef getPropertyGV() const;

    // Print the gv
    virtual void print(unknown::raw_ostream &OS, bool NewLine = true) const override;

    // Print the gv
    virtual void print(unknown::XMLPrinter &Printer) const;

public:
    // Static
    // Generate a new value name by order
    static std::string generateOrderedGlobalVarName(Context &C);

    // Allocate a GlobalVariable
    static GlobalVariable *get(Type *Ty, const unknown::StringRef &GlobalVariableName, uint64_t GlobalVariableAddress);
    static GlobalVariable *get(Type *Ty);
};

template <typename T = uint8_t>
requires std::is_integral_v<T> || std::is_pointer_v<T>
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
        const GlobalArrayType &GlobalArrayElements,
        const unknown::StringRef &GlobalArrayName = generateOrderedGlobalVarName(C),
        uint64_t GlobalArrayAddress = 0) :
        GlobalVariable(PointerType::get(C, ElmtTy), GlobalArrayName, GlobalArrayAddress), mElements(GlobalArrayElements)
    {
        if (ElmtTy->getTypeSize() != sizeof(T))
        {
            std::printf(
                std::format("ElmtTy->getTypeSize()[{}] != sizeof(T)[{}]\n", ElmtTy->getTypeSize(), sizeof(T)).c_str());
            std::abort();
        }
    }

    virtual ~GlobalArray() = default;

public:
    // Get/Set
    GlobalArrayType &getGlobalArray() { return mElements; }
    const GlobalArrayType &getGlobalArray() const { return mElements; }
    void setGlobalArray(const GlobalArrayType &GlobalArrayElements) { mElements = GlobalArrayElements; }

public:
    // Static
    static GlobalArray *
    get(Context &C,
        Type *ElmtTy,
        const GlobalArrayType &GlobalArrayElements,
        const unknown::StringRef &GlobalArrayName,
        uint64_t GlobalArrayAddress)
    {
        return new GlobalArray(C, ElmtTy, GlobalArrayElements, GlobalArrayName, GlobalArrayAddress);
    }

    static GlobalArray *get(Context &C, Type *ElmtTy, const GlobalArrayType &GlobalArrayElements)
    {
        return get(C, ElmtTy, GlobalArrayElements, generateOrderedGlobalVarName(C), 0);
    }
};

} // namespace uir
