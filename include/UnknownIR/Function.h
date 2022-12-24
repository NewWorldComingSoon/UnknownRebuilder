#pragma once
#include <UnknownIR/Constant.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>

namespace uir {

class Function : public Constant
{
private:
    std::string mFunctionName;
    uint64_t mFunctionAddressBegin;
    uint64_t mFunctionAddressEnd;

public:
    explicit Function(
        Context &C,
        unknown::StringRef FunctionName,
        uint64_t FunctionAddressBegin = 0,
        uint64_t FunctionAddressEnd = 0);
    virtual ~Function();

public:
    // Get/Set
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

    // Get the begin/end address of this function
    uint64_t getFunctionBeginAddress() const;
    uint64_t getFunctionEndAddress() const;

    // Set the begin/end address of this function
    void setFunctionBeginAddress(uint64_t FunctionBeginAddress);
    void setFunctionEndAddress(uint64_t FunctionEndAddress);

public:
    // Static
    // Generate a new function name by order
    static std::string generateOrderedFunctionName(Context &C);

public:
    // Print
    // Print the function
    void print(unknown::raw_ostream &OS) const;
};

} // namespace uir
