#pragma once
#include <UnknownIR/Constant.h>

namespace uir {

class Context;
class Function;

class FunctionContext : public Constant
{
    friend class Function;

private:
    Function *mParent;
    uint32_t mCtxNo;

public:
    explicit FunctionContext(
        Type *Ty,
        const unknown::StringRef &CtxName = "",
        Function *F = nullptr,
        uint32_t CtxNo = 0);
    virtual ~FunctionContext();

public:
    // Get/Set
    // Get the parent function of this argument
    const Function *getParent() const;
    Function *getParent();

    // Set the parent function of this argument
    void setParent(Function *F);

    // Get the context number of this argument
    const uint32_t getCtxNo() const;

    // Set the context number of this argument
    void setCtxNo(uint32_t CtxNo);

public:
    // Remove/Erase
    // Remove this context from its parent, but does not delete it.
    void removeFromParent();

    // Remove this context from its parent and delete it.
    void eraseFromParent();

public:
    // Static
    static FunctionContext *
    get(Type *Ty, const unknown::StringRef &CtxName = "", Function *F = nullptr, uint32_t CtxNo = 0);
};

} // namespace uir
