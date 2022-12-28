#pragma once
#include <UnknownIR/Constant.h>

namespace uir {

class Context;
class Function;

class Argument : public Constant
{
    friend class Function;

private:
    Function *mParent;
    uint32_t mArgNo;

public:
    explicit Argument(Type *Ty, const unknown::StringRef &ArgName = "", Function *F = nullptr, uint32_t ArgNo = 0);
    virtual ~Argument();

public:
    // Get/Set
    // Get the parent function of this argument
    const Function *getParent() const;
    Function *getParent();

    // Set the parent function of this argument
    void setParent(Function *F);

    // Get the argument number of this argument
    const uint32_t getArgNo() const;

    // Set the argument number of this argument
    void setArgNo(uint32_t ArgNo);

public:
    // Remove/Erase
    // Remove this argument from its parent, but does not delete it.
    void removeFromParent();

    // Remove this argument from its parent and delete it.
    void eraseFromParent();

public:
    // Static
    static Argument *get(Type *Ty, const unknown::StringRef &ArgName = "", Function *F = nullptr, uint32_t ArgNo = 0);
};

} // namespace uir
