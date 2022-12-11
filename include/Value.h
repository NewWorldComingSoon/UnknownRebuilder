#pragma once
#include "Object.h"
#include "Type.h"

#include <stdint.h>
#include <unordered_set>

namespace uir {

class Context;
class User;

class Value : public Object
{
private:
    Type *mType;
    std::string mValueName;

private:
    std::unordered_set<User *> mUsers;

public:
    Value();
    Value(Type *Ty, const std::string ValueName);
    virtual ~Value();

public:
    // Context
    Context &getContext() const;

public:
    // Get/Set the name of the value
    std::string getName() const;
    bool hasName() const;
    void setName(const std::string ValueName);

    // Get/Set the type of the value
    Type *getType() const;
    void setType(Type *Ty);

public:
    // Replace
    // Replaces all references to the "From" definition with references to the
    virtual void replaceUsesOfWith(Value *From, Value *To) override;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) override;

public:
    // Friend
    friend class User;
};

} // namespace uir