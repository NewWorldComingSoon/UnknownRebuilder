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

    // Get the bits/size of the value
    uint32_t getValueBits() const;
    uint32_t getValueSize() const;

public:
    // Iterator
    using user_iterator = std::unordered_set<User *>::iterator;
    using const_user_iterator = std::unordered_set<User *>::const_iterator;
    user_iterator user_begin();
    const_user_iterator user_begin() const;
    user_iterator user_end();
    const_user_iterator user_end() const;
    bool user_empty() const;
    bool user_contains(User *U) const;
    size_t user_size() const;
    size_t user_count(User *U) const;
    void user_insert(User *U);
    void user_erase(User *U);
    void user_clear();

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