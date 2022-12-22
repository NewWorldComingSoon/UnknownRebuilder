#pragma once

#include <cstdint>
#include <unordered_set>

#include <UnknownIR/Object.h>
#include <UnknownIR/Type.h>

namespace uir {

class Context;
class User;

class Value : public Object
{
protected:
    Type *mType;
    std::string mValueName;

protected:
    std::unordered_set<User *> mUsers;

public:
    Value();
    explicit Value(Type *Ty, const char *ValueName);
    virtual ~Value();

public:
    // Context
    Context &getContext() const;

public:
    // User
    const std::unordered_set<User *> &getUsers() const;
    std::unordered_set<User *> &getUsers();

public:
    // Get/Set the name of the value
    bool hasName() const;
    void setName(const char *ValueName);

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
    // Virtual
    // Get the name of the value
    virtual std::string getName() const override;

    // Get the readable name of the value
    virtual std::string getReadableName() const override;

    // Replaces all references to the "From" definition with references to the "To"
    virtual void replaceUsesOfWith(Value *From, Value *To) = 0;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) = 0;
};

} // namespace uir