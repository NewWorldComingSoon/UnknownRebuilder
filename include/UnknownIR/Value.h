#pragma once
#include <UnknownIR/Object.h>
#include <UnknownIR/Type.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>
#include <UnknownUtils/unknown/ADT/StringRef.h>

namespace uir {

class Context;
class User;

class Value : public Object
{
public:
    using UsersListType = std::unordered_set<User *>;
    using ExtraInfoListType = std::vector<std::string>;

protected:
    Type *mType;
    std::string mValueName;

protected:
    UsersListType mUsers;

protected:
    ExtraInfoListType mExtraInfoList;
    std::string mComment;

public:
    Value();
    explicit Value(Type *Ty, const unknown::StringRef &ValueName);
    virtual ~Value();

public:
    // Context
    Context &getContext() const;

public:
    // User
    const UsersListType &getUsers() const;
    UsersListType &getUsers();

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

    // Get the extra info of this object
    const ExtraInfoListType &getExtraInfoList() const;

    // Set the extra info of this object
    void setExtraInfoList(const ExtraInfoListType &ExtraInfo);

    // Get the comment of this object
    const std::string getComment() const;

    // Set the comment of this object
    void setComment(const unknown::StringRef &Comment);

public:
    // Add/Remove
    // Add extra info to this object
    void addExtraInfo(const unknown::StringRef &ExtraInfo);

    // Remove extra info from this object
    void removeExtraInfo(const unknown::StringRef &ExtraInfo);

    // Add the comment of this object
    void addComment(const unknown::StringRef &Comment);

public:
    // Iterator
    using user_iterator = UsersListType::iterator;
    using const_user_iterator = UsersListType::const_iterator;
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
    // Virtual functions
    // Get the name of the value
    virtual std::string getName() const override;

    // Get the readable name of the value
    virtual std::string getReadableName() const override;

    // Get the property 'name' of the value
    virtual unknown::StringRef getPropertyName() const;

    // Get the property 'addr' of the value
    virtual unknown::StringRef getPropertyAddr() const;

    // Get the property 'range' of the value
    virtual unknown::StringRef getPropertyRange() const;

    // Get the property 'extra' of the value
    virtual unknown::StringRef getPropertyExtra() const;

    // Get the property 'comment' of the value
    virtual unknown::StringRef getPropertyComment() const;

    // Print the object name
    virtual void print(unknown::raw_ostream &OS, bool NewLine = true) const override;

    // Print the extra info of this object
    virtual void printExtraInfo(unknown::raw_ostream &OS) const;

    // Print the comment info of this object
    virtual void printCommentInfo(unknown::raw_ostream &OS) const;

    // Replaces all references to the "From" definition with references to the "To"
    virtual void replaceUsesOfWith(Value *From, Value *To) = 0;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) = 0;
};

} // namespace uir