#pragma once
#include "Object.h"
#include "Type.h"

#include <stdint.h>
#include <unordered_set>

namespace uir {

class Value : public Object
{
private:
    Type *mType;
    std::string mValueName;
    std::unordered_set<Value *> mUsers;

public:
    Value();
    Value(Type *Ty, const std::string ValueName);
    virtual ~Value();

public:
    // Get/Set the name of the value
    std::string getName() const;
    void setName(const std::string ValueName);

    // Get/Set the type of the value
    Type *getType() const;
    void setType(Type *Ty);

private:
};

} // namespace uir