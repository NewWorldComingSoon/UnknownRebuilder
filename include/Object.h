#pragma once
#include <string>

namespace uir {

class Value;

// This is base class
class Object
{
public:
    Object();
    virtual ~Object();

public:
    // Name
    // Get the name of this object
    virtual std::string getName() const = 0;
    // Get the readable name of this object
    virtual std::string getReadableName() const = 0;

public:
    // Replace
    // Replaces all references to the "From" definition with references to the "To"
    virtual void replaceUsesOfWith(Value *From, Value *To) = 0;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) = 0;
};

} // namespace uir
