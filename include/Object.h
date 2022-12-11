#pragma once

namespace uir {

class Value;

// This is base class
class Object
{
public:
    Object();
    virtual ~Object();

public:
    // Replace
    // Replaces all references to the "From" definition with references to the
    virtual void replaceUsesOfWith(Value *From, Value *To) = 0;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) = 0;
};

} // namespace uir
