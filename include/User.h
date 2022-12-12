#pragma once
#include "Value.h"

namespace uir {

class User : public Value
{
public:
    User();
    virtual ~User();

public:
    // Replace
    // Replaces all references to the "From" definition with references to the "To"
    virtual void replaceUsesOfWith(Value *From, Value *To) override;

    // Change all uses of this to point to a new Value.
    virtual void replaceAllUsesWith(Value *V) override;
};

} // namespace uir