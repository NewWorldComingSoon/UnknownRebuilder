#pragma once
#include <string>

namespace uir {

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
};

} // namespace uir
