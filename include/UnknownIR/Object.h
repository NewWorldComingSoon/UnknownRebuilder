#pragma once
#include <string>

#include <UnknownUtils/unknown/Support/raw_ostream.h>

namespace uir {

// This is base class
class Object
{
public:
    Object() = default;
    virtual ~Object() = default;

public:
    // Pure virtual functions
    // Get the name of this object
    virtual std::string getName() const = 0;

    // Get the readable name of this object
    virtual std::string getReadableName() const = 0;

    // Print the object name
    virtual void print(unknown::raw_ostream &OS) const = 0;
};

} // namespace uir
