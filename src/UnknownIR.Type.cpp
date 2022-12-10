#include "Type.h"

namespace uir {

////////////////////////////////////////////////////////////
// Get/Set

// Get/Set the name of the type
std::string
Type::getTypeName() const
{
    return mTypeName;
}

void
Type::setTypeName(const std::string TypeName)
{
    mTypeName = TypeName;
}

// Get/Set the id of the type
Type::TypeID
Type::getTypeID() const
{
    return mTypeID;
}

void
Type::setTypeID(TypeID TypeID)
{
    mTypeID = TypeID;
}

// Get/Set the bits of the type
uint32_t
Type::getTypeBits() const
{
    return mTypeSizeInBits;
}

void
Type::setTypeBits(uint32_t TypeSizeInBits)
{
    mTypeSizeInBits = TypeSizeInBits;
}

} // namespace uir