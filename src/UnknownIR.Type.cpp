#include <Type.h>

namespace uir {
////////////////////////////////////////////////////////////
//     Type
//

////////////////////////////////////////////////////////////
// Ctor/Dtor
Type::Type(Context &C, const std::string TypeName, TypeID TypeID, uint32_t TypeSizeInBits) :
    mContext(C), mTypeName(TypeName), mTypeID(TypeID), mTypeSizeInBits(TypeSizeInBits)
{
}

Type::~Type() {}

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

uint32_t
Type::getTypeSize() const
{
    return mTypeSizeInBits / 8;
}

void
Type::setTypeBits(uint32_t TypeSizeInBits)
{
    mTypeSizeInBits = TypeSizeInBits;
}

////////////////////////////////////////////////////////////
// IsXXXTy
// Return true if this is 'void'
bool
Type::isVoidTy() const
{
    return getTypeID() == VoidTyID;
}

// Return true if this is 'float'
bool
Type::isFloatTy() const
{
    return getTypeID() == FloatTyID;
}

// Return true if this is 'double'
bool
Type::isDoubleTy() const
{
    return getTypeID() == DoubleTyID;
}

// Return true if this is 'label'
bool
Type::isLabelTy() const
{
    return getTypeID() == LabelTyID;
}

// Return true if this is 'integer'
bool
Type::isIntegerTy() const
{
    return getTypeID() == IntegerTyID;
}

// Return true if this is 'function'
bool
Type::isFunctionTy() const
{
    return getTypeID() == FunctionTyID;
}

// Return true if this is 'array'
bool
Type::isArrayTy() const
{
    return getTypeID() == ArrayTyID;
}

// Return true if this is 'pointer'
bool
Type::isPointerTy() const
{
    return getTypeID() == PointerTyID;
}

////////////////////////////////////////////////////////////
//     IntegerType
//

IntegerType::IntegerType(Context &C, const std::string TypeName, uint32_t NumBits) :
    Type(C, TypeName, Type::IntegerTyID, NumBits)
{
}

IntegerType::~IntegerType() {}

} // namespace uir