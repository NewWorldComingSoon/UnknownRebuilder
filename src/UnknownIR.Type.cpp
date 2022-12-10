#include <Type.h>
#include <Context.h>

#include "ContextImpl.h"

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
// Static
Type *
Type::getVoidTy(Context &C)
{
    return &C.mImpl->mVoidTy;
}

Type *
Type::getFloatTy(Context &C)
{
    return &C.mImpl->mFloatTy;
}

Type *
Type::getDoubleTy(Context &C)
{
    return &C.mImpl->mDoubleTy;
}

Type *
Type::getLabelTy(Context &C)
{
    return &C.mImpl->mLabelTy;
}

Type *
Type::getFunctionTy(Context &C)
{
    return &C.mImpl->mFunctionTy;
}

IntegerType *
Type::getInt1Ty(Context &C)
{
    return &C.mImpl->mInt1Ty;
}

IntegerType *
Type::getInt8Ty(Context &C)
{
    return &C.mImpl->mInt8Ty;
}

IntegerType *
Type::getInt16Ty(Context &C)
{
    return &C.mImpl->mInt16Ty;
}

IntegerType *
Type::getInt32Ty(Context &C)
{
    return &C.mImpl->mInt32Ty;
}

IntegerType *
Type::getInt64Ty(Context &C)
{
    return &C.mImpl->mInt64Ty;
}

IntegerType *
Type::getInt128Ty(Context &C)
{
    return &C.mImpl->mInt128Ty;
}

PointerType *
Type::getInt1PtrTy(Context &C, uint32_t ElementTypeSizeInBits)
{
    return getInt1Ty(C)->getPointerTo(ElementTypeSizeInBits);
}

PointerType *
Type::getInt8PtrTy(Context &C, uint32_t ElementTypeSizeInBits)
{
    return getInt8Ty(C)->getPointerTo(ElementTypeSizeInBits);
}

PointerType *
Type::getInt16PtrTy(Context &C, uint32_t ElementTypeSizeInBits)
{
    return getInt16Ty(C)->getPointerTo(ElementTypeSizeInBits);
}

PointerType *
Type::getInt32PtrTy(Context &C, uint32_t ElementTypeSizeInBits)
{
    return getInt32Ty(C)->getPointerTo(ElementTypeSizeInBits);
}

PointerType *
Type::getInt64PtrTy(Context &C, uint32_t ElementTypeSizeInBits)
{
    return getInt64Ty(C)->getPointerTo(ElementTypeSizeInBits);
}

////////////////////////////////////////////////////////////
// Pointer
// Return a pointer to the current type.  This is equivalent
PointerType *
Type::getPointerTo(uint32_t ElementTypeSizeInBits)
{
    return PointerType::get(mContext, this, ElementTypeSizeInBits);
}

////////////////////////////////////////////////////////////
//     IntegerType
//

IntegerType::IntegerType(Context &C, const std::string TypeName, uint32_t TypeSizeInBits) :
    Type(C, TypeName, Type::IntegerTyID, TypeSizeInBits)
{
}

IntegerType::~IntegerType() {}

////////////////////////////////////////////////////////////
//     PointerType
//

PointerType::PointerType(Context &C, Type *ElementType, const std::string TypeName, uint32_t ElementTypeSizeInBits) :
    Type(C, TypeName, Type::PointerTyID, ElementTypeSizeInBits)
{
    mElementType = ElementType;
}

PointerType::~PointerType() {}

Type *
PointerType::getElementType() const
{
    return mElementType;
}

////////////////////////////////////////////////////////////
// Static
PointerType *
PointerType::get(Context &C, Type *ElementType, uint32_t ElementTypeSizeInBits)
{
    return C.mImpl->getPointerType(ElementType, ElementTypeSizeInBits);
}

} // namespace uir