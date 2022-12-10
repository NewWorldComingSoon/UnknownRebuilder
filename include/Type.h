#pragma once
#include <stdint.h>
#include <string>

namespace uir {

class Context;

class Type
{
public:
    enum TypeID
    {
        VoidTyID,
        FloatTyID,
        DoubleTyID,
        LabelTyID,
        IntegerTyID,
        FunctionTyID,
        ArrayTyID,
        PointerTyID,
    };

private:
    Context &mContext;
    std::string mTypeName;
    TypeID mTypeID;
    uint32_t mTypeSizeInBits;

public:
    explicit Type(Context &C, const std::string TypeName, TypeID TypeID, uint32_t TypeSizeInBits) :
        mContext(C), mTypeName(TypeName), mTypeID(TypeID), mTypeSizeInBits(TypeSizeInBits)
    {
    }
    virtual ~Type() {}

public:
    // Context
    Context &getContext() const { return mContext; }

public:
    // Get/Set the name of the type
    std::string getTypeName() const;
    void setTypeName(const std::string TypeName);

    // Get/Set the id of the type
    TypeID getTypeID() const;
    void setTypeID(TypeID TypeID);

    // Get/Set the bits of the type
    uint32_t getTypeBits() const;
    uint32_t getTypeSize() const;
    void setTypeBits(uint32_t TypeSizeInBits);

public:
    // Return true if this is 'void'
    bool isVoidTy() const;

    // Return true if this is 'float'
    bool isFloatTy() const;

    // Return true if this is 'double'
    bool isDoubleTy() const;

    // Return true if this is 'label'
    bool isLabelTy() const;

    // Return true if this is 'integer'
    bool isIntegerTy() const;

    // Return true if this is 'function'
    bool isFunctionTy() const;

    // Return true if this is 'array'
    bool isArrayTy() const;

    // Return true if this is 'pointer'
    bool isPointerTy() const;
};

} // namespace uir
