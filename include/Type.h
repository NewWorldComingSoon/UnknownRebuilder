#pragma once
#include <stdint.h>
#include <string>

namespace uir {

class Context;
class IntegerType;
class PointerType;

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
    explicit Type(Context &C, const std::string TypeName, TypeID TypeID, uint32_t TypeSizeInBits);
    virtual ~Type();

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

public:
    // Static
    static Type *getVoidTy(Context &C);
    static Type *getFloatTy(Context &C);
    static Type *getDoubleTy(Context &C);
    static Type *getLabelTy(Context &C);
    static Type *getFunctionTy(Context &C);
    static IntegerType *getInt1Ty(Context &C);
    static IntegerType *getInt8Ty(Context &C);
    static IntegerType *getInt16Ty(Context &C);
    static IntegerType *getInt32Ty(Context &C);
    static IntegerType *getInt64Ty(Context &C);
    static IntegerType *getInt128Ty(Context &C);
};

class IntegerType : public Type
{
public:
    explicit IntegerType(Context &C, const std::string TypeName, uint32_t TypeSizeInBits);
    virtual ~IntegerType();
};

class PointerType : public Type
{
private:
    Type *mElementType;

public:
    explicit PointerType(Context &C, Type *ElementType, const std::string TypeName, uint32_t ElementTypeSizeInBits);
    virtual ~PointerType();

public:
    Type *getElementType() const;
};

} // namespace uir
