#pragma once
#include <cstdint>
#include <string>

#include <UnknownUtils/unknown/ADT/StringRef.h>

namespace uir {

class Context;
class IntegerType;
class PointerType;

class Type
{
public:
    enum TypeID : uint32_t
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

protected:
    Context &mContext;

protected:
    std::string mTypeName;
    TypeID mTypeID;
    uint32_t mTypeSizeInBits;

public:
    explicit Type(Context &C, const unknown::StringRef &TypeName, TypeID TypeID, uint32_t TypeSizeInBits);
    virtual ~Type();

public:
    // Context
    Context &getContext() const { return mContext; }

public:
    // Get/Set the name of the type
    unknown::StringRef getTypeName() const;
    void setTypeName(const unknown::StringRef &TypeName);

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
    static IntegerType *getIntNTy(Context &C, uint32_t N);
    static PointerType *getInt1PtrTy(Context &C);
    static PointerType *getInt8PtrTy(Context &C);
    static PointerType *getInt16PtrTy(Context &C);
    static PointerType *getInt32PtrTy(Context &C);
    static PointerType *getInt64PtrTy(Context &C);
    static PointerType *getIntNPtrTy(Context &C, uint32_t N);

public:
    // Pointer
    // Return a pointer to the current type.  This is equivalent
    PointerType *getPointerTo();
};

class IntegerType : public Type
{
public:
    explicit IntegerType(Context &C, const char *TypeName, uint32_t TypeSizeInBits);
    virtual ~IntegerType();

public:
    // Static
    // Get or create an IntegerType instance.
    static IntegerType *get(Context &C, uint32_t NumBits);
};

class PointerType : public Type
{
private:
    Type *mElementType;

public:
    explicit PointerType(Context &C, Type *ElementType, const char *TypeName);
    virtual ~PointerType();

public:
    Type *getElementType() const;
    uint32_t getPointerBits() const;
    uint32_t getElementTypeBits() const;

public:
    // Static
    static PointerType *get(Context &C, Type *ElementType);
};

} // namespace uir
