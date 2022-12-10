#pragma once
#include <stdint.h>
#include <string>

namespace uir {

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
    std::string mTypeName;
    TypeID mTypeID;
    uint32_t mTypeSizeInBits;

public:
    explicit Type(const std::string TypeName, TypeID TypeID, uint64_t TypeSizeInBits) :
        mTypeName(TypeName), mTypeID(TypeID), mTypeSizeInBits(TypeSizeInBits)
    {
    }
    virtual ~Type() {}

public:
    // Get/Set the name of the type
    std::string getTypeName() const;
    void setTypeName(const std::string TypeName);

    // Get/Set the id of the type
    TypeID getTypeID() const;
    void setTypeID(TypeID TypeID);

    // Get/Set the bits of the type
    uint32_t getTypeBits() const;
    void setTypeBits(uint32_t TypeSizeInBits);
};

} // namespace uir
