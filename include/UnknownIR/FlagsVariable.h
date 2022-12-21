#pragma once
#include <UnknownIR/LocalVariable.h>

namespace uir {

class FlagsVariable : public LocalVariable
{
public:
    union Flags
    {
        uint32_t FlagsValue;

        struct
        {
            uint32_t CarryFlag : 1;     // CF
            uint32_t ParityFlag : 1;    // PF
            uint32_t AuxParityFlag : 1; // AF
            uint32_t ZeroFlag : 1;      // ZF
            uint32_t SignFlag : 1;      // SF
            uint32_t DirectionFlag : 1; // DF
            uint32_t OverflowFlag : 1;  // OF
        };
    };

private:
    Flags mFlags;

public:
    explicit FlagsVariable(Type *Ty);
    virtual ~FlagsVariable();

public:
    // Get/Set
    // Get the flags value
    const Flags getFlags() const;
    const uint32_t getFlagsValue() const;

    // Set the flags value
    void setFlags(Flags Flag);
    void setFlagsValue(uint32_t FlagsVal);

    // Set the CarryFlag
    void setCarryFlag(bool Set = true);

    // Set the ParityFlag
    void setParityFlag(bool Set = true);

    // Set the AuxParityFlag
    void setAuxParityFlag(bool Set = true);

    // Set the ZeroFlag
    void setZeroFlag(bool Set = true);

    // Set the SignFlag
    void setSignFlag(bool Set = true);

    // Set the DirectionFlag
    void setDirectionFlag(bool Set = true);

    // Set the OverflowFlag
    void setOverflowFlag(bool Set = true);
};

} // namespace uir
