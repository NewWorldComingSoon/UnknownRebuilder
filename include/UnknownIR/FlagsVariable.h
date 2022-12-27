#pragma once
#include <UnknownIR/LocalVariable.h>

namespace uir {

class FlagsVariable : public LocalVariable
{
public:
    union Flags
    {
        uint64_t FlagsValue;

        struct
        {
            uint64_t CarryFlag : 1;     // CF
            uint64_t ParityFlag : 1;    // PF
            uint64_t AuxParityFlag : 1; // AF
            uint64_t ZeroFlag : 1;      // ZF
            uint64_t SignFlag : 1;      // SF
            uint64_t DirectionFlag : 1; // DF
            uint64_t OverflowFlag : 1;  // OF
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
    const uint64_t getFlagsValue() const;

    // Set the flags value
    void setFlags(Flags Flag);
    void setFlagsValue(uint64_t FlagsVal);

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

public:
    // Static
    static FlagsVariable *get(Type *Ty);
};

} // namespace uir
