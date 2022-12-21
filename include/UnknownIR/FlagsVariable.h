#pragma once
#include <UnknownIR/LocalVariable.h>

namespace uir {

class FlagsVariable : public LocalVariable
{
public:
    union Flags
    {
        uint32_t FlagValue;

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
    const Flags getFlags() const;

    void setFlags(Flags Flag);

    void setCarryFlag(bool Set = true);
    void setParityFlag(bool Set = true);
    void setAuxParityFlag(bool Set = true);
    void setZeroFlag(bool Set = true);
    void setSignFlag(bool Set = true);
    void setDirectionFlag(bool Set = true);
    void setOverflowFlag(bool Set = true);
};

} // namespace uir
