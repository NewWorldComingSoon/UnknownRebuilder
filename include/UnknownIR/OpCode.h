#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace uir {

enum class OpCodeID : uint8_t
{
    // Binary operators instructions
    Add,
    Sub,

    // Bitwise instructions
    Xor,
    Or,
    And,
    Not,

    // Terminator instructions
    Ret,
    RetIMM,

    // Unknown
    Unknown
};

struct OpCodeComponent
{
    OpCodeID mOpCodeID;
    std::string mOpCodeName;
    uint32_t mNumberOfOperands;
    bool mHasEFlags;
};

// clang-format off
const std::vector<OpCodeComponent> GlobalOpCodeComponents = {
    // Binary operators instructions
        // op3 = op1 + op2
    {   OpCodeID::Add,         "uir.add",      3,      true    },
        // op3 = op1 - op2
    {   OpCodeID::Sub,         "uir.sub",      3,      true    },

    // Bitwise instructions
        // op3 = op1 ^ op2
    {   OpCodeID::Xor,         "uir.xor",      3,      true    },
        // op3 = op1 | op2
    {   OpCodeID::Or,          "uir.or",       3,      true    },
        // op3 = op1 & op2
    {   OpCodeID::And,         "uir.and",      3,      true    },
        // op2 = ~op1
    {   OpCodeID::Not,         "uir.not",      2,      false   },
	
    // Terminator instructions
        // ret
    {   OpCodeID::Ret,         "uir.ret",      0,      false   },
        // ret imm
    {   OpCodeID::RetIMM,      "uir.retimm",   1,      false   },

        // Unknown
    {   OpCodeID::Unknown,     "uir.unknown",  0,      false   },
};
// clang-format on

////////////////////////////////////////////////////////////////////
// Function
// Get OpCode component by ID
const OpCodeComponent &
getOpCodeComponent(OpCodeID ID);

// Get OpCode component by name
const OpCodeComponent &
getOpCodeComponent(const char *Name);

} // namespace uir
