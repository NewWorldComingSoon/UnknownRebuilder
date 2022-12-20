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
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Binary operators instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// op3 = op1 + op2
const OpCodeComponent AddComponent        = {    OpCodeID::Add,       "uir.add",      3,      true};

// op3 = op1 - op2
const OpCodeComponent SubComponent        = {    OpCodeID::Sub,       "uir.sub",      3,      true};


// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Bitwise instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// op3 = op1 ^ op2
const OpCodeComponent XorComponent        = {    OpCodeID::Xor,       "uir.xor",      3,      true};

// op3 = op1 | op2
const OpCodeComponent OrComponent         = {    OpCodeID::Or,        "uir.or",       3,      true};

// op3 = op1 & op2
const OpCodeComponent AndComponent        = {    OpCodeID::And,       "uir.and",      3,      true};

// op2 = ~op1
const OpCodeComponent NotComponent        = {    OpCodeID::Not,       "uir.not",      2,      false};


// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Terminator instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ret
const OpCodeComponent RetComponent        = {    OpCodeID::Ret,       "uir.ret",      0,      false};

// ret imm
const OpCodeComponent RetIMMComponent     = {    OpCodeID::RetIMM,    "uir.retimm",   1,      false};


// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Unknown
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const OpCodeComponent UnknownComponent    = {    OpCodeID::Unknown,   "uir.unknown",  0,      false};
// clang-format on

} // namespace uir
