#pragma once
#include <cstdint>
#include <vector>

#include <UnknownUtils/unknown/ADT/StringRef.h>

namespace uir {

enum class OpCodeID : uint8_t
{
    // Data/Memory instructions
    Load,
    Store,
    Lea,

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
    JmpAddr,
    JmpBB,
    JccAddr,
    JccBB,

    // Unknown
    Unknown
};

struct OpCodeComponent
{
    OpCodeID mOpCodeID;
    unknown::StringRef mOpCodeName;
    uint32_t mNumberOfOperands;
    bool mHasResult;
    bool mHasFlags;
};

// clang-format off
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Data/Memory instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// res = load op1
const OpCodeComponent LoadComponent       = {    OpCodeID::Load,        "uir.load",         1,      true,      false};

// store op1, op2
const OpCodeComponent StoreComponent      = {    OpCodeID::Store,       "uir.store",        2,      false,     false};

// res = lea op1, offset
const OpCodeComponent LeaComponent        = {    OpCodeID::Lea,         "uir.lea",          2,      true,      false};


// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Binary operators instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// res = op1 + op2
const OpCodeComponent AddComponent        = {    OpCodeID::Add,         "uir.add",          2,      true,       true};

// res = op1 - op2
const OpCodeComponent SubComponent        = {    OpCodeID::Sub,         "uir.sub",          2,      true,       true};


// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Bitwise instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// res = op1 ^ op2
const OpCodeComponent XorComponent        = {    OpCodeID::Xor,         "uir.xor",          2,      true,       true};

// res = op1 | op2
const OpCodeComponent OrComponent         = {    OpCodeID::Or,          "uir.or",           2,      true,       true};

// res = op1 & op2
const OpCodeComponent AndComponent        = {    OpCodeID::And,         "uir.and",          2,      true,       true};

// res = ~op1
const OpCodeComponent NotComponent        = {    OpCodeID::Not,         "uir.not",          1,      true,       false};


// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Terminator instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Ret
const OpCodeComponent RetComponent        = {    OpCodeID::Ret,         "uir.ret",          0,      false,      false};

// Ret imm
const OpCodeComponent RetIMMComponent     = {    OpCodeID::RetIMM,      "uir.ret.imm",      1,      false,      false};

// JmpAddr address
const OpCodeComponent JmpAddrComponent    = {    OpCodeID::JmpAddr,     "uir.jmp.addr",     1,      false,      false};

// JmpBB targetBB
const OpCodeComponent JmpBBComponent      = {    OpCodeID::JmpBB,       "uir.jmp.bb",       1,      false,      false};

// JccAddr targetAddr, normalAddr
const OpCodeComponent JccAddrComponent    = {    OpCodeID::JccAddr,     "uir.jcc.addr",     2,      false,      true};

// JccBB targetBB, normalBB
const OpCodeComponent JccBBComponent      = {    OpCodeID::JccBB,       "uir.jcc.bb",       2,      false,      true};


// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Unknown
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const OpCodeComponent UnknownComponent    = {    OpCodeID::Unknown,     "uir.unknown",      0,      false,      false};
// clang-format on

} // namespace uir
