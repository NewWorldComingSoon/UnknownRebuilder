//===-- StringPool.cpp - Interned string pool -----------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the StringPool class.
//
//===----------------------------------------------------------------------===//

#include "unknown/Support/StringPool.h"
#include "unknown/ADT/StringRef.h"

using namespace unknown;

StringPool::StringPool() {}

StringPool::~StringPool()
{
    assert(InternTable.empty() && "PooledStringPtr leaked!");
}

PooledStringPtr
StringPool::intern(StringRef Key)
{
    table_t::iterator I = InternTable.find(Key);
    if (I != InternTable.end())
        return PooledStringPtr(&*I);

    entry_t *S = entry_t::Create(Key);
    S->getValue().Pool = this;
    InternTable.insert(S);

    return PooledStringPtr(S);
}
