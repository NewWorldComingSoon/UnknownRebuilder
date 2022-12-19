//===--- Watchdog.h - Watchdog timer ----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file declares the unknown::sys::Watchdog class.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "unknown/Support/Compiler.h"

namespace unknown {
namespace sys {

/// This class provides an abstraction for a timeout around an operation
/// that must complete in a given amount of time. Failure to complete before
/// the timeout is an unrecoverable situation and no mechanisms to attempt
/// to handle it are provided.
class Watchdog
{
public:
    Watchdog(unsigned int seconds);
    ~Watchdog();

private:
    // Noncopyable.
    Watchdog(const Watchdog &other) = delete;
    Watchdog &operator=(const Watchdog &other) = delete;
};
} // namespace sys
} // namespace unknown

#endif
