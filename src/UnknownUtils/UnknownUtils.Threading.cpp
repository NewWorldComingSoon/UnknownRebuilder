//===-- llvm/Support/Threading.cpp- Control multithreading mode --*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines helper functions for running LLVM in a multi-threaded
// environment.
//
//===----------------------------------------------------------------------===//

#include "unknown/Support/Threading.h"
#include "unknown/Config/config.h"
#include "unknown/Support/Host.h"

#include <cassert>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

using namespace unknown;

//===----------------------------------------------------------------------===//
//=== WARNING: Implementation here must contain only TRULY operating system
//===          independent code.
//===----------------------------------------------------------------------===//

bool unknown::llvm_is_multithreaded() {
#if LLVM_ENABLE_THREADS != 0
  return true;
#else
  return false;
#endif
}

#if LLVM_ENABLE_THREADS == 0 ||                                                \
    (!defined(_WIN32) && !defined(HAVE_PTHREAD_H))
// Support for non-Win32, non-pthread implementation.
void unknown::llvm_execute_on_thread(void (*Fn)(void *), void *UserData,
                                  unsigned RequestedStackSize) {
  (void)RequestedStackSize;
  Fn(UserData);
}

unsigned unknown::heavyweight_hardware_concurrency() { return 1; }

unsigned unknown::hardware_concurrency() { return 1; }

uint64_t unknown::get_threadid() { return 0; }

uint32_t unknown::get_max_thread_name_length() { return 0; }

void unknown::set_thread_name(const Twine &Name) {}

void unknown::get_thread_name(SmallVectorImpl<char> &Name) { Name.clear(); }

#else

#include <thread>
unsigned unknown::heavyweight_hardware_concurrency() {
  // Since we can't get here unless LLVM_ENABLE_THREADS == 1, it is safe to use
  // `std::thread` directly instead of `unknown::thread` (and indeed, doing so
  // allows us to not define `thread` in the llvm namespace, which conflicts
  // with some platforms such as FreeBSD whose headers also define a struct
  // called `thread` in the global namespace which can cause ambiguity due to
  // ADL.
  int NumPhysical = sys::getHostNumPhysicalCores();
  if (NumPhysical == -1)
    return std::thread::hardware_concurrency();
  return NumPhysical;
}

unsigned unknown::hardware_concurrency() {
#if defined(HAVE_SCHED_GETAFFINITY) && defined(HAVE_CPU_COUNT)
  cpu_set_t Set;
  if (sched_getaffinity(0, sizeof(Set), &Set))
    return CPU_COUNT(&Set);
#endif
  // Guard against std::thread::hardware_concurrency() returning 0.
  if (unsigned Val = std::thread::hardware_concurrency())
    return Val;
  return 1;
}

// Include the platform-specific parts of this class.
#ifdef LLVM_ON_UNIX
#include "Unix/Threading.inc"
#endif
#ifdef _WIN32
#include "Windows/Threading.inc"
#endif

#endif
