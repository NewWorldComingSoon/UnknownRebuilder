//===- llvm/Support/PrettyStackTrace.h - Pretty Crash Handling --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the PrettyStackTraceEntry class, which is used to make
// crashes give more contextual information about what the program was doing
// when it crashed.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "unknown/ADT/SmallVector.h"
#include "unknown/Support/Compiler.h"

namespace unknown {
class raw_ostream;

void
EnablePrettyStackTrace();

/// PrettyStackTraceEntry - This class is used to represent a frame of the
/// "pretty" stack trace that is dumped when a program crashes. You can define
/// subclasses of this and declare them on the program stack: when they are
/// constructed and destructed, they will add their symbolic frames to a
/// virtual stack trace.  This gets dumped out if the program crashes.
class PrettyStackTraceEntry
{
    friend PrettyStackTraceEntry *ReverseStackTrace(PrettyStackTraceEntry *);

    PrettyStackTraceEntry *NextEntry;
    PrettyStackTraceEntry(const PrettyStackTraceEntry &) = delete;
    void operator=(const PrettyStackTraceEntry &) = delete;

public:
    PrettyStackTraceEntry();
    virtual ~PrettyStackTraceEntry();

    /// print - Emit information about this stack frame to OS.
    virtual void print(raw_ostream &OS) const = 0;

    /// getNextEntry - Return the next entry in the list of frames.
    const PrettyStackTraceEntry *getNextEntry() const { return NextEntry; }
};

/// PrettyStackTraceString - This object prints a specified string (which
/// should not contain newlines) to the stream as the stack trace when a crash
/// occurs.
class PrettyStackTraceString : public PrettyStackTraceEntry
{
    const char *Str;

public:
    PrettyStackTraceString(const char *str) : Str(str) {}
    void print(raw_ostream &OS) const override;
};

/// PrettyStackTraceFormat - This object prints a string (which may use
/// printf-style formatting but should not contain newlines) to the stream
/// as the stack trace when a crash occurs.
class PrettyStackTraceFormat : public PrettyStackTraceEntry
{
    unknown::SmallVector<char, 32> Str;

public:
    PrettyStackTraceFormat(const char *Format, ...);
    void print(raw_ostream &OS) const override;
};

/// PrettyStackTraceProgram - This object prints a specified program arguments
/// to the stream as the stack trace when a crash occurs.
class PrettyStackTraceProgram : public PrettyStackTraceEntry
{
    int ArgC;
    const char *const *ArgV;

public:
    PrettyStackTraceProgram(int argc, const char *const *argv) : ArgC(argc), ArgV(argv) { EnablePrettyStackTrace(); }
    void print(raw_ostream &OS) const override;
};

/// Returns the topmost element of the "pretty" stack state.
const void *
SavePrettyStackState();

/// Restores the topmost element of the "pretty" stack state to State, which
/// should come from a previous call to SavePrettyStackState().  This is
/// useful when using a CrashRecoveryContext in code that also uses
/// PrettyStackTraceEntries, to make sure the stack that's printed if a crash
/// happens after a crash that's been recovered by CrashRecoveryContext
/// doesn't have frames on it that were added in code unwound by the
/// CrashRecoveryContext.
void
RestorePrettyStackState(const void *State);

} // namespace unknown

#endif
