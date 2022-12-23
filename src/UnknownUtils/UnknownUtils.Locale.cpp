#include "unknown/Support/Locale.h"
#include "unknown/ADT/StringRef.h"
#include "unknown/Support/Unicode.h"

namespace unknown {
namespace sys {
namespace locale {

int columnWidth(StringRef Text) {
  return unknown::sys::unicode::columnWidthUTF8(Text);
}

bool isPrint(int UCS) {
  return unknown::sys::unicode::isPrintable(UCS);
}

} // namespace locale
} // namespace sys
} // namespace llvm
