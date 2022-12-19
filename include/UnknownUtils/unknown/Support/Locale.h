#pragma once

namespace unknown {
class StringRef;

namespace sys {
namespace locale {

int
columnWidth(StringRef s);
bool
isPrint(int c);

} // namespace locale
} // namespace sys
} // namespace unknown
