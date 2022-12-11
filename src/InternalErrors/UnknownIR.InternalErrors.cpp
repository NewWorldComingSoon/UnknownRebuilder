#include "InternalErrors.h"
#include <iostream>

namespace uir {

void
uir_unreachable_internal(const char *msg = nullptr, const char *file = nullptr, unsigned line = 0)
{
    std::cerr << "[UIR]: ";
    if (msg)
    {
        std::cerr << msg << "\n";
    }

    std::cerr << "UNREACHABLE executed";
    if (file)
    {
        std::cerr << " at " << file << ":" << line;
    }

    std::cerr << "!\n";
    std::abort();
}

} // namespace uir
