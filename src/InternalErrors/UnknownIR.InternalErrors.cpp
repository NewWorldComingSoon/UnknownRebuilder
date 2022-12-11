#include "InternalErrors.h"
#include <iostream>

namespace uir {

void
uir_unreachable_internal(const char *msg /*= nullptr*/, const char *file /*= nullptr*/, unsigned line /*= 0*/)
{
    if (msg)
    {
        std::cerr << "[UIR]: " << msg << "\n";
        std::cerr << "UNREACHABLE executed";
        if (file)
        {
            std::cerr << " at " << file << ":" << line;
        }

        std::cerr << "!\n";
    }

    std::abort();
}

} // namespace uir
