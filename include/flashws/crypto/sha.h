#pragma once

#include <openssl/sha.h>
#include "flashws/base/basic_macros.h"

namespace fws {



    FWS_ALWAYS_INLINE void* Sha1(const void* FWS_RESTRICT src, size_t src_len,
                                 void* FWS_RESTRICT dst) {
        return SHA1((const unsigned char*)src, src_len, (unsigned char*)dst);
    }

} // namespace fws