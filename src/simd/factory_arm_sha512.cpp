#include "factory_impl.hpp"

#ifdef CRYPTOWORDS_HAVE_ARM_SHA512
CRYPTOWORDS_DEFINE_SIMD_FACTORY(arm_sha512, SimdArch::ARM_SHA512)
#endif
