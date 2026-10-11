#include "factory_impl.hpp"

#ifdef CRYPTOWORDS_HAVE_ARM_NEON
CRYPTOWORDS_DEFINE_SIMD_FACTORY(arm_neon, SimdArch::ARM_NEON)
#endif
