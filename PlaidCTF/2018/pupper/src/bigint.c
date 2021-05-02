/* This file is the interface to constant-time arithmetic for big integers,
 using the Constant Time ToolKit (CTTK) */

#include "cttk.h"
#include "mlton_types.h"
#define BIGINT_BITS (48 * 8) /* Large enough to fit flag + extra slop if wanted */

typedef cti_def(bigint_type, BIGINT_BITS);
Word32 BIGINT_NUM_BITS = BIGINT_BITS;
Int32 BIGINT_SIZE_IN_BYTES = sizeof(bigint_type);

/* Interface */
void bigint_init(Pointer bigint) {
  cti_init(bigint, BIGINT_BITS);
}

void bigint_set_word(Pointer dst, Word32 val) {
  cti_set_u32(dst, val);
}


/* Comparison */

#define DECLARE_COMPARISON(name, op)                      \
  Bool bigint_##name(const Pointer x, const Pointer y) {  \
    return cttk_bool_to_int(op(x, y));                    \
  }

DECLARE_COMPARISON(eq, cti_eq)
DECLARE_COMPARISON(lt, cti_lt)
DECLARE_COMPARISON(gt, cti_gt)
DECLARE_COMPARISON(le, cti_leq)
DECLARE_COMPARISON(ge, cti_geq)

/* Arithmetic */

#define DECLARE_ARITHMETIC(name, op)                                   \
  void bigint_##name(Pointer dst, const Pointer a, const Pointer b) {  \
    op(dst, a, b);                                                     \
  }

DECLARE_ARITHMETIC(add, cti_add)
DECLARE_ARITHMETIC(sub, cti_sub)
DECLARE_ARITHMETIC(mul, cti_mul)
DECLARE_ARITHMETIC(quot, cti_div)
DECLARE_ARITHMETIC(rem, cti_rem)

/* For converting to decimal */

void bigint_read_from_bytes(Pointer dst, const Pointer src, Word32 len) {
  cti_decbe_unsigned(dst, src, len);
}

void bigint_copy(Pointer dst, const Pointer src) {
  cti_copy(dst, src);
}

void bigint_neg(Pointer dst, const Pointer src) {
  cti_neg(dst, src);
}

Bool bigint_isnan(const Pointer x) {
  return cttk_bool_to_int(cti_isnan(x));
}

Bool bigint_eq0(const Pointer x) {
  return cttk_bool_to_int(cti_eq0(x));
}

Bool bigint_lt0(const Pointer x) {
  return cttk_bool_to_int(cti_lt0(x));
}

Word32 bigint_to_word(Pointer x) {
  return cti_to_u32(x);
}

void bigint_quotrem(Pointer quot, Pointer rem, const Pointer a, const Pointer b) {
  cti_divrem(quot, rem, a, b);
}
