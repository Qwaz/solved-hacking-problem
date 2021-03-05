#include <math.h>
#include <string.h>

#include "wasmpwn.h"
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)

#define TRAP(x) (wasm_rt_trap(WASM_RT_TRAP_##x), 0)

#define FUNC_PROLOGUE                                            \
  if (++wasm_rt_call_stack_depth > WASM_RT_MAX_CALL_STACK_DEPTH) \
    TRAP(EXHAUSTION)

#define FUNC_EPILOGUE --wasm_rt_call_stack_depth

#define UNREACHABLE TRAP(UNREACHABLE)

#define CALL_INDIRECT(table, t, ft, x, ...)          \
  (LIKELY((x) < table.size && table.data[x].func &&  \
          table.data[x].func_type == func_types[ft]) \
       ? ((t)table.data[x].func)(__VA_ARGS__)        \
       : TRAP(CALL_INDIRECT))

#define MEMCHECK(mem, a, t)  \
  if (UNLIKELY((a) + sizeof(t) > mem->size)) TRAP(OOB)

#define DEFINE_LOAD(name, t1, t2, t3)              \
  static inline t3 name(wasm_rt_memory_t* mem, u64 addr) {   \
    MEMCHECK(mem, addr, t1);                       \
    t1 result;                                     \
    memcpy(&result, &mem->data[addr], sizeof(t1)); \
    return (t3)(t2)result;                         \
  }

#define DEFINE_STORE(name, t1, t2)                           \
  static inline void name(wasm_rt_memory_t* mem, u64 addr, t2 value) { \
    MEMCHECK(mem, addr, t1);                                 \
    t1 wrapped = (t1)value;                                  \
    memcpy(&mem->data[addr], &wrapped, sizeof(t1));          \
  }

DEFINE_LOAD(i32_load, u32, u32, u32);
DEFINE_LOAD(i64_load, u64, u64, u64);
DEFINE_LOAD(f32_load, f32, f32, f32);
DEFINE_LOAD(f64_load, f64, f64, f64);
DEFINE_LOAD(i32_load8_s, s8, s32, u32);
DEFINE_LOAD(i64_load8_s, s8, s64, u64);
DEFINE_LOAD(i32_load8_u, u8, u32, u32);
DEFINE_LOAD(i64_load8_u, u8, u64, u64);
DEFINE_LOAD(i32_load16_s, s16, s32, u32);
DEFINE_LOAD(i64_load16_s, s16, s64, u64);
DEFINE_LOAD(i32_load16_u, u16, u32, u32);
DEFINE_LOAD(i64_load16_u, u16, u64, u64);
DEFINE_LOAD(i64_load32_s, s32, s64, u64);
DEFINE_LOAD(i64_load32_u, u32, u64, u64);
DEFINE_STORE(i32_store, u32, u32);
DEFINE_STORE(i64_store, u64, u64);
DEFINE_STORE(f32_store, f32, f32);
DEFINE_STORE(f64_store, f64, f64);
DEFINE_STORE(i32_store8, u8, u32);
DEFINE_STORE(i32_store16, u16, u32);
DEFINE_STORE(i64_store8, u8, u64);
DEFINE_STORE(i64_store16, u16, u64);
DEFINE_STORE(i64_store32, u32, u64);

#define I32_CLZ(x) ((x) ? __builtin_clz(x) : 32)
#define I64_CLZ(x) ((x) ? __builtin_clzll(x) : 64)
#define I32_CTZ(x) ((x) ? __builtin_ctz(x) : 32)
#define I64_CTZ(x) ((x) ? __builtin_ctzll(x) : 64)
#define I32_POPCNT(x) (__builtin_popcount(x))
#define I64_POPCNT(x) (__builtin_popcountll(x))

#define DIV_S(ut, min, x, y)                                 \
   ((UNLIKELY((y) == 0)) ?                TRAP(DIV_BY_ZERO)  \
  : (UNLIKELY((x) == min && (y) == -1)) ? TRAP(INT_OVERFLOW) \
  : (ut)((x) / (y)))

#define REM_S(ut, min, x, y)                                \
   ((UNLIKELY((y) == 0)) ?                TRAP(DIV_BY_ZERO) \
  : (UNLIKELY((x) == min && (y) == -1)) ? 0                 \
  : (ut)((x) % (y)))

#define I32_DIV_S(x, y) DIV_S(u32, INT32_MIN, (s32)x, (s32)y)
#define I64_DIV_S(x, y) DIV_S(u64, INT64_MIN, (s64)x, (s64)y)
#define I32_REM_S(x, y) REM_S(u32, INT32_MIN, (s32)x, (s32)y)
#define I64_REM_S(x, y) REM_S(u64, INT64_MIN, (s64)x, (s64)y)

#define DIVREM_U(op, x, y) \
  ((UNLIKELY((y) == 0)) ? TRAP(DIV_BY_ZERO) : ((x) op (y)))

#define DIV_U(x, y) DIVREM_U(/, x, y)
#define REM_U(x, y) DIVREM_U(%, x, y)

#define ROTL(x, y, mask) \
  (((x) << ((y) & (mask))) | ((x) >> (((mask) - (y) + 1) & (mask))))
#define ROTR(x, y, mask) \
  (((x) >> ((y) & (mask))) | ((x) << (((mask) - (y) + 1) & (mask))))

#define I32_ROTL(x, y) ROTL(x, y, 31)
#define I64_ROTL(x, y) ROTL(x, y, 63)
#define I32_ROTR(x, y) ROTR(x, y, 31)
#define I64_ROTR(x, y) ROTR(x, y, 63)

#define FMIN(x, y)                                          \
   ((UNLIKELY((x) != (x))) ? NAN                            \
  : (UNLIKELY((y) != (y))) ? NAN                            \
  : (UNLIKELY((x) == 0 && (y) == 0)) ? (signbit(x) ? x : y) \
  : (x < y) ? x : y)

#define FMAX(x, y)                                          \
   ((UNLIKELY((x) != (x))) ? NAN                            \
  : (UNLIKELY((y) != (y))) ? NAN                            \
  : (UNLIKELY((x) == 0 && (y) == 0)) ? (signbit(x) ? y : x) \
  : (x > y) ? x : y)

#define TRUNC_S(ut, st, ft, min, max, maxop, x)                             \
   ((UNLIKELY((x) != (x))) ? TRAP(INVALID_CONVERSION)                       \
  : (UNLIKELY((x) < (ft)(min) || (x) maxop (ft)(max))) ? TRAP(INT_OVERFLOW) \
  : (ut)(st)(x))

#define I32_TRUNC_S_F32(x) TRUNC_S(u32, s32, f32, INT32_MIN, INT32_MAX, >=, x)
#define I64_TRUNC_S_F32(x) TRUNC_S(u64, s64, f32, INT64_MIN, INT64_MAX, >=, x)
#define I32_TRUNC_S_F64(x) TRUNC_S(u32, s32, f64, INT32_MIN, INT32_MAX, >,  x)
#define I64_TRUNC_S_F64(x) TRUNC_S(u64, s64, f64, INT64_MIN, INT64_MAX, >=, x)

#define TRUNC_U(ut, ft, max, maxop, x)                                    \
   ((UNLIKELY((x) != (x))) ? TRAP(INVALID_CONVERSION)                     \
  : (UNLIKELY((x) <= (ft)-1 || (x) maxop (ft)(max))) ? TRAP(INT_OVERFLOW) \
  : (ut)(x))

#define I32_TRUNC_U_F32(x) TRUNC_U(u32, f32, UINT32_MAX, >=, x)
#define I64_TRUNC_U_F32(x) TRUNC_U(u64, f32, UINT64_MAX, >=, x)
#define I32_TRUNC_U_F64(x) TRUNC_U(u32, f64, UINT32_MAX, >,  x)
#define I64_TRUNC_U_F64(x) TRUNC_U(u64, f64, UINT64_MAX, >=, x)

#define DEFINE_REINTERPRET(name, t1, t2)  \
  static inline t2 name(t1 x) {           \
    t2 result;                            \
    memcpy(&result, &x, sizeof(result));  \
    return result;                        \
  }

DEFINE_REINTERPRET(f32_reinterpret_i32, u32, f32)
DEFINE_REINTERPRET(i32_reinterpret_f32, f32, u32)
DEFINE_REINTERPRET(f64_reinterpret_i64, u64, f64)
DEFINE_REINTERPRET(i64_reinterpret_f64, f64, u64)


static u32 func_types[18];

static void init_func_types(void) {
  func_types[0] = wasm_rt_register_func_type(1, 0, WASM_RT_I32);
  func_types[1] = wasm_rt_register_func_type(2, 0, WASM_RT_I32, WASM_RT_I32);
  func_types[2] = wasm_rt_register_func_type(0, 0);
  func_types[3] = wasm_rt_register_func_type(2, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[4] = wasm_rt_register_func_type(1, 1, WASM_RT_I32, WASM_RT_I64);
  func_types[5] = wasm_rt_register_func_type(4, 0, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[6] = wasm_rt_register_func_type(3, 0, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[7] = wasm_rt_register_func_type(1, 1, WASM_RT_I32, WASM_RT_I32);
  func_types[8] = wasm_rt_register_func_type(3, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[9] = wasm_rt_register_func_type(4, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[10] = wasm_rt_register_func_type(9, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I64, WASM_RT_I64, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[11] = wasm_rt_register_func_type(0, 1, WASM_RT_I32);
  func_types[12] = wasm_rt_register_func_type(5, 0, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[13] = wasm_rt_register_func_type(9, 0, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I64, WASM_RT_I64, WASM_RT_I32);
  func_types[14] = wasm_rt_register_func_type(5, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[15] = wasm_rt_register_func_type(6, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[16] = wasm_rt_register_func_type(7, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[17] = wasm_rt_register_func_type(3, 1, WASM_RT_I64, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
}

static void __wasm_call_ctors(void);
static void _start(void);
static void _ZN4core3ptr13drop_in_place17h0b50dd8d2a848e35E(u32);
static void _ZN4core3ptr13drop_in_place17h2536ad9e9e2aef4bE(u32);
static void _ZN4core3ptr13drop_in_place17h6f88c2a73a2f75e3E(u32);
static void _ZN4core3ptr13drop_in_place17h817fb0c7ec85b37eE(u32);
static u32 _ZN60__LT_alloc__string__String_u20_as_u20_core__fmt__Display_GT_3fmt17h88e8485f1d902f65E(u32, u32);
static void _ZN48__LT_wasm__RustySword_u20_as_u20_wasm__Sword_GT_7inspect17h0a0fbb6cb6fae517E(u32, u32);
static void _ZN4wasm9read_file17h566cb374fd921ccdE(u32);
static void _ZN48__LT_wasm__RustySword_u20_as_u20_wasm__Sword_GT_7display17hfb31197012fa7bd0E(u32);
static void _ZN46__LT_wasm__NewSword_u20_as_u20_wasm__Sword_GT_7inspect17hf7461e527deeaef1E(u32, u32);
static void _ZN4wasm6prompt17h864234ab4d9bd9dcE(void);
static void _ZN46__LT_wasm__NewSword_u20_as_u20_wasm__Sword_GT_7display17h4e2aee64bd382a71E(u32);
static void _ZN4wasm4main17h0fcb4ec8ced93f5dE(void);
static u32 __original_main(void);
static u32 main(u32, u32);
static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h5e91b6421c7b45c3E_llvm_3493317965437833058(void);
static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h6cc9081211f3042fE_llvm_3493317965437833058(u32);
static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_7reserve17h48301355d030439aE(u32, u32, u32);
static void _ZN4core3ptr13drop_in_place17hd3f3959f4c97243cE(u32);
static void _ZN50__LT_T_u20_as_u20_core__convert__Into_LT_U_GT__GT_4into17h983ad7f08df26d1eE(u32, u32, u32);
static void _ZN3std5error5Error5cause17h42b6be22af74ab4cE(u32, u32);
static u64 _ZN3std5error5Error7type_id17hd7db71e5437d290fE(u32);
static u32 _ZN3std5error5Error9backtrace17hb542ab28ea02206fE(u32);
static u32 _ZN3std2rt10lang_start28__u7b__u7b_closure_u7d__u7d_17h38b7bbbd60866851E(u32);
static u32 _ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h1734dabf5e32b98aE(u32);
static void _ZN4core3ptr13drop_in_place17h8527075be1a03755E(u32);
static void _ZN5alloc5slice64__LT_impl_u20_alloc__borrow__ToOwned_u20_for_u20__u5b_T_u5d__GT_8to_owned17hcbfede6e87b73bf8E(u32, u32, u32);
static void _ZN3std2io16append_to_string17h5b76cd210b0a5cd8E(u32, u32, u32);
static void _ZN4core5slice29__LT_impl_u20__u5b_T_u5d__GT_15copy_from_slice17hdeeb8ec1d0ce5f8bE(u32, u32, u32, u32);
static void _ZN79__LT_std__io__buffered__BufWriter_LT_W_GT__u20_as_u20_core__ops__drop__Drop_GT_4drop17h35eae9ee9f99cf1eE(u32);
static void _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h85e9c06ab818adc3E(u32);
static void _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17hf62bca0551a53043E(u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17he7c55c53190843baE(u32, u32);
static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17h017dd7820235afadE(u32, u32);
static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17hc62cda27386bedf7E(u32, u32);
static void _ZN65__LT_std__io__stdio__Maybe_LT_W_GT__u20_as_u20_std__io__Write_GT_5write17h635a424e4604ada3E(u32, u32, u32, u32);
static u32 __rust_alloc(u32, u32);
static void __rust_dealloc(u32, u32, u32);
static u32 __rust_realloc(u32, u32, u32, u32);
static void _ZN109__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_alloc__vec__SpecExtend_LT__RF_T_C_core__slice__Iter_LT_T_GT__GT__GT_11spec_extend17hce2eec127ad34cc7E(u32, u32, u32);
static u64 _ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h0190c02ab65d56acE(u32);
static u64 _ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h029516de738f74ddE(u32);
static u64 _ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h1036ec8cc0ac4000E(u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h0154d9e42860dd53E(u32, u32);
static u32 _ZN73__LT_std__sys_common__os_str_bytes__Slice_u20_as_u20_core__fmt__Debug_GT_3fmt17h48c636194360662dE(u32, u32, u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h2e0883158ff4bc71E(u32, u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h33fbe4fe765398d6E(u32, u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h7b30a097e07ac9d4E(u32, u32);
static u32 _ZN57__LT_std__io__error__Repr_u20_as_u20_core__fmt__Debug_GT_3fmt17h35f993de34bdfaf1E(u32, u32);
static u32 _ZN58__LT_std__ffi__c_str__CStr_u20_as_u20_core__fmt__Debug_GT_3fmt17h28e0d8bc9678db10E(u32, u32, u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17hed958284c2b6c751E(u32, u32);
static u32 _ZN62__LT_std__io__error__ErrorKind_u20_as_u20_core__fmt__Debug_GT_3fmt17h3ea22aa413b60deaE(u32, u32);
static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17h30c05985b633232cE(u32, u32);
static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17hb42a3b6b7f8cdfc5E(u32, u32);
static u32 _ZN45__LT__RF_T_u20_as_u20_core__fmt__UpperHex_GT_3fmt17h7be854885e27c6ffE(u32, u32);
static u32 _ZN4core3fmt3num50__LT_impl_u20_core__fmt__Debug_u20_for_u20_i32_GT_3fmt17h1f2c474a10b11f09E(u32, u32);
static u32 _ZN4core3fmt5Write10write_char17h0b163bb0f36a33d5E(u32, u32);
static void _ZN3std2io5Write9write_all17h3c6b69cf0d5dfa52E(u32, u32, u32, u32);
static u32 _ZN4core3fmt5Write10write_char17hd5e375ed7cc26f67E(u32, u32);
static void _ZN3std2io5Write9write_all17h0ac6a6a37a604fceE(u32, u32, u32, u32);
static u32 _ZN4core3fmt5Write9write_fmt17h0c6297cc94671fdbE(u32, u32);
static u32 _ZN4core3fmt5Write9write_fmt17hef4ec0875f790078E(u32, u32);
static void _ZN3std9panicking12default_hook17h61085b8eace1a41cE(u32);
static void _ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h2bc8b0235c26cfedE(u32, u32);
static void _ZN3std4sync4once4Once9call_once28__u7b__u7b_closure_u7d__u7d_17ha8365db8fceb4f2cE(u32, u32);
static void _ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h458ee20a9f44d36bE(u32);
static void _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h636c01c268505f2aE(u32);
static void _ZN3std9panicking11begin_panic17h03009c70f59374e1E(u32, u32, u32);
static u32 _ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h717d1eb4223145c5E(u32, u32, u32);
static void _ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17hfef0f420f30980acE(u32);
static void _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h76eb5b162db06de2E(u32);
static void _ZN4core3ptr13drop_in_place17h02dece875a093ec5E(u32);
static void _ZN4core3ptr13drop_in_place17h049ce136079928c5E(u32);
static void _ZN4core3ptr13drop_in_place17h12fdb55a43c98e2eE(u32);
static void _ZN4core3ptr13drop_in_place17h1bc2903d971cdafdE(u32);
static void _ZN4core3ptr13drop_in_place17h357736d8dd8f427cE(u32);
static void _ZN4core3ptr13drop_in_place17h4fb62c5b377abd3dE(u32);
static void _ZN4core3ptr13drop_in_place17had9a6dbef51e0932E(u32);
static void _ZN4core3ptr13drop_in_place17hfd7be1f615408ba6E(u32);
static u32 _ZN4core6option15Option_LT_T_GT_6unwrap17hcef08ddb8cf9885dE(u32, u32);
static u32 _ZN4core6option15Option_LT_T_GT_6unwrap17hf88ae310ea733521E(u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17h1148e112010023a0E(u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17h847b5ed38de6fefaE(u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17hd2e1f2321b48f67eE(u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17h3b7bf02809848e00E(u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17h64f54daf655ce739E(u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17hdd5646de992e1c42E(u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h17594c444a344b88E(u32, u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h2ccf06e1a3fafb6aE(u32, u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h43a4a1478c7fe4a7E(u32, u32, u32);
static u32 _ZN58__LT_alloc__string__String_u20_as_u20_core__fmt__Debug_GT_3fmt17h2cea2baa4dfef855E(u32, u32);
static void _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h54081c59c02bd7eaE(u32);
static void _ZN3std2io8buffered18BufWriter_LT_W_GT_9flush_buf17hd67ccca3c7d9e3cdE(u32, u32);
static void _ZN5alloc5slice29__LT_impl_u20__u5b_T_u5d__GT_6to_vec17h2392cf0518e8ca41E(u32, u32, u32);
static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h132ff70aff78c839E(void);
static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(u32, u32);
static u32 _ZN60__LT_alloc__string__String_u20_as_u20_core__fmt__Display_GT_3fmt17h88e8485f1d902f65E_1(u32, u32);
static u32 _ZN3std10sys_common11thread_info10ThreadInfo4with28__u7b__u7b_closure_u7d__u7d_17h4f4afda818addf88E(u32);
static void _ZN3std6thread4park17haa34f1fc5521730bE(void);
static void _ZN3std4sync7condvar7Condvar6verify17h950e8c3c7a86a681E(u32, u32);
static void _ZN3std10sys_common7condvar7Condvar4wait17hb99804595d9707a7E(void);
static void _ZN3std9panicking15begin_panic_fmt17h3bc495be3b042206E(u32, u32);
static u32 _ZN3std6thread6Thread3new17h1d02bb6db813b9d0E(u32);
static void _ZN3std3ffi5c_str7CString18from_vec_unchecked17h48bedb0a7532b717E(u32, u32);
static void _ZN3std3sys4wasi11unsupported17hd974f16cf85baeceE(u32);
static void _ZN3std3env7_var_os17h65122ae02361542aE(u32, u32, u32);
static void _ZN70__LT__RF_str_u20_as_u20_std__ffi__c_str__CString__new__SpecIntoVec_GT_8into_vec17h65a4d42209f91185E(u32, u32, u32);
static void _ZN3std3ffi5c_str104__LT_impl_u20_core__convert__From_LT_std__ffi__c_str__NulError_GT__u20_for_u20_std__io__error__Error_GT_4from17he7bd34cf5a7ddaa1E(u32, u32);
static u32 _ZN60__LT_std__io__error__Error_u20_as_u20_core__fmt__Display_GT_3fmt17h12ea3a633b564efaE(u32, u32);
static u32 _ZN55__LT_std__path__Display_u20_as_u20_core__fmt__Debug_GT_3fmt17hfa561203d2c037b8E(u32, u32);
static u64 _ZN3std5error5Error7type_id17h57e588fb6656ec7eE(u32);
static u32 _ZN3std5error5Error9backtrace17he16cc217c1a2f33bE(u32);
static void _ZN3std5error5Error5cause17h4f470d68a88d26ceE(u32, u32);
static void _ZN243__LT_std__error___LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__boxed__Box_LT_dyn_u20_std__error__Error_u2b_core__marker__Sync_u2b_core__marker__Send_GT__GT___from__StringError_u20_as_u20_std__error__Error_GT_11description17h29c39b0cc2d10c9fE(u32, u32);
static u32 _ZN244__LT_std__error___LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__boxed__Box_LT_dyn_u20_std__error__Error_u2b_core__marker__Sync_u2b_core__marker__Send_GT__GT___from__StringError_u20_as_u20_core__fmt__Display_GT_3fmt17h36f89103f15672f6E(u32, u32);
static u32 _ZN242__LT_std__error___LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__boxed__Box_LT_dyn_u20_std__error__Error_u2b_core__marker__Sync_u2b_core__marker__Send_GT__GT___from__StringError_u20_as_u20_core__fmt__Debug_GT_3fmt17hd9db4bd6825b019cE(u32, u32);
static u32 _ZN61__LT_std__ffi__c_str__CString_u20_as_u20_core__fmt__Debug_GT_3fmt17h76df9c6c5e27e8efE(u32, u32);
static void _ZN3std3sys4wasi2fs11open_parent17h2bf813dab646b1efE(u32, u32, u32);
static void _ZN3std3sys4wasi2fs7open_at17h2ff12843dac03953E(u32, u32, u32, u32, u32);
static void _ZN47__LT_std__fs__File_u20_as_u20_std__io__Read_GT_4read17h1f42a62b4fce9d8aE(u32, u32, u32, u32);
static void _ZN3std2fs11OpenOptions3new17he0d0cef85f34602fE(u32);
static u32 _ZN3std2fs11OpenOptions4read17h7401959d78f75c40E(u32, u32);
static void _ZN3std2fs11OpenOptions5_open17h3cc2934c37bbaa9aE(u32, u32, u32, u32);
static u32 _ZN3std3sys4wasi17decode_error_kind17he23a249a9ada7316E(u32);
static void _ZN72__LT_std__io__buffered__BufWriter_LT_W_GT__u20_as_u20_std__io__Write_GT_5write17h98b8ed5b902ebbc8E(u32, u32, u32, u32);
static u32 _ZN58__LT_std__io__error__Error_u20_as_u20_core__fmt__Debug_GT_3fmt17he9ea5949f4a2990eE(u32, u32);
static void _ZN3std2io5error5Error4_new17h276c50b6edbce93bE(u32, u32, u32, u32);
static u32 _ZN3std2io5error5Error4kind17hdcfd08845a3d8932E(u32);
static void _ZN3std3sys4wasi2os12error_string17h2cf85a3df68353a7E(u32, u32);
static void _ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_5write17h1f75c072454a7cb2E(u32, u32, u32, u32);
static void _ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_14write_vectored17hdc4c24efc025d6a0E(u32, u32, u32, u32);
static void _ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_5flush17h9425a9f607fd3865E(u32, u32);
static void _ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_9write_all17hce2c6010f31eb804E(u32, u32, u32, u32);
static void _ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_9write_fmt17h1cfe94106c0e4d55E(u32, u32, u32);
static void _ZN60__LT_std__io__stdio__StdoutRaw_u20_as_u20_std__io__Write_GT_5write17h6c80cfd177b83762E(u32, u32, u32, u32);
static void _ZN60__LT_std__io__stdio__StderrRaw_u20_as_u20_std__io__Write_GT_5write17hf7531ab2fbcf77b3E(u32, u32, u32, u32);
static u32 _ZN3std2io5stdio5stdin17h6275b62513a72eaaE(void);
static u32 _ZN3std10sys_common11at_exit_imp4push17h17f1d1a73fe1793aE(u32, u32);
static void _ZN3std2io5stdio5Stdin9read_line17h8f9a7008c4938aaaE(u32, u32, u32);
static void _ZN55__LT_std__io__stdio__Stdin_u20_as_u20_std__io__Read_GT_4read17h43ce0ea6cf440e2eE(u32, u32, u32, u32);
static void _ZN59__LT_std__io__stdio__StdinLock_u20_as_u20_std__io__Read_GT_4read17hbf4316ecbb809641E(u32, u32, u32, u32);
static u32 _ZN3std2io5stdio6stdout17h060687408f12e049E(void);
static void _ZN61__LT_std__io__stdio__StdoutLock_u20_as_u20_std__io__Write_GT_5write17h50f86d8404c780efE(u32, u32, u32, u32);
static void _ZN57__LT_std__io__stdio__Stdout_u20_as_u20_std__io__Write_GT_5flush17ha8096688cb5c04b4E(u32, u32);
static void _ZN57__LT_std__io__stdio__Stdout_u20_as_u20_std__io__Write_GT_9write_fmt17hfcc1c9dfb39740edE(u32, u32, u32);
static void _ZN3std4sync4once4Once10call_inner17h74e47fc5d3e1aa49E(u32, u32, u32, u32);
static void _ZN3std2io5stdio9set_panic17h73ed222c0f64725fE(u32, u32, u32);
static void _ZN3std2io5stdio6_print17hc41bda27e6084072E(u32);
static void _ZN56__LT_std__io__Guard_u20_as_u20_core__ops__drop__Drop_GT_4drop17h7f4cce983b4a506eE(u32);
static void _ZN3std2io5Write14write_vectored17hcfbf4a1d27a1ae81E(u32, u32, u32, u32);
static void _ZN3std2io5Write18write_all_vectored17h31bcf0c43c76d367E(u32, u32, u32, u32);
static void _ZN3std2io5Write18write_all_vectored17hbfa4a88028508b9dE(u32, u32, u32, u32);
static void _ZN3std2io5Write9write_fmt17h61c08c303399aa39E(u32, u32, u32);
static u32 _ZN80__LT_std__io__Write__write_fmt__Adaptor_LT_T_GT__u20_as_u20_core__fmt__Write_GT_9write_str17habbf305c93d57a52E(u32, u32, u32);
static u32 _ZN80__LT_std__io__Write__write_fmt__Adaptor_LT_T_GT__u20_as_u20_core__fmt__Write_GT_9write_str17hfba8d08e2a0d6be2E(u32, u32, u32);
static void _ZN79__LT_std__path__Path_u20_as_u20_core__convert__AsRef_LT_std__path__Path_GT__GT_6as_ref17h7dc33fb987337414E(u32, u32, u32);
static void _ZN59__LT_std__process__ChildStdin_u20_as_u20_std__io__Write_GT_5flush17h3236cbe8e09377f1E(u32, u32);
static void _ZN3std7process4exit17h15172f2c8741ba8bE(u32);
static void _ZN3std10sys_common7cleanup17h0efc2b08e2a4a6c3E(void);
static void _ZN3std3sys4wasi2os4exit17h7b4910da2192d43dE(u32);
static void _ZN3std7process5abort17h5ef35935ef2edf2cE(void);
static void _ZN3std3sys4wasi14abort_internal17h148e8bcb88f086ceE(void);
static void _ZN70__LT_std__sync__once__WaiterQueue_u20_as_u20_core__ops__drop__Drop_GT_4drop17h18e38d5577964ed0E(u32);
static u32 _ZN91__LT_std__sys_common__backtrace___print__DisplayBacktrace_u20_as_u20_core__fmt__Display_GT_3fmt17h25daba2a18d6a743E(u32, u32);
static u32 _ZN3std10sys_common9backtrace10_print_fmt28__u7b__u7b_closure_u7d__u7d_17ha62efdc37013783cE(u32, u32, u32);
static u32 _ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17hd2bb8386068f691aE(u32, u32);
static void _ZN3std3sys4wasi7condvar7Condvar4wait17h08e64e77fb399e8fE(u32, u32);
static u32 _ZN82__LT_std__sys_common__poison__PoisonError_LT_T_GT__u20_as_u20_core__fmt__Debug_GT_3fmt17h16f30397faa9688eE(u32, u32);
static void _ZN3std10sys_common4util10dumb_print17h200d2c5cffd6deeaE(u32);
static void _ZN3std10sys_common4util5abort17hc50d73ca76b1b533E(u32);
static void _ZN3std5alloc24default_alloc_error_hook17h676e6a95f439f851E(u32, u32);
static void rust_oom(u32, u32);
static u32 __rdl_alloc(u32, u32);
static void __rdl_dealloc(u32, u32, u32);
static u32 __rdl_realloc(u32, u32, u32, u32);
static void _ZN3std9panicking12default_hook28__u7b__u7b_closure_u7d__u7d_17h586ab2a6a28d8372E(u32, u32, u32);
static void rust_begin_unwind(u32);
static void _ZN3std9panicking20rust_panic_with_hook17hb8132b4308a71007E(u32, u32, u32, u32);
static void _ZN90__LT_std__panicking__begin_panic_handler__PanicPayload_u20_as_u20_core__panic__BoxMeUp_GT_8take_box17h2d26e4289e9e0f5bE(u32, u32);
static void _ZN90__LT_std__panicking__begin_panic_handler__PanicPayload_u20_as_u20_core__panic__BoxMeUp_GT_3get17haebaf56b59d9f0f7E(u32, u32);
static void _ZN91__LT_std__panicking__begin_panic__PanicPayload_LT_A_GT__u20_as_u20_core__panic__BoxMeUp_GT_8take_box17h00afc1f3240f4984E(u32, u32);
static void _ZN91__LT_std__panicking__begin_panic__PanicPayload_LT_A_GT__u20_as_u20_core__panic__BoxMeUp_GT_3get17hf7b2418ff47c602eE(u32, u32);
static void rust_panic(u32, u32);
static u32 _ZN3std2rt19lang_start_internal17h66de5b0ec01e6d33E(u32, u32, u32, u32);
static u32 _ZN62__LT_std__ffi__c_str__NulError_u20_as_u20_core__fmt__Debug_GT_3fmt17h7aebd1ccdb940e5aE(u32, u32);
static void _ZN68__LT_std__sys__wasi__fd__WasiFd_u20_as_u20_core__ops__drop__Drop_GT_4drop17h4d2e151266c87dc4E(u32);
static void _ZN3std3sys4wasi2fs9osstr2str17h2b93d5c461792507E(u32, u32, u32);
static void _ZN3std3sys4wasi5mutex14ReentrantMutex6unlock17h57b66397f140f523E(u32);
static u32 _ZN3std3sys4wasi7process8ExitCode6as_i3217h363ebb260b4f8711E(u32);
static u32 _ZN3std3sys4wasi5stdio8is_ebadf17h866f32eebed413cfE(u32);
static u32 __rust_start_panic(u32);
static u32 _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(u32);
static u32 _ZN4wasi13lib_generated8fd_close17hfa5cf758483496b0E(u32);
static void _ZN4wasi13lib_generated7fd_read17h0d476bb7732cd2ceE(u32, u32, u32, u32);
static void _ZN4wasi13lib_generated8fd_write17hacbf9079620e9958E(u32, u32, u32, u32);
static void _ZN4wasi13lib_generated9path_open17h60ff9154cd4f4a34E(u32, u32, u32, u32, u32, u32, u64, u64, u32);
static void _ZN9backtrace5print12BacktraceFmt3new17h3ab018832264a723E(u32, u32, u32, u32, u32);
static u32 _ZN9backtrace5print12BacktraceFmt11add_context17hc1ee7fb8cfa6f36aE(u32);
static void abort(void);
static u32 malloc(u32);
static u32 dlmalloc(u32);
static void free(u32);
static void dlfree(u32);
static u32 calloc(u32, u32);
static u32 realloc(u32, u32);
static void dispose_chunk(u32, u32);
static u32 internal_memalign(u32, u32);
static u32 aligned_alloc(u32, u32);
static void _Exit(u32);
static u32 __wasilibc_find_relpath(u32, u32);
static void __wasilibc_populate_libpreopen(void);
static void __wasilibc_initialize_environ_eagerly(void);
static u32 sbrk(u32);
static void __wasilibc_ensure_environ(void);
static void __wasilibc_initialize_environ(void);
static void dummy(void);
static void __prepare_for_exit(void);
static void exit(u32);
static u32 getenv(u32);
static u32 strlen_0(u32);
static u32 __strchrnul(u32, u32);
static u32 memcpy_0(u32, u32, u32);
static u32 memset_0(u32, u32, u32);
static u32 memcmp_0(u32, u32, u32);
static u32 strncmp_0(u32, u32, u32);
static u32 strerror_0(u32);
static u32 strerror_r(u32, u32, u32);
static u32 memmove_0(u32, u32, u32);
static u32 dummy_1(u32, u32);
static u32 __lctrans(u32, u32);
static void _ZN4core3ptr13drop_in_place17h402ec9c621dc0a64E(u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17he835ee2740080451E(u32, u32);
static void _ZN5alloc6string6String4push17h49cb764b5cad3b99E(u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17hd12a4d5c4ea306b5E(u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h0d968c1939c85c57E(u32, u32, u32);
static void _ZN109__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_alloc__vec__SpecExtend_LT__RF_T_C_core__slice__Iter_LT_T_GT__GT__GT_11spec_extend17h45c47c004d042e17E(u32, u32, u32);
static void _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(u32, u32);
static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h08088d9b25d6a95aE(void);
static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17ha9e5510550e81555E(u32, u32);
static void _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E(void);
static void _ZN5alloc3fmt6format17h791816ebd75606e6E(u32, u32);
static void _ZN5alloc5slice29__LT_impl_u20__u5b_T_u5d__GT_6to_vec17h36ab9f401e213751E(u32, u32, u32);
static void _ZN60__LT_alloc__string__String_u20_as_u20_core__clone__Clone_GT_5clone17hd5bc8de5dcbfa5d2E(u32, u32);
static void _ZN5alloc6string104__LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__vec__Vec_LT_u8_GT__GT_4from17h645290af10f55923E(u32, u32);
static void _ZN5alloc3vec12Vec_LT_T_GT_5drain17end_assert_failed17hccc4a24f1f7369a6E(u32, u32);
static u32 _ZN4core3ops8function6FnOnce9call_once17h0c772a731295e95aE(u32, u32);
static void _ZN4core3ptr13drop_in_place17h01fc6f5e51d8edbeE(u32);
static void _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(u32, u32, u32);
static void _ZN4core9panicking5panic17hab35b75b6c5c31f2E(u32, u32, u32);
static void _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(u32, u32, u32);
static void _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(u32, u32, u32);
static u32 _ZN4core3fmt9Formatter3pad17h18e6ccc150f9bfbcE(u32, u32, u32);
static void _ZN4core3str16slice_error_fail17h756d0528f966c096E(u32, u32, u32, u32, u32);
static void _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(u32, u32);
static u32 _ZN4core3fmt3num3imp52__LT_impl_u20_core__fmt__Display_u20_for_u20_u32_GT_3fmt17haffb72d949b13748E(u32, u32);
static void _ZN4core3num14from_str_radix17ha04c95ba4acb47c5E(u32, u32, u32, u32);
static u32 _ZN4core3fmt5write17h4834d85ce1be7131E(u32, u32, u32);
static u32 _ZN71__LT_core__ops__range__Range_LT_Idx_GT__u20_as_u20_core__fmt__Debug_GT_3fmt17h560d60a49501f432E(u32, u32);
static u32 _ZN4core3fmt3num52__LT_impl_u20_core__fmt__Debug_u20_for_u20_usize_GT_3fmt17hd9e5ee56a3abf985E(u32, u32);
static u64 _ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h21038e7fd8af2881E(u32);
static void _ZN4core5ascii14escape_default17h0c71e6816c4ab86eE(u32, u32);
static void _ZN85__LT_core__ascii__EscapeDefault_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17h75372c571a88c631E(u32, u32);
static u32 _ZN60__LT_core__cell__BorrowError_u20_as_u20_core__fmt__Debug_GT_3fmt17hdfa14f22cbd9ae5fE(u32, u32);
static u32 _ZN63__LT_core__cell__BorrowMutError_u20_as_u20_core__fmt__Debug_GT_3fmt17h888db12a3966bea9E(u32, u32);
static u32 _ZN82__LT_core__char__EscapeDebug_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17h31831fc6cb32f772E(u32);
static u32 _ZN4core3fmt8builders11DebugStruct5field17h8526abf557e6a496E(u32, u32, u32, u32, u32);
static void _ZN4core6option13expect_failed17hdd81bfbb4998aefaE(u32, u32, u32);
static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17ha84d8cd9be8910c1E(u32, u32);
static void _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(u32, u32, u32, u32, u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17hb3a7d31ca8f59d32E(u32, u32);
static u32 _ZN4core5panic9PanicInfo7message17h92bd97d427b892e1E(u32);
static u32 _ZN4core5panic9PanicInfo8location17hadae980b9a5e60d2E(u32);
static u32 _ZN4core5panic8Location6caller17ha977844962a520efE(u32);
static void _ZN4core5panic8Location4file17hd78f3cde5f346820E(u32, u32);
static u32 _ZN60__LT_core__panic__Location_u20_as_u20_core__fmt__Display_GT_3fmt17h5a11f7908f87d86dE(u32, u32);
static u32 _ZN68__LT_core__fmt__builders__PadAdapter_u20_as_u20_core__fmt__Write_GT_9write_str17hb63bd9b52d2ea355E(u32, u32, u32);
static void _ZN4core5slice6memchr6memchr17h4b6f86a8dda0136aE(u32, u32, u32, u32);
static u32 _ZN4core3fmt8builders11DebugStruct6finish17hab8f7dfb856acfc0E(u32);
static u32 _ZN4core3fmt8builders10DebugTuple5field17h16202dfa3a9387a4E(u32, u32, u32);
static u32 _ZN4core3fmt8builders10DebugTuple6finish17h540db6bc8e5a3697E(u32);
static void _ZN4core3fmt8builders10DebugInner5entry17hcf0cc88c48da1d40E(u32, u32, u32);
static u32 _ZN4core3fmt8builders8DebugSet5entry17he2607966213fa565E(u32, u32, u32);
static u32 _ZN4core3fmt8builders9DebugList6finish17hf24d2051438d787aE(u32);
static u32 _ZN4core3fmt5Write10write_char17h2e3be12005dd62ddE(u32, u32);
static u32 _ZN4core3fmt5Write9write_fmt17h0c139c28d79b9a60E(u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h079bfd1e4c225fd5E(u32, u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17h6458f56299ed9010E(u32, u32);
static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17h8b43657baa867c64E(u32, u32);
static u32 _ZN59__LT_core__fmt__Arguments_u20_as_u20_core__fmt__Display_GT_3fmt17h25afdf22ace19a57E(u32, u32);
static u32 _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(u32, u32, u32, u32, u32, u32);
static u32 _ZN4core3fmt9Formatter12pad_integral12write_prefix17h8315a5e67d65fa1fE(u32, u32, u32, u32);
static u32 _ZN4core3fmt9Formatter9write_str17h3d77f3190807e699E(u32, u32, u32);
static u32 _ZN4core3fmt9Formatter9write_fmt17h5f4a789bf06948b3E(u32, u32);
static u32 _ZN4core3fmt9Formatter15debug_lower_hex17h613d71a0ae3bc060E(u32);
static u32 _ZN4core3fmt9Formatter15debug_upper_hex17h5c3e903ff5236763E(u32);
static void _ZN4core3fmt9Formatter12debug_struct17h46183d60fb16cd21E(u32, u32, u32, u32);
static void _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(u32, u32, u32, u32);
static void _ZN4core3fmt9Formatter10debug_list17h71cfa9ce1b3f9f44E(u32, u32);
static u32 _ZN57__LT_core__fmt__Formatter_u20_as_u20_core__fmt__Write_GT_10write_char17h22afcca50c7c4efdE(u32, u32);
static u32 _ZN40__LT_str_u20_as_u20_core__fmt__Debug_GT_3fmt17hc81f6984a0ce9960E(u32, u32, u32);
static u32 _ZN4core7unicode12unicode_data15grapheme_extend6lookup17h138f528bd4ec82e3E(u32);
static u32 _ZN4core7unicode9printable5check17hc49c8dda078b527eE(u32, u32, u32, u32, u32, u32, u32);
static void _ZN4core3str6traits101__LT_impl_u20_core__slice__SliceIndex_LT_str_GT__u20_for_u20_core__ops__range__Range_LT_usize_GT__GT_5index28__u7b__u7b_closure_u7d__u7d_17h834e63e786a4d85dE(u32);
static u32 _ZN42__LT_str_u20_as_u20_core__fmt__Display_GT_3fmt17h503be603f26e92cbE(u32, u32, u32);
static u32 _ZN41__LT_char_u20_as_u20_core__fmt__Debug_GT_3fmt17hb09a68fda0268a45E(u32, u32);
static void _ZN4core5slice6memchr7memrchr17heee7616632cba075E(u32, u32, u32, u32);
static void _ZN4core5slice25slice_index_overflow_fail17h96c96832494e835eE(u32);
static void _ZN4core3str5lossy9Utf8Lossy10from_bytes17h1fc730ab18994b0dE(u32, u32, u32);
static void _ZN4core3str5lossy9Utf8Lossy6chunks17ha62e90201a5f69d8E(u32, u32, u32);
static void _ZN96__LT_core__str__lossy__Utf8LossyChunksIter_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17he3cf0b2f3c5f8b4eE(u32, u32);
static u32 _ZN66__LT_core__str__lossy__Utf8Lossy_u20_as_u20_core__fmt__Display_GT_3fmt17h9396f0cf1136f103E(u32, u32, u32);
static u32 _ZN4core3fmt3num52__LT_impl_u20_core__fmt__LowerHex_u20_for_u20_i8_GT_3fmt17h6b3e03432bfb2278E(u32, u32);
static void _ZN4core3str9from_utf817he6f02ee8cec749d4E(u32, u32, u32);
static u32 _ZN4core3fmt3num3imp51__LT_impl_u20_core__fmt__Display_u20_for_u20_u8_GT_3fmt17hfd698e1eaf4e0cebE(u32, u32);
static void _ZN4core3str21__LT_impl_u20_str_GT_4trim17h7b79618a50b556d3E(u32, u32, u32);
static u32 _ZN4core7unicode12unicode_data11white_space6lookup17hc2ed76cfbabc0c2fE(u32);
static u32 _ZN4core7unicode9printable12is_printable17h481fab4e83051dc0E(u32);
static u32 _ZN4core3fmt3num53__LT_impl_u20_core__fmt__LowerHex_u20_for_u20_i32_GT_3fmt17h4b124e18148b69c3E(u32, u32);
static void _ZN4core3num52__LT_impl_u20_core__str__FromStr_u20_for_u20_i32_GT_8from_str17h24ec4dabfaea63f0E(u32, u32, u32);
static void _ZN4core3num52__LT_impl_u20_core__str__FromStr_u20_for_u20_u32_GT_8from_str17hee1e4ecf1e1de66dE(u32, u32, u32);
static u32 _ZN61__LT_core__num__ParseIntError_u20_as_u20_core__fmt__Debug_GT_3fmt17h121cef04e893d4c1E(u32, u32);
static u32 _ZN4core3fmt3num3imp7fmt_u6417h1d17ceced9d6225fE(u64, u32, u32);
static u32 _ZN4core3fmt3num52__LT_impl_u20_core__fmt__UpperHex_u20_for_u20_i8_GT_3fmt17h768b96441edb650eE(u32, u32);
static u32 _ZN4core3fmt3num53__LT_impl_u20_core__fmt__UpperHex_u20_for_u20_i32_GT_3fmt17hac44606703ee1b92E(u32, u32);
static u32 _ZN4core3fmt3num3imp52__LT_impl_u20_core__fmt__Display_u20_for_u20_i32_GT_3fmt17hcf6a92db823ff527E(u32, u32);
static u32 _ZN53__LT_core__fmt__Error_u20_as_u20_core__fmt__Debug_GT_3fmt17h0546d0fd69e4b730E(u32, u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h82db6cee448a2919E(u32, u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h8ebaddfa97032842E(u32, u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17hde16ba6a50b346e4E(u32, u32);
static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17he1c9497b0427386eE(u32, u32);
static u32 _ZN57__LT_core__str__Utf8Error_u20_as_u20_core__fmt__Debug_GT_3fmt17hf1ddee02a010aedaE(u32, u32);

static u32 g0;
static u32 __data_end;
static u32 __heap_base;

static void init_globals(void) {
  g0 = 1048576u;
  __data_end = 1062288u;
  __heap_base = 1062288u;
}

static wasm_rt_memory_t memory;

static wasm_rt_table_t T0;

static void __wasm_call_ctors(void) {
  FUNC_PROLOGUE;
  __wasilibc_initialize_environ_eagerly();
  __wasilibc_populate_libpreopen();
  FUNC_EPILOGUE;
}

static void _start(void) {
  u32 l0 = 0;
  FUNC_PROLOGUE;
  u32 i0;
  __wasm_call_ctors();
  i0 = __original_main();
  l0 = i0;
  __prepare_for_exit();
  i0 = l0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l0;
  (*Z_wasi_snapshot_preview1Z_proc_exitZ_vi)(i0);
  UNREACHABLE;
  B0:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17h0b50dd8d2a848e35E(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 2u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l3;
  i2 = l2;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B1:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17h2536ad9e9e2aef4bE(u32 p0) {
  FUNC_PROLOGUE;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17h6f88c2a73a2f75e3E(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l1;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = p0;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i1 = l1;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17h817fb0c7ec85b37eE(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l1;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  FUNC_EPILOGUE;
}

static u32 _ZN60__LT_alloc__string__String_u20_as_u20_core__fmt__Display_GT_3fmt17h88e8485f1d902f65E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i2 = p1;
  i0 = _ZN42__LT_str_u20_as_u20_core__fmt__Display_GT_3fmt17h503be603f26e92cbE(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN48__LT_wasm__RustySword_u20_as_u20_wasm__Sword_GT_7inspect17h0a0fbb6cb6fae517E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  _ZN4wasm9read_file17h566cb374fd921ccdE(i0);
  FUNC_EPILOGUE;
}

static void _ZN4wasm9read_file17h566cb374fd921ccdE(u32 p0) {
  u32 l1 = 0, l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 144u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = l1;
  i1 = 13u;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = l1;
  i1 = 1049488u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l1;
  i1 = 96u;
  i0 += i1;
  _ZN3std2fs11OpenOptions3new17he0d0cef85f34602fE(i0);
  i0 = l1;
  i1 = 96u;
  i0 += i1;
  i1 = 1u;
  i0 = _ZN3std2fs11OpenOptions4read17h7401959d78f75c40E(i0, i1);
  l2 = i0;
  i0 = l1;
  i1 = 8u;
  i0 += i1;
  i1 = 1049488u;
  i2 = 13u;
  _ZN79__LT_std__path__Path_u20_as_u20_core__convert__AsRef_LT_std__path__Path_GT__GT_6as_ref17h7dc33fb987337414E(i0, i1, i2);
  i0 = l1;
  i1 = 48u;
  i0 += i1;
  i1 = l2;
  i2 = l1;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  i3 = l1;
  i3 = i32_load((&memory), (u64)(i3 + 12));
  _ZN3std2fs11OpenOptions5_open17h3cc2934c37bbaa9aE(i0, i1, i2, i3);
  i0 = l1;
  i1 = 116u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 100), j1);
  i0 = l1;
  i1 = 1049524u;
  i32_store((&memory), (u64)(i0 + 96), i1);
  i0 = l1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l1;
  i1 = l1;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 112), i1);
  i0 = l1;
  i1 = l1;
  i2 = 80u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l1;
  i1 = l1;
  i2 = 16u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 80), i1);
  i0 = l1;
  i1 = 64u;
  i0 += i1;
  i1 = l1;
  i2 = 96u;
  i1 += i2;
  _ZN5alloc3fmt6format17h791816ebd75606e6E(i0, i1);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = l1;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 52));
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 68));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 64));
  i1 = l2;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B2:;
  i0 = l1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l1;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = l1;
  i1 = l1;
  i2 = 28u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 96), i1);
  i0 = l1;
  i1 = 48u;
  i0 += i1;
  i1 = l1;
  i2 = 32u;
  i1 += i2;
  i2 = l1;
  i3 = 96u;
  i2 += i3;
  _ZN3std2io16append_to_string17h5b76cd210b0a5cd8E(i0, i1, i2);
  i0 = l1;
  i1 = 116u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 100), j1);
  i0 = l1;
  i1 = 1049580u;
  i32_store((&memory), (u64)(i0 + 96), i1);
  i0 = l1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 84), i1);
  i0 = l1;
  i1 = l1;
  i2 = 80u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 112), i1);
  i0 = l1;
  i1 = l1;
  i2 = 92u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 80), i1);
  i0 = l1;
  i1 = l1;
  i2 = 16u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 92), i1);
  i0 = l1;
  i1 = 64u;
  i0 += i1;
  i1 = l1;
  i2 = 96u;
  i1 += i2;
  _ZN5alloc3fmt6format17h791816ebd75606e6E(i0, i1);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 68));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 64));
  i1 = l2;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = p0;
  i1 = l1;
  j1 = i64_load((&memory), (u64)(i1 + 32));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l1;
  i2 = 32u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 28u;
  i0 += i1;
  _ZN68__LT_std__sys__wasi__fd__WasiFd_u20_as_u20_core__ops__drop__Drop_GT_4drop17h4d2e151266c87dc4E(i0);
  i0 = l1;
  i1 = 144u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B1:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 72));
  p0 = i0;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 64));
  l2 = i0;
  i0 = l1;
  i1 = l1;
  j1 = i64_load((&memory), (u64)(i1 + 52));
  i64_store((&memory), (u64)(i0 + 96), j1);
  i0 = l2;
  i1 = p0;
  i2 = l1;
  i3 = 96u;
  i2 += i3;
  i3 = 1048576u;
  i4 = 1049532u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B0:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 72));
  p0 = i0;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 64));
  l2 = i0;
  i0 = l1;
  i1 = l1;
  j1 = i64_load((&memory), (u64)(i1 + 52));
  i64_store((&memory), (u64)(i0 + 96), j1);
  i0 = l2;
  i1 = p0;
  i2 = l1;
  i3 = 96u;
  i2 += i3;
  i3 = 1048576u;
  i4 = 1049588u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN48__LT_wasm__RustySword_u20_as_u20_wasm__Sword_GT_7display17hfb31197012fa7bd0E(u32 p0) {
  u32 l1 = 0, l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = l1;
  i1 = 20u;
  i0 += i1;
  l2 = i0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l1;
  i1 = 1048676u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l1;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l1;
  i1 = l1;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l1;
  _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
  i0 = l1;
  i1 = 32u;
  i0 += i1;
  _ZN4wasm9read_file17h566cb374fd921ccdE(i0);
  i0 = l2;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l1;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l1;
  i1 = 1048708u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = l1;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l1;
  i1 = l1;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l1;
  _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 36));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 32));
  i1 = p0;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = l1;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN46__LT_wasm__NewSword_u20_as_u20_wasm__Sword_GT_7inspect17hf7461e527deeaef1E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 20u;
  i0 += i1;
  l3 = i0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1048760u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l2;
  i1 = 1048752u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
  i0 = l3;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1048760u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l2;
  i1 = 1048816u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
  _ZN4wasm6prompt17h864234ab4d9bd9dcE();
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l2;
  i1 = _ZN3std2io5stdio5stdin17h6275b62513a72eaaE();
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l2;
  i1 = l2;
  i2 = 36u;
  i1 += i2;
  i2 = l2;
  i3 = 24u;
  i2 += i3;
  _ZN3std2io5stdio5Stdin9read_line17h8f9a7008c4938aaaE(i0, i1, i2);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 36));
  l3 = i0;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1));
  l3 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = l2;
  i1 = 36u;
  i0 += i1;
  _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h85e9c06ab818adc3E(i0);
  B1:;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l4 = i0;
  i1 = l2;
  i2 = 24u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 24));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 12u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B2:;
  i0 = l3;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l3;
  _ZN60__LT_alloc__string__String_u20_as_u20_core__clone__Clone_GT_5clone17hd5bc8de5dcbfa5d2E(i0, i1);
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B0:;
  i0 = l2;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 4));
  i64_store((&memory), (u64)(i0 + 40), j1);
  i0 = 1048824u;
  i1 = 21u;
  i2 = l2;
  i3 = 40u;
  i2 += i3;
  i3 = 1048576u;
  i4 = 1048852u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN4wasm6prompt17h864234ab4d9bd9dcE(void) {
  u32 l0 = 0, l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l0 = i0;
  g0 = i0;
  i0 = l0;
  i1 = 28u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = 1048760u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l0;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 12), j1);
  i0 = l0;
  i1 = 1049464u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l0;
  i1 = 8u;
  i0 += i1;
  _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
  i0 = l0;
  i1 = _ZN3std2io5stdio6stdout17h060687408f12e049E();
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l0;
  i1 = 32u;
  i0 += i1;
  i1 = l0;
  i2 = 44u;
  i1 += i2;
  _ZN57__LT_std__io__stdio__Stdout_u20_as_u20_std__io__Write_GT_5flush17ha8096688cb5c04b4E(i0, i1);
  i0 = l0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 32));
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  i0 = l0;
  i0 = i32_load((&memory), (u64)(i0 + 44));
  l1 = i0;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1));
  l1 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = l0;
  i1 = 44u;
  i0 += i1;
  _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17hf62bca0551a53043E(i0);
  B1:;
  i0 = l0;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B0:;
  i0 = l0;
  i1 = l0;
  j1 = i64_load((&memory), (u64)(i1 + 32));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = 1048608u;
  i1 = 43u;
  i2 = l0;
  i3 = 8u;
  i2 += i3;
  i3 = 1048576u;
  i4 = 1049472u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN46__LT_wasm__NewSword_u20_as_u20_wasm__Sword_GT_7display17h4e2aee64bd382a71E(u32 p0) {
  u32 l1 = 0, l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = l1;
  i1 = 20u;
  i0 += i1;
  l2 = i0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l1;
  i1 = 1048676u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l1;
  i1 = l1;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l1;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l1;
  _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
  i0 = l2;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l1;
  i1 = 1048708u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l1;
  i1 = p0;
  i2 = 12u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l1;
  i1 = l1;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l1;
  _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
  i0 = l1;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN4wasm4main17h0fcb4ec8ced93f5dE(void) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  u64 l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 2400u;
  i0 -= i1;
  l0 = i0;
  g0 = i0;
  i0 = l0;
  i1 = 2064u;
  i0 += i1;
  l1 = i0;
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  l2 = i0;
  L0: 
    i0 = l2;
    i1 = 0u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l2;
    i1 = 4u;
    i0 += i1;
    i1 = 1049076u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l2;
    i1 = 8u;
    i0 += i1;
    l2 = i0;
    i1 = l1;
    i0 = i0 != i1;
    if (i0) {goto L0;}
  i0 = l0;
  i1 = 0u;
  i32_store16((&memory), (u64)(i0 + 2070), i1);
  i0 = l0;
  i1 = 2072u;
  i0 += i1;
  i1 = 0u;
  i2 = 256u;
  i0 = memset_0(i0, i1, i2);
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  l2 = i0;
  i0 = 1u;
  l3 = i0;
  L2: 
    i0 = l0;
    i1 = 1u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049616u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 3u;
    i32_store((&memory), (u64)(i0 + 2332), i1);
    i0 = l0;
    i1 = l3;
    i32_store((&memory), (u64)(i0 + 2344), i1);
    i0 = l0;
    i1 = l0;
    i2 = 2328u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    i1 = l0;
    i2 = 2344u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 2328), i1);
    i0 = l0;
    i1 = 2384u;
    i0 += i1;
    i1 = l0;
    i2 = 2360u;
    i1 += i2;
    _ZN5alloc3fmt6format17h791816ebd75606e6E(i0, i1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    l1 = i0;
    i0 = !(i0);
    if (i0) {goto B1;}
    i0 = l1;
    i1 = l0;
    j1 = i64_load((&memory), (u64)(i1 + 2384));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l1;
    i1 = 8u;
    i0 += i1;
    i1 = l0;
    i2 = 2384u;
    i1 += i2;
    i2 = 8u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l2;
    i1 = 4u;
    i0 += i1;
    i1 = 1049624u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l2;
    i1 = l1;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l2;
    i1 = 8u;
    i0 += i1;
    l2 = i0;
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    i1 = 11u;
    i0 = i0 != i1;
    if (i0) {goto L2;}
  i0 = l0;
  i1 = 2380u;
  i0 += i1;
  l2 = i0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = 1048760u;
  i32_store((&memory), (u64)(i0 + 2376), i1);
  i0 = l0;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 2364), j1);
  i0 = l0;
  i1 = 1049800u;
  i32_store((&memory), (u64)(i0 + 2360), i1);
  i0 = l0;
  i1 = 2360u;
  i0 += i1;
  _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = 1048760u;
  i32_store((&memory), (u64)(i0 + 2376), i1);
  i0 = l0;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 2364), j1);
  i0 = l0;
  i1 = 1050028u;
  i32_store((&memory), (u64)(i0 + 2360), i1);
  i0 = l0;
  i1 = 2360u;
  i0 += i1;
  _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = 1048760u;
  i32_store((&memory), (u64)(i0 + 2376), i1);
  i0 = l0;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 2364), j1);
  i0 = l0;
  i1 = 1050164u;
  i32_store((&memory), (u64)(i0 + 2360), i1);
  i0 = l0;
  i1 = 2360u;
  i0 += i1;
  _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
  i0 = l0;
  i1 = 2372u;
  i0 += i1;
  l4 = i0;
  i0 = 10u;
  l5 = i0;
  L3: 
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1048888u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1048916u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1048944u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1048968u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1048988u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049004u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    _ZN4wasm6prompt17h864234ab4d9bd9dcE();
    i0 = l0;
    i1 = _ZN3std2io5stdio5stdin17h6275b62513a72eaaE();
    i32_store((&memory), (u64)(i0 + 2344), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    i1 = l0;
    i2 = 2344u;
    i1 += i2;
    i2 = l0;
    i3 = 2070u;
    i2 += i3;
    i3 = 2u;
    _ZN55__LT_std__io__stdio__Stdin_u20_as_u20_std__io__Read_GT_4read17h43ce0ea6cf440e2eE(i0, i1, i2, i3);
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2360));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B13;}
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2344));
    l2 = i0;
    i1 = l2;
    i1 = i32_load((&memory), (u64)(i1));
    l2 = i1;
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l2;
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B14;}
    i0 = l0;
    i1 = 2344u;
    i0 += i1;
    _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h85e9c06ab818adc3E(i0);
    B14:;
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    i1 = l0;
    i2 = 2070u;
    i1 += i2;
    i2 = 2u;
    _ZN4core3str9from_utf817he6f02ee8cec749d4E(i0, i1, i2);
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2360));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B12;}
    i0 = l0;
    i1 = 8u;
    i0 += i1;
    i1 = l0;
    i1 = i32_load((&memory), (u64)(i1 + 2364));
    i2 = l0;
    i2 = i32_load((&memory), (u64)(i2 + 2368));
    _ZN4core3str21__LT_impl_u20_str_GT_4trim17h7b79618a50b556d3E(i0, i1, i2);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    i1 = l0;
    i1 = i32_load((&memory), (u64)(i1 + 8));
    i2 = l0;
    i2 = i32_load((&memory), (u64)(i2 + 12));
    _ZN4core3num52__LT_impl_u20_core__str__FromStr_u20_for_u20_i32_GT_8from_str17h24ec4dabfaea63f0E(i0, i1, i2);
    i0 = l0;
    i0 = i32_load8_u((&memory), (u64)(i0 + 2360));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B11;}
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2364));
    i1 = 4294967295u;
    i0 += i1;
    l2 = i0;
    i1 = 5u;
    i0 = i0 <= i1;
    if (i0) {goto B15;}
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1050220u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    goto L3;
    B15:;
    i0 = l2;
    switch (i0) {
      case 0: goto B21;
      case 1: goto B20;
      case 2: goto B19;
      case 3: goto B18;
      case 4: goto B17;
      case 5: goto B16;
      default: goto B21;
    }
    B21:;
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049048u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2336), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2328), j1);
    _ZN4wasm6prompt17h864234ab4d9bd9dcE();
    i0 = l0;
    i1 = _ZN3std2io5stdio5stdin17h6275b62513a72eaaE();
    i32_store((&memory), (u64)(i0 + 2344), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    i1 = l0;
    i2 = 2344u;
    i1 += i2;
    i2 = l0;
    i3 = 2328u;
    i2 += i3;
    _ZN3std2io5stdio5Stdin9read_line17h8f9a7008c4938aaaE(i0, i1, i2);
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2360));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B10;}
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2344));
    l2 = i0;
    i1 = l2;
    i1 = i32_load((&memory), (u64)(i1));
    l2 = i1;
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l2;
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B22;}
    i0 = l0;
    i1 = 2344u;
    i0 += i1;
    _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h85e9c06ab818adc3E(i0);
    B22:;
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    i1 = 8u;
    i0 += i1;
    l1 = i0;
    i1 = l0;
    i2 = 2328u;
    i1 += i2;
    i2 = 8u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l0;
    i1 = l0;
    j1 = i64_load((&memory), (u64)(i1 + 2328));
    i64_store((&memory), (u64)(i0 + 2360), j1);
    i0 = l0;
    j1 = 4294967300ull;
    i64_store((&memory), (u64)(i0 + 2344), j1);
    i0 = 4u;
    i1 = 1u;
    i0 = __rust_alloc(i0, i1);
    l2 = i0;
    i0 = !(i0);
    if (i0) {goto B9;}
    i0 = l0;
    j1 = 4ull;
    i64_store((&memory), (u64)(i0 + 2388), j1);
    i0 = l0;
    i1 = l2;
    i32_store((&memory), (u64)(i0 + 2384), i1);
    i0 = l0;
    i1 = 2384u;
    i0 += i1;
    i1 = 0u;
    i2 = 4u;
    _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_7reserve17h48301355d030439aE(i0, i1, i2);
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2384));
    i1 = l0;
    i1 = i32_load((&memory), (u64)(i1 + 2392));
    l2 = i1;
    i0 += i1;
    i1 = 4u;
    i2 = 1049072u;
    i3 = 4u;
    _ZN4core5slice29__LT_impl_u20__u5b_T_u5d__GT_15copy_from_slice17hdeeb8ec1d0ce5f8bE(i0, i1, i2, i3);
    i0 = l0;
    i1 = 2344u;
    i0 += i1;
    i1 = 8u;
    i0 += i1;
    i1 = l2;
    i2 = 4u;
    i1 += i2;
    l2 = i1;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l0;
    i1 = l0;
    j1 = i64_load((&memory), (u64)(i1 + 2384));
    l6 = j1;
    i64_store((&memory), (u64)(i0 + 2344), j1);
    i0 = l4;
    i1 = 8u;
    i0 += i1;
    i1 = l2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l4;
    j1 = l6;
    i64_store((&memory), (u64)(i0), j1);
    i0 = 24u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    l2 = i0;
    i0 = !(i0);
    if (i0) {goto B8;}
    i0 = l2;
    i1 = l0;
    j1 = i64_load((&memory), (u64)(i1 + 2360));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l2;
    i1 = 16u;
    i0 += i1;
    i1 = l0;
    i2 = 2360u;
    i1 += i2;
    i2 = 16u;
    i1 += i2;
    j1 = i64_load((&memory), (u64)(i1));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l2;
    i1 = 8u;
    i0 += i1;
    i1 = l1;
    j1 = i64_load((&memory), (u64)(i1));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l0;
    i1 = 16u;
    i0 += i1;
    i1 = l5;
    i2 = 255u;
    i1 &= i2;
    i2 = 3u;
    i1 <<= (i2 & 31);
    i0 += i1;
    l1 = i0;
    i1 = 1049076u;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l1;
    i1 = l2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049104u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l5;
    i1 = 1u;
    i0 += i1;
    l5 = i0;
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    goto L3;
    B20:;
    i0 = l5;
    i1 = 255u;
    i0 &= i1;
    l2 = i0;
    i1 = 10u;
    i0 = i0 > i1;
    if (i0) {goto B23;}
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049200u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    goto L3;
    B23:;
    i0 = l2;
    i1 = 3u;
    i0 <<= (i1 & 31);
    i1 = l0;
    i2 = 16u;
    i1 += i2;
    i0 += i1;
    i1 = 4294967288u;
    i0 += i1;
    l2 = i0;
    i1 = 1049076u;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l2;
    i1 = 0u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049104u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l5;
    i1 = 4294967295u;
    i0 += i1;
    l5 = i0;
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    goto L3;
    B19:;
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049248u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2352), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2344), j1);
    _ZN4wasm6prompt17h864234ab4d9bd9dcE();
    i0 = l0;
    i1 = _ZN3std2io5stdio5stdin17h6275b62513a72eaaE();
    i32_store((&memory), (u64)(i0 + 2328), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    i1 = l0;
    i2 = 2328u;
    i1 += i2;
    i2 = l0;
    i3 = 2344u;
    i2 += i3;
    _ZN3std2io5stdio5Stdin9read_line17h8f9a7008c4938aaaE(i0, i1, i2);
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2360));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B7;}
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2328));
    l2 = i0;
    i1 = l2;
    i1 = i32_load((&memory), (u64)(i1));
    l2 = i1;
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l2;
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B24;}
    i0 = l0;
    i1 = 2328u;
    i0 += i1;
    _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h85e9c06ab818adc3E(i0);
    B24:;
    i0 = l0;
    i1 = l0;
    i1 = i32_load((&memory), (u64)(i1 + 2344));
    i2 = l0;
    i2 = i32_load((&memory), (u64)(i2 + 2352));
    _ZN4core3str21__LT_impl_u20_str_GT_4trim17h7b79618a50b556d3E(i0, i1, i2);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    i1 = l0;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = l0;
    i2 = i32_load((&memory), (u64)(i2 + 4));
    _ZN4core3num52__LT_impl_u20_core__str__FromStr_u20_for_u20_u32_GT_8from_str17hee1e4ecf1e1de66dE(i0, i1, i2);
    i0 = l0;
    i0 = i32_load8_u((&memory), (u64)(i0 + 2360));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B6;}
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2364));
    l2 = i0;
    i1 = 255u;
    i0 = i0 > i1;
    if (i0) {goto B25;}
    i0 = l0;
    i1 = 16u;
    i0 += i1;
    i1 = l2;
    i2 = 3u;
    i1 <<= (i2 & 31);
    i0 += i1;
    l1 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l3 = i0;
    if (i0) {goto B26;}
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049360u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    goto B4;
    B26:;
    i0 = l0;
    i1 = 2384u;
    i0 += i1;
    i1 = l3;
    i2 = l1;
    i2 = i32_load((&memory), (u64)(i2 + 4));
    i2 = i32_load((&memory), (u64)(i2 + 12));
    CALL_INDIRECT(T0, void (*)(u32, u32), 1, i2, i0, i1);
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2392));
    l1 = i0;
    i0 = l2;
    i1 = 10u;
    i0 = i0 < i1;
    if (i0) {goto B28;}
    i0 = l1;
    i1 = 256u;
    i0 = i0 > i1;
    if (i0) {goto B27;}
    B28:;
    i0 = l0;
    i1 = 2072u;
    i0 += i1;
    i1 = l0;
    i1 = i32_load((&memory), (u64)(i1 + 2384));
    l2 = i1;
    i2 = l1;
    i0 = memcpy_0(i0, i1, i2);
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2388));
    l1 = i0;
    i0 = !(i0);
    if (i0) {goto B4;}
    i0 = l2;
    i1 = l1;
    i2 = 1u;
    __rust_dealloc(i0, i1, i2);
    goto B4;
    B27:;
    i0 = l0;
    i1 = 2380u;
    i0 += i1;
    i1 = 0u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049336u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    i0 = 0u;
    _ZN3std7process4exit17h15172f2c8741ba8bE(i0);
    UNREACHABLE;
    B25:;
    i0 = l2;
    i1 = 256u;
    i2 = 1049304u;
    _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
    UNREACHABLE;
    B18:;
    i0 = 0u;
    l2 = i0;
    L29: 
      i0 = l0;
      i1 = 16u;
      i0 += i1;
      i1 = l2;
      i0 += i1;
      l1 = i0;
      i0 = i32_load((&memory), (u64)(i0));
      l3 = i0;
      i0 = !(i0);
      if (i0) {goto L3;}
      i0 = l3;
      i1 = l1;
      i2 = 4u;
      i1 += i2;
      i1 = i32_load((&memory), (u64)(i1));
      i1 = i32_load((&memory), (u64)(i1 + 16));
      CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
      i0 = l2;
      i1 = 8u;
      i0 += i1;
      l2 = i0;
      i1 = 2048u;
      i0 = i0 != i1;
      if (i0) {goto L29;}
    i0 = 256u;
    i1 = 256u;
    i2 = 1049368u;
    _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
    UNREACHABLE;
    B17:;
    i0 = l0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049420u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    i0 = l0;
    i1 = 2384u;
    i0 += i1;
    i1 = l0;
    i2 = 2072u;
    i1 += i2;
    i2 = 256u;
    _ZN4core3str9from_utf817he6f02ee8cec749d4E(i0, i1, i2);
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2384));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B5;}
    i0 = l0;
    i1 = l0;
    j1 = i64_load((&memory), (u64)(i1 + 2388));
    i64_store((&memory), (u64)(i0 + 2344), j1);
    i0 = l0;
    i1 = 4u;
    i32_store((&memory), (u64)(i0 + 2332), i1);
    i0 = l0;
    i1 = 1u;
    i32_store((&memory), (u64)(i0 + 2380), i1);
    i0 = l0;
    j1 = 2ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1049428u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = l0;
    i2 = 2344u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 2328), i1);
    i0 = l0;
    i1 = l0;
    i2 = 2328u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    goto L3;
    B16:;
    i0 = l0;
    i1 = 2380u;
    i0 += i1;
    i1 = 0u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l0;
    i1 = 1048760u;
    i32_store((&memory), (u64)(i0 + 2376), i1);
    i0 = l0;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 2364), j1);
    i0 = l0;
    i1 = 1050236u;
    i32_store((&memory), (u64)(i0 + 2360), i1);
    i0 = l0;
    i1 = 2360u;
    i0 += i1;
    _ZN3std2io5stdio6_print17hc41bda27e6084072E(i0);
    i0 = 0u;
    _ZN3std7process4exit17h15172f2c8741ba8bE(i0);
    UNREACHABLE;
    B13:;
    i0 = l0;
    i1 = l0;
    j1 = i64_load((&memory), (u64)(i1 + 2364));
    i64_store((&memory), (u64)(i0 + 2384), j1);
    i0 = 1048824u;
    i1 = 21u;
    i2 = l0;
    i3 = 2384u;
    i2 += i3;
    i3 = 1048576u;
    i4 = 1050172u;
    _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
    UNREACHABLE;
    B12:;
    i0 = l0;
    i1 = l0;
    j1 = i64_load((&memory), (u64)(i1 + 2364));
    i64_store((&memory), (u64)(i0 + 2384), j1);
    i0 = 1048608u;
    i1 = 43u;
    i2 = l0;
    i3 = 2384u;
    i2 += i3;
    i3 = 1048652u;
    i4 = 1050188u;
    _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
    UNREACHABLE;
    B11:;
    i0 = l0;
    i1 = l0;
    i1 = i32_load8_u((&memory), (u64)(i1 + 2361));
    i32_store8((&memory), (u64)(i0 + 2384), i1);
    i0 = 1049272u;
    i1 = 13u;
    i2 = l0;
    i3 = 2384u;
    i2 += i3;
    i3 = 1048592u;
    i4 = 1050188u;
    _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
    UNREACHABLE;
    B10:;
    i0 = l0;
    i1 = l0;
    j1 = i64_load((&memory), (u64)(i1 + 2364));
    i64_store((&memory), (u64)(i0 + 2384), j1);
    i0 = 1048824u;
    i1 = 21u;
    i2 = l0;
    i3 = 2384u;
    i2 += i3;
    i3 = 1048576u;
    i4 = 1049056u;
    _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
    UNREACHABLE;
    B9:;
    i0 = l0;
    i1 = 2344u;
    i0 += i1;
    _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h6cc9081211f3042fE_llvm_3493317965437833058(i0);
    UNREACHABLE;
    B8:;
    i0 = 24u;
    i1 = 4u;
    _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
    UNREACHABLE;
    B7:;
    i0 = l0;
    i1 = l0;
    j1 = i64_load((&memory), (u64)(i1 + 2364));
    i64_store((&memory), (u64)(i0 + 2384), j1);
    i0 = 1048824u;
    i1 = 21u;
    i2 = l0;
    i3 = 2384u;
    i2 += i3;
    i3 = 1048576u;
    i4 = 1049256u;
    _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
    UNREACHABLE;
    B6:;
    i0 = l0;
    i1 = l0;
    i1 = i32_load8_u((&memory), (u64)(i1 + 2361));
    i32_store8((&memory), (u64)(i0 + 2384), i1);
    i0 = 1049272u;
    i1 = 13u;
    i2 = l0;
    i3 = 2384u;
    i2 += i3;
    i3 = 1048592u;
    i4 = 1049288u;
    _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
    UNREACHABLE;
    B5:;
    i0 = l0;
    i1 = l0;
    j1 = i64_load((&memory), (u64)(i1 + 2388));
    i64_store((&memory), (u64)(i0 + 2360), j1);
    i0 = 1048608u;
    i1 = 43u;
    i2 = l0;
    i3 = 2360u;
    i2 += i3;
    i3 = 1048652u;
    i4 = 1049444u;
    _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
    UNREACHABLE;
    B4:;
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2348));
    l2 = i0;
    i0 = !(i0);
    if (i0) {goto L3;}
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 2344));
    i1 = l2;
    i2 = 1u;
    __rust_dealloc(i0, i1, i2);
    goto L3;
  B1:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 __original_main(void) {
  u32 l0 = 0, l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l0 = i0;
  g0 = i0;
  i0 = l0;
  i1 = 5u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l0;
  i1 = 12u;
  i0 += i1;
  i1 = 1050284u;
  i2 = 0u;
  i3 = 0u;
  i0 = _ZN3std2rt19lang_start_internal17h66de5b0ec01e6d33E(i0, i1, i2, i3);
  l1 = i0;
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = l1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 main(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = __original_main();
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h5e91b6421c7b45c3E_llvm_3493317965437833058(void) {
  FUNC_PROLOGUE;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h6cc9081211f3042fE_llvm_3493317965437833058(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_7reserve17h48301355d030439aE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i1 = p1;
  i0 -= i1;
  i1 = p2;
  i0 = i0 >= i1;
  if (i0) {goto B0;}
  i0 = p1;
  i1 = p2;
  i0 += i1;
  p2 = i0;
  i1 = p1;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l3;
  i1 = 1u;
  i0 <<= (i1 & 31);
  p1 = i0;
  i1 = p2;
  i2 = p1;
  i3 = p2;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  p1 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B4;}
  i0 = l3;
  if (i0) {goto B5;}
  i0 = p1;
  if (i0) {goto B3;}
  i0 = 1u;
  p2 = i0;
  goto B1;
  B5:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p2 = i0;
  i0 = l3;
  i1 = p1;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = p2;
  i1 = l3;
  i2 = 1u;
  i3 = p1;
  i0 = __rust_realloc(i0, i1, i2, i3);
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  goto B1;
  B4:;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  B3:;
  i0 = p1;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  p2 = i0;
  if (i0) {goto B1;}
  B2:;
  i0 = p1;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  B0:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17hd3f3959f4c97243cE(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l1;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  FUNC_EPILOGUE;
}

static void _ZN50__LT_T_u20_as_u20_core__convert__Into_LT_U_GT__GT_4into17h983ad7f08df26d1eE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = p1;
  i2 = p2;
  _ZN5alloc5slice64__LT_impl_u20_alloc__borrow__ToOwned_u20_for_u20__u5b_T_u5d__GT_8to_owned17hcbfede6e87b73bf8E(i0, i1, i2);
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  p2 = i0;
  i1 = l3;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p1 = i0;
  if (i0) {goto B0;}
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = p1;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 16));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 1050244u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN3std5error5Error5cause17h42b6be22af74ab4cE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static u64 _ZN3std5error5Error7type_id17hd7db71e5437d290fE(u32 p0) {
  FUNC_PROLOGUE;
  u64 j0;
  j0 = 5771058436666545696ull;
  FUNC_EPILOGUE;
  return j0;
}

static u32 _ZN3std5error5Error9backtrace17hb542ab28ea02206fE(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = 0u;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN3std2rt10lang_start28__u7b__u7b_closure_u7d__u7d_17h38b7bbbd60866851E(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  CALL_INDIRECT(T0, void (*)(void), 2, i0);
  i0 = l1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 15), i1);
  i0 = l1;
  i1 = 15u;
  i0 += i1;
  i0 = _ZN3std3sys4wasi7process8ExitCode6as_i3217h363ebb260b4f8711E(i0);
  p0 = i0;
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h1734dabf5e32b98aE(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  CALL_INDIRECT(T0, void (*)(void), 2, i0);
  i0 = l1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 15), i1);
  i0 = l1;
  i1 = 15u;
  i0 += i1;
  i0 = _ZN3std3sys4wasi7process8ExitCode6as_i3217h363ebb260b4f8711E(i0);
  p0 = i0;
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3ptr13drop_in_place17h8527075be1a03755E(u32 p0) {
  FUNC_PROLOGUE;
  FUNC_EPILOGUE;
}

static void _ZN5alloc5slice64__LT_impl_u20_alloc__borrow__ToOwned_u20_for_u20__u5b_T_u5d__GT_8to_owned17hcbfede6e87b73bf8E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = 1u;
  l4 = i0;
  i0 = l3;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l3;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = p2;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B1;}
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p2;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  B2:;
  i0 = l3;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l3;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l3;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = 0u;
  i2 = p2;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_7reserve17h48301355d030439aE(i0, i1, i2);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1 + 16));
  l4 = i1;
  i0 += i1;
  i1 = p2;
  i2 = p1;
  i3 = p2;
  _ZN4core5slice29__LT_impl_u20__u5b_T_u5d__GT_15copy_from_slice17hdeeb8ec1d0ce5f8bE(i0, i1, i2, i3);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i2 = p2;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B1:;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h5e91b6421c7b45c3E_llvm_3493317965437833058();
  UNREACHABLE;
  B0:;
  i0 = l3;
  i1 = 24u;
  i0 += i1;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h6cc9081211f3042fE_llvm_3493317965437833058(i0);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN3std2io16append_to_string17h5b76cd210b0a5cd8E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1, j2;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  l4 = i1;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  i0 = l3;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  i1 = 4u;
  i0 |= i1;
  l6 = i0;
  i0 = l4;
  l7 = i0;
  i0 = l4;
  p2 = i0;
  L3: 
    i0 = p2;
    i1 = l7;
    i0 = i0 == i1;
    if (i0) {goto B5;}
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    l7 = i0;
    goto B4;
    B5:;
    i0 = p1;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1 + 8));
    i2 = 32u;
    _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_7reserve17h48301355d030439aE(i0, i1, i2);
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    p1 = i0;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    l7 = i1;
    i32_store((&memory), (u64)(i0 + 8), i1);
    i0 = l7;
    i1 = l3;
    i1 = i32_load((&memory), (u64)(i1 + 28));
    p2 = i1;
    i0 = i0 < i1;
    if (i0) {goto B2;}
    B4:;
    i0 = l7;
    i1 = p2;
    i0 = i0 < i1;
    if (i0) {goto B1;}
    i0 = l3;
    i1 = 32u;
    i0 += i1;
    i1 = l5;
    i2 = p1;
    i2 = i32_load((&memory), (u64)(i2));
    i3 = p2;
    i2 += i3;
    i3 = l7;
    i4 = p2;
    i3 -= i4;
    _ZN47__LT_std__fs__File_u20_as_u20_std__io__Read_GT_4read17h1f42a62b4fce9d8aE(i0, i1, i2, i3);
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 32));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B7;}
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 36));
    p1 = i0;
    if (i0) {goto B8;}
    i0 = p2;
    i1 = l4;
    i0 -= i1;
    l6 = i0;
    i0 = 0u;
    l7 = i0;
    goto B0;
    B8:;
    i0 = l3;
    i1 = p1;
    i2 = p2;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 28), i1);
    goto B6;
    B7:;
    i0 = l6;
    i0 = _ZN3std2io5error5Error4kind17hdcfd08845a3d8932E(i0);
    i1 = 255u;
    i0 &= i1;
    i1 = 15u;
    i0 = i0 == i1;
    if (i0) {goto B9;}
    i0 = 1u;
    l7 = i0;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 40));
    l4 = i0;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 36));
    l6 = i0;
    goto B0;
    B9:;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 32));
    i0 = !(i0);
    if (i0) {goto B6;}
    i0 = l3;
    i0 = i32_load8_u((&memory), (u64)(i0 + 36));
    i1 = 255u;
    i0 &= i1;
    i1 = 2u;
    i0 = i0 < i1;
    if (i0) {goto B6;}
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 40));
    p2 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = p2;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i1 = i32_load((&memory), (u64)(i1));
    CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
    i0 = p2;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    p1 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l7 = i0;
    i0 = !(i0);
    if (i0) {goto B10;}
    i0 = p2;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l7;
    i2 = p1;
    i2 = i32_load((&memory), (u64)(i2 + 8));
    __rust_dealloc(i0, i1, i2);
    B10:;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 40));
    i1 = 12u;
    i2 = 4u;
    __rust_dealloc(i0, i1, i2);
    B6:;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    p1 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    l7 = i0;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 28));
    p2 = i0;
    goto L3;
  B2:;
  i0 = p2;
  i1 = l7;
  i2 = 1050428u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = p2;
  i1 = l7;
  i2 = 1050444u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l3;
  i1 = 24u;
  i0 += i1;
  _ZN56__LT_std__io__Guard_u20_as_u20_core__ops__drop__Drop_GT_4drop17h7f4cce983b4a506eE(i0);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l5 = i0;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  p2 = i1;
  i0 = i0 < i1;
  if (i0) {goto B11;}
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p2;
  i1 += i2;
  i2 = l5;
  i3 = p2;
  i2 -= i3;
  _ZN4core3str9from_utf817he6f02ee8cec749d4E(i0, i1, i2);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 32));
  if (i0) {goto B13;}
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l7;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i32_store((&memory), (u64)(i0 + 20), i1);
  goto B12;
  B13:;
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B15;}
  i0 = p0;
  i1 = l4;
  j1 = (u64)(i1);
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i2 = l6;
  j2 = (u64)(i2);
  j1 |= j2;
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B14;
  B15:;
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = 1050392u;
  i2 = 34u;
  _ZN50__LT_T_u20_as_u20_core__convert__Into_LT_U_GT__GT_4into17h983ad7f08df26d1eE(i0, i1, i2);
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  i1 = 12u;
  i2 = l3;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  i3 = l3;
  i3 = i32_load((&memory), (u64)(i3 + 12));
  _ZN3std2io5error5Error4_new17h276c50b6edbce93bE(i0, i1, i2, i3);
  i0 = p0;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 32));
  i64_store((&memory), (u64)(i0 + 4), j1);
  B14:;
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  B12:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  _ZN56__LT_std__io__Guard_u20_as_u20_core__ops__drop__Drop_GT_4drop17h7f4cce983b4a506eE(i0);
  i0 = l3;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B11:;
  i0 = p2;
  i1 = l5;
  i2 = 1050376u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN4core5slice29__LT_impl_u20__u5b_T_u5d__GT_15copy_from_slice17hdeeb8ec1d0ce5f8bE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 96u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = l4;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p1;
  i1 = p3;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = p2;
  i2 = p1;
  i0 = memcpy_0(i0, i1, i2);
  i0 = l4;
  i1 = 96u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B0:;
  i0 = l4;
  i1 = 40u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 27u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 52u;
  i0 += i1;
  i1 = 28u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l4;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 64), i1);
  i0 = l4;
  i1 = l4;
  i2 = 12u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 68), i1);
  i0 = l4;
  i1 = 72u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  j1 = 3ull;
  i64_store((&memory), (u64)(i0 + 20), j1);
  i0 = l4;
  i1 = 1050520u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l4;
  i1 = 28u;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l4;
  i1 = 1050604u;
  i32_store((&memory), (u64)(i0 + 88), i1);
  i0 = l4;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 76), j1);
  i0 = l4;
  i1 = 1050596u;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l4;
  i1 = l4;
  i2 = 40u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l4;
  i1 = l4;
  i2 = 72u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l4;
  i1 = l4;
  i2 = 68u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l4;
  i1 = l4;
  i2 = 64u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = 1050680u;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN79__LT_std__io__buffered__BufWriter_LT_W_GT__u20_as_u20_core__ops__drop__Drop_GT_4drop17h35eae9ee9f99cf1eE(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l8 = 0, l9 = 0;
  u64 l7 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 12));
  i1 = 2u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 13));
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  l3 = i0;
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l1;
  i1 = 8u;
  i0 += i1;
  i1 = 4u;
  i0 |= i1;
  l4 = i0;
  i0 = 0u;
  l5 = i0;
  i0 = l2;
  l6 = i0;
  L5: 
    i0 = l1;
    i1 = 8u;
    i0 += i1;
    i1 = l3;
    i2 = p0;
    i2 = i32_load((&memory), (u64)(i2));
    i3 = l5;
    i2 += i3;
    i3 = l6;
    i4 = l5;
    i3 -= i4;
    _ZN65__LT_std__io__stdio__Maybe_LT_W_GT__u20_as_u20_std__io__Write_GT_5write17h635a424e4604ada3E(i0, i1, i2, i3);
    i0 = p0;
    i1 = 0u;
    i32_store8((&memory), (u64)(i0 + 13), i1);
    i0 = l1;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B7;}
    i0 = l1;
    i0 = i32_load((&memory), (u64)(i0 + 12));
    l6 = i0;
    if (i0) {goto B8;}
    i0 = l1;
    i1 = 1050804u;
    i2 = 33u;
    _ZN50__LT_T_u20_as_u20_core__convert__Into_LT_U_GT__GT_4into17h983ad7f08df26d1eE(i0, i1, i2);
    i0 = l1;
    i1 = 24u;
    i0 += i1;
    i1 = 14u;
    i2 = l1;
    i2 = i32_load((&memory), (u64)(i2));
    i3 = l1;
    i3 = i32_load((&memory), (u64)(i3 + 4));
    _ZN3std2io5error5Error4_new17h276c50b6edbce93bE(i0, i1, i2, i3);
    i0 = l1;
    j0 = i64_load((&memory), (u64)(i0 + 24));
    l7 = j0;
    goto B3;
    B8:;
    i0 = l6;
    i1 = l5;
    i0 += i1;
    l5 = i0;
    goto B6;
    B7:;
    i0 = l4;
    i0 = _ZN3std2io5error5Error4kind17hdcfd08845a3d8932E(i0);
    i1 = 255u;
    i0 &= i1;
    i1 = 15u;
    i0 = i0 == i1;
    if (i0) {goto B9;}
    i0 = l1;
    j0 = i64_load((&memory), (u64)(i0 + 12));
    l7 = j0;
    goto B3;
    B9:;
    i0 = l1;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    i0 = !(i0);
    if (i0) {goto B6;}
    i0 = l1;
    i0 = i32_load8_u((&memory), (u64)(i0 + 12));
    i1 = 255u;
    i0 &= i1;
    i1 = 2u;
    i0 = i0 < i1;
    if (i0) {goto B6;}
    i0 = l1;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    l6 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l6;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i1 = i32_load((&memory), (u64)(i1));
    CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
    i0 = l6;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l8 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l9 = i0;
    i0 = !(i0);
    if (i0) {goto B10;}
    i0 = l6;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l9;
    i2 = l8;
    i2 = i32_load((&memory), (u64)(i2 + 8));
    __rust_dealloc(i0, i1, i2);
    B10:;
    i0 = l1;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    i1 = 12u;
    i2 = 4u;
    __rust_dealloc(i0, i1, i2);
    B6:;
    i0 = l5;
    i1 = l2;
    i0 = i0 < i1;
    if (i0) {goto B11;}
    i0 = 3u;
    l2 = i0;
    goto B2;
    B11:;
    i0 = p0;
    i1 = 1u;
    i32_store8((&memory), (u64)(i0 + 13), i1);
    i0 = p0;
    i0 = i32_load8_u((&memory), (u64)(i0 + 12));
    i1 = 2u;
    i0 = i0 == i1;
    if (i0) {goto B4;}
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    l6 = i0;
    i1 = l5;
    i0 = i0 >= i1;
    if (i0) {goto L5;}
  i0 = l5;
  i1 = l6;
  i2 = 1050788u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B4:;
  i0 = 1050837u;
  i1 = 43u;
  i2 = 1050772u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B3:;
  j0 = l7;
  j1 = 32ull;
  j0 >>= (j1 & 63);
  i0 = (u32)(j0);
  l6 = i0;
  j0 = l7;
  i0 = (u32)(j0);
  l2 = i0;
  B2:;
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l3 = i0;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = l5;
  i0 -= i1;
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i1 = l4;
  i2 = l5;
  i1 += i2;
  i2 = l3;
  i0 = memmove_0(i0, i1, i2);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 8), i1);
  B12:;
  i0 = 0u;
  if (i0) {goto B13;}
  i0 = l2;
  i1 = 3u;
  i0 &= i1;
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  B13:;
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B14;}
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B14:;
  i0 = l6;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  i0 = l1;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B0:;
  i0 = l5;
  i1 = l3;
  _ZN5alloc3vec12Vec_LT_T_GT_5drain17end_assert_failed17hccc4a24f1f7369a6E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h85e9c06ab818adc3E(u32 p0) {
  u32 l1 = 0, l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 1u;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  i0 = l1;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  l1 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l1;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 36u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  FUNC_EPILOGUE;
}

static void _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17hf62bca0551a53043E(u32 p0) {
  u32 l1 = 0, l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i1 = 8u;
  i0 += i1;
  _ZN3std3sys4wasi5mutex14ReentrantMutex6unlock17h57b66397f140f523E(i0);
  i0 = l1;
  i1 = 12u;
  i0 += i1;
  l2 = i0;
  _ZN79__LT_std__io__buffered__BufWriter_LT_W_GT__u20_as_u20_core__ops__drop__Drop_GT_4drop17h35eae9ee9f99cf1eE(i0);
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l1;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  l1 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l1;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 32u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  FUNC_EPILOGUE;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17he7c55c53190843baE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = p1;
  i0 = _ZN4core3fmt9Formatter15debug_lower_hex17h613d71a0ae3bc060E(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i0 = _ZN4core3fmt9Formatter15debug_upper_hex17h5c3e903ff5236763E(i0);
  if (i0) {goto B1;}
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num3imp52__LT_impl_u20_core__fmt__Display_u20_for_u20_u32_GT_3fmt17haffb72d949b13748E(i0, i1);
  goto Bfunc;
  B1:;
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num53__LT_impl_u20_core__fmt__UpperHex_u20_for_u20_i32_GT_3fmt17hac44606703ee1b92E(i0, i1);
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num53__LT_impl_u20_core__fmt__LowerHex_u20_for_u20_i32_GT_3fmt17h4b124e18148b69c3E(i0, i1);
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17h017dd7820235afadE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = p1;
  i0 = _ZN42__LT_str_u20_as_u20_core__fmt__Display_GT_3fmt17h503be603f26e92cbE(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17hc62cda27386bedf7E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = p1;
  i0 = _ZN42__LT_str_u20_as_u20_core__fmt__Display_GT_3fmt17h503be603f26e92cbE(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN65__LT_std__io__stdio__Maybe_LT_W_GT__u20_as_u20_std__io__Write_GT_5write17h635a424e4604ada3E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B0;
  B1:;
  i0 = l4;
  i1 = p1;
  i2 = 1u;
  i1 += i2;
  i2 = p2;
  i3 = p3;
  _ZN60__LT_std__io__stdio__StdoutRaw_u20_as_u20_std__io__Write_GT_5write17h6c80cfd177b83762E(i0, i1, i2, i3);
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B2;}
  i0 = l4;
  i1 = 4u;
  i0 |= i1;
  i0 = _ZN3std3sys4wasi5stdio8is_ebadf17h866f32eebed413cfE(i0);
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l4;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  i1 = 2u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = l4;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p3 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p3;
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  goto B0;
  B2:;
  i0 = p0;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  B0:;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 __rust_alloc(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p1;
  i0 = __rdl_alloc(i0, i1);
  l2 = i0;
  i0 = l2;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void __rust_dealloc(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i1 = p1;
  i2 = p2;
  __rdl_dealloc(i0, i1, i2);
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 __rust_realloc(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i1 = p1;
  i2 = p2;
  i3 = p3;
  i0 = __rdl_realloc(i0, i1, i2, i3);
  l4 = i0;
  i0 = l4;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN109__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_alloc__vec__SpecExtend_LT__RF_T_C_core__slice__Iter_LT_T_GT__GT__GT_11spec_extend17hce2eec127ad34cc7E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l4 = i1;
  i0 -= i1;
  i1 = p2;
  i2 = p1;
  i1 -= i2;
  p2 = i1;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  goto B0;
  B1:;
  i0 = l4;
  i1 = p2;
  i0 += i1;
  l5 = i0;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B5;}
  i0 = l3;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l6 = i0;
  i1 = l5;
  i2 = l6;
  i3 = l5;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l6 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B5;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  if (i0) {goto B6;}
  B7:;
  i0 = l6;
  if (i0) {goto B4;}
  i0 = 1u;
  l5 = i0;
  goto B2;
  B6:;
  i0 = l3;
  i1 = l6;
  i0 = i0 == i1;
  if (i0) {goto B8;}
  i0 = l5;
  i1 = l3;
  i2 = 1u;
  i3 = l6;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l5 = i0;
  B8:;
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  goto B2;
  B5:;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  B4:;
  i0 = l6;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l5 = i0;
  if (i0) {goto B2;}
  B3:;
  i0 = l6;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B2:;
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  B0:;
  i0 = l5;
  i1 = l4;
  i0 += i1;
  i1 = p1;
  i2 = p2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i2 = p2;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static u64 _ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h0190c02ab65d56acE(u32 p0) {
  FUNC_PROLOGUE;
  u64 j0;
  j0 = 10536124946013174407ull;
  FUNC_EPILOGUE;
  return j0;
}

static u64 _ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h029516de738f74ddE(u32 p0) {
  FUNC_PROLOGUE;
  u64 j0;
  j0 = 12613753443797613946ull;
  FUNC_EPILOGUE;
  return j0;
}

static u64 _ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h1036ec8cc0ac4000E(u32 p0) {
  FUNC_PROLOGUE;
  u64 j0;
  j0 = 1229646359891580772ull;
  FUNC_EPILOGUE;
  return j0;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h0154d9e42860dd53E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = p1;
  i0 = _ZN4core3fmt9Formatter15debug_lower_hex17h613d71a0ae3bc060E(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i0 = _ZN4core3fmt9Formatter15debug_upper_hex17h5c3e903ff5236763E(i0);
  if (i0) {goto B1;}
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num3imp52__LT_impl_u20_core__fmt__Display_u20_for_u20_u32_GT_3fmt17haffb72d949b13748E(i0, i1);
  goto Bfunc;
  B1:;
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num53__LT_impl_u20_core__fmt__UpperHex_u20_for_u20_i32_GT_3fmt17hac44606703ee1b92E(i0, i1);
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num53__LT_impl_u20_core__fmt__LowerHex_u20_for_u20_i32_GT_3fmt17h4b124e18148b69c3E(i0, i1);
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN73__LT_std__sys_common__os_str_bytes__Slice_u20_as_u20_core__fmt__Debug_GT_3fmt17h48c636194360662dE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, 
      l11 = 0;
  u64 l12 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j0, j1;
  i0 = g0;
  i1 = 80u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = 1u;
  l4 = i0;
  i0 = p2;
  i1 = 1051900u;
  i2 = 1u;
  i0 = _ZN4core3fmt9Formatter9write_str17h3d77f3190807e699E(i0, i1, i2);
  if (i0) {goto B0;}
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i2 = p1;
  _ZN4core3str5lossy9Utf8Lossy10from_bytes17h1fc730ab18994b0dE(i0, i1, i2);
  i0 = l3;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i2 = l3;
  i2 = i32_load((&memory), (u64)(i2 + 12));
  _ZN4core3str5lossy9Utf8Lossy6chunks17ha62e90201a5f69d8E(i0, i1, i2);
  i0 = l3;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = l3;
  i1 = 40u;
  i0 += i1;
  i1 = l3;
  i2 = 16u;
  i1 += i2;
  _ZN96__LT_core__str__lossy__Utf8LossyChunksIter_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17he3cf0b2f3c5f8b4eE(i0, i1);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 40));
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l3;
  i1 = 48u;
  i0 += i1;
  l5 = i0;
  i0 = l3;
  i1 = 64u;
  i0 += i1;
  l6 = i0;
  L2: 
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 52));
    l7 = i0;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 48));
    l8 = i0;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 44));
    p0 = i0;
    i0 = l3;
    i1 = 4u;
    i32_store((&memory), (u64)(i0 + 64), i1);
    i0 = l3;
    i1 = 4u;
    i32_store((&memory), (u64)(i0 + 48), i1);
    i0 = l3;
    i1 = l4;
    i32_store((&memory), (u64)(i0 + 40), i1);
    i0 = l3;
    i1 = l4;
    i2 = p0;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 44), i1);
    i0 = 4u;
    l4 = i0;
    L4: 
      i0 = l4;
      i1 = 4u;
      i0 = i0 == i1;
      if (i0) {goto B17;}
      i0 = l5;
      i0 = _ZN82__LT_core__char__EscapeDebug_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17h31831fc6cb32f772E(i0);
      l4 = i0;
      i1 = 1114112u;
      i0 = i0 != i1;
      if (i0) {goto B16;}
      i0 = l3;
      i1 = 4u;
      i32_store((&memory), (u64)(i0 + 48), i1);
      B17:;
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 44));
      p0 = i0;
      i1 = l3;
      i1 = i32_load((&memory), (u64)(i1 + 40));
      l4 = i1;
      i0 = i0 == i1;
      if (i0) {goto B18;}
      i0 = l3;
      i1 = l4;
      i2 = 1u;
      i1 += i2;
      l9 = i1;
      i32_store((&memory), (u64)(i0 + 40), i1);
      i0 = l4;
      i0 = i32_load8_s((&memory), (u64)(i0));
      p1 = i0;
      i1 = 4294967295u;
      i0 = (u32)((s32)i0 <= (s32)i1);
      if (i0) {goto B20;}
      i0 = p1;
      i1 = 255u;
      i0 &= i1;
      p0 = i0;
      goto B19;
      B20:;
      i0 = l9;
      i1 = p0;
      i0 = i0 != i1;
      if (i0) {goto B22;}
      i0 = 0u;
      l4 = i0;
      i0 = p0;
      l9 = i0;
      goto B21;
      B22:;
      i0 = l3;
      i1 = l4;
      i2 = 2u;
      i1 += i2;
      l9 = i1;
      i32_store((&memory), (u64)(i0 + 40), i1);
      i0 = l4;
      i0 = i32_load8_u((&memory), (u64)(i0 + 1));
      i1 = 63u;
      i0 &= i1;
      l4 = i0;
      B21:;
      i0 = p1;
      i1 = 31u;
      i0 &= i1;
      l10 = i0;
      i0 = p1;
      i1 = 255u;
      i0 &= i1;
      p1 = i0;
      i1 = 223u;
      i0 = i0 > i1;
      if (i0) {goto B23;}
      i0 = l4;
      i1 = l10;
      i2 = 6u;
      i1 <<= (i2 & 31);
      i0 |= i1;
      p0 = i0;
      goto B19;
      B23:;
      i0 = l9;
      i1 = p0;
      i0 = i0 != i1;
      if (i0) {goto B25;}
      i0 = 0u;
      l9 = i0;
      i0 = p0;
      l11 = i0;
      goto B24;
      B25:;
      i0 = l3;
      i1 = l9;
      i2 = 1u;
      i1 += i2;
      l11 = i1;
      i32_store((&memory), (u64)(i0 + 40), i1);
      i0 = l9;
      i0 = i32_load8_u((&memory), (u64)(i0));
      i1 = 63u;
      i0 &= i1;
      l9 = i0;
      B24:;
      i0 = l9;
      i1 = l4;
      i2 = 6u;
      i1 <<= (i2 & 31);
      i0 |= i1;
      l4 = i0;
      i0 = p1;
      i1 = 240u;
      i0 = i0 >= i1;
      if (i0) {goto B26;}
      i0 = l4;
      i1 = l10;
      i2 = 12u;
      i1 <<= (i2 & 31);
      i0 |= i1;
      p0 = i0;
      goto B19;
      B26:;
      i0 = l11;
      i1 = p0;
      i0 = i0 != i1;
      if (i0) {goto B28;}
      i0 = 0u;
      p0 = i0;
      goto B27;
      B28:;
      i0 = l3;
      i1 = l11;
      i2 = 1u;
      i1 += i2;
      i32_store((&memory), (u64)(i0 + 40), i1);
      i0 = l11;
      i0 = i32_load8_u((&memory), (u64)(i0));
      i1 = 63u;
      i0 &= i1;
      p0 = i0;
      B27:;
      i0 = l4;
      i1 = 6u;
      i0 <<= (i1 & 31);
      i1 = l10;
      i2 = 18u;
      i1 <<= (i2 & 31);
      i2 = 1835008u;
      i1 &= i2;
      i0 |= i1;
      i1 = p0;
      i0 |= i1;
      p0 = i0;
      B19:;
      i0 = 2u;
      l4 = i0;
      i0 = p0;
      i1 = 4294967287u;
      i0 += i1;
      l9 = i0;
      i1 = 30u;
      i0 = i0 <= i1;
      if (i0) {goto B13;}
      i0 = p0;
      i1 = 92u;
      i0 = i0 == i1;
      if (i0) {goto B11;}
      i0 = p0;
      i1 = 1114112u;
      i0 = i0 != i1;
      if (i0) {goto B12;}
      B18:;
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 64));
      i1 = 4u;
      i0 = i0 == i1;
      if (i0) {goto B15;}
      i0 = l6;
      i0 = _ZN82__LT_core__char__EscapeDebug_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17h31831fc6cb32f772E(i0);
      l4 = i0;
      i1 = 1114112u;
      i0 = i0 == i1;
      if (i0) {goto B15;}
      B16:;
      i0 = p2;
      i1 = l4;
      i0 = _ZN57__LT_core__fmt__Formatter_u20_as_u20_core__fmt__Write_GT_10write_char17h22afcca50c7c4efdE(i0, i1);
      if (i0) {goto B14;}
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 48));
      l4 = i0;
      goto L4;
      B15:;
      L29: 
        i0 = l7;
        i0 = !(i0);
        if (i0) {goto B3;}
        i0 = l3;
        i1 = l8;
        i32_store((&memory), (u64)(i0 + 28), i1);
        i0 = l3;
        i1 = 1u;
        i32_store((&memory), (u64)(i0 + 60), i1);
        i0 = l3;
        i1 = 1u;
        i32_store((&memory), (u64)(i0 + 52), i1);
        i0 = l3;
        i1 = 1053704u;
        i32_store((&memory), (u64)(i0 + 48), i1);
        i0 = l3;
        i1 = 1u;
        i32_store((&memory), (u64)(i0 + 44), i1);
        i0 = l3;
        i1 = 1053696u;
        i32_store((&memory), (u64)(i0 + 40), i1);
        i0 = l3;
        i1 = 29u;
        i32_store((&memory), (u64)(i0 + 36), i1);
        i0 = l7;
        i1 = 4294967295u;
        i0 += i1;
        l7 = i0;
        i0 = l8;
        i1 = 1u;
        i0 += i1;
        l8 = i0;
        i0 = l3;
        i1 = l3;
        i2 = 32u;
        i1 += i2;
        i32_store((&memory), (u64)(i0 + 56), i1);
        i0 = l3;
        i1 = l3;
        i2 = 28u;
        i1 += i2;
        i32_store((&memory), (u64)(i0 + 32), i1);
        i0 = p2;
        i1 = l3;
        i2 = 40u;
        i1 += i2;
        i0 = _ZN4core3fmt9Formatter9write_fmt17h5f4a789bf06948b3E(i0, i1);
        i0 = !(i0);
        if (i0) {goto L29;}
      B14:;
      i0 = 1u;
      l4 = i0;
      goto B0;
      B13:;
      i0 = 116u;
      p1 = i0;
      i0 = l9;
      switch (i0) {
        case 0: goto B5;
        case 1: goto B7;
        case 2: goto B12;
        case 3: goto B12;
        case 4: goto B6;
        case 5: goto B12;
        case 6: goto B12;
        case 7: goto B12;
        case 8: goto B12;
        case 9: goto B12;
        case 10: goto B12;
        case 11: goto B12;
        case 12: goto B12;
        case 13: goto B12;
        case 14: goto B12;
        case 15: goto B12;
        case 16: goto B12;
        case 17: goto B12;
        case 18: goto B12;
        case 19: goto B12;
        case 20: goto B12;
        case 21: goto B12;
        case 22: goto B12;
        case 23: goto B12;
        case 24: goto B12;
        case 25: goto B11;
        case 26: goto B12;
        case 27: goto B12;
        case 28: goto B12;
        case 29: goto B12;
        case 30: goto B11;
        default: goto B5;
      }
      B12:;
      i0 = p0;
      i0 = _ZN4core7unicode12unicode_data15grapheme_extend6lookup17h138f528bd4ec82e3E(i0);
      i0 = !(i0);
      if (i0) {goto B30;}
      i0 = p0;
      i1 = 1u;
      i0 |= i1;
      i0 = I32_CLZ(i0);
      i1 = 2u;
      i0 >>= (i1 & 31);
      i1 = 7u;
      i0 ^= i1;
      j0 = (u64)(i0);
      j1 = 21474836480ull;
      j0 |= j1;
      l12 = j0;
      goto B9;
      B30:;
      i0 = 1u;
      l4 = i0;
      i0 = p0;
      i0 = _ZN4core7unicode9printable12is_printable17h481fab4e83051dc0E(i0);
      i0 = !(i0);
      if (i0) {goto B10;}
      B11:;
      goto B8;
      B10:;
      i0 = p0;
      i1 = 1u;
      i0 |= i1;
      i0 = I32_CLZ(i0);
      i1 = 2u;
      i0 >>= (i1 & 31);
      i1 = 7u;
      i0 ^= i1;
      j0 = (u64)(i0);
      j1 = 21474836480ull;
      j0 |= j1;
      l12 = j0;
      B9:;
      i0 = 3u;
      l4 = i0;
      B8:;
      i0 = p0;
      p1 = i0;
      goto B5;
      B7:;
      i0 = 110u;
      p1 = i0;
      goto B5;
      B6:;
      i0 = 114u;
      p1 = i0;
      B5:;
      i0 = l3;
      j1 = l12;
      i64_store((&memory), (u64)(i0 + 56), j1);
      i0 = l3;
      i1 = p1;
      i32_store((&memory), (u64)(i0 + 52), i1);
      i0 = l3;
      i1 = l4;
      i32_store((&memory), (u64)(i0 + 48), i1);
      goto L4;
    B3:;
    i0 = l3;
    i1 = 40u;
    i0 += i1;
    i1 = l3;
    i2 = 16u;
    i1 += i2;
    _ZN96__LT_core__str__lossy__Utf8LossyChunksIter_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17he3cf0b2f3c5f8b4eE(i0, i1);
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 40));
    l4 = i0;
    if (i0) {goto L2;}
  B1:;
  i0 = p2;
  i1 = 1051900u;
  i2 = 1u;
  i0 = _ZN4core3fmt9Formatter9write_str17h3d77f3190807e699E(i0, i1, i2);
  l4 = i0;
  B0:;
  i0 = l3;
  i1 = 80u;
  i0 += i1;
  g0 = i0;
  i0 = l4;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h2e0883158ff4bc71E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = p1;
  i0 = _ZN4core3fmt9Formatter15debug_lower_hex17h613d71a0ae3bc060E(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i0 = _ZN4core3fmt9Formatter15debug_upper_hex17h5c3e903ff5236763E(i0);
  if (i0) {goto B1;}
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num3imp51__LT_impl_u20_core__fmt__Display_u20_for_u20_u8_GT_3fmt17hfd698e1eaf4e0cebE(i0, i1);
  goto Bfunc;
  B1:;
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num52__LT_impl_u20_core__fmt__UpperHex_u20_for_u20_i8_GT_3fmt17h768b96441edb650eE(i0, i1);
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num52__LT_impl_u20_core__fmt__LowerHex_u20_for_u20_i8_GT_3fmt17h6b3e03432bfb2278E(i0, i1);
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h33fbe4fe765398d6E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i2 = i32_load((&memory), (u64)(i2 + 36));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h7b30a097e07ac9d4E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = l2;
  i1 = p1;
  _ZN4core3fmt9Formatter10debug_list17h71cfa9ce1b3f9f44E(i0, i1);
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B0;}
  L1: 
    i0 = l2;
    i1 = p0;
    i32_store((&memory), (u64)(i0 + 12), i1);
    i0 = l2;
    i1 = l2;
    i2 = 12u;
    i1 += i2;
    i2 = 1050952u;
    i0 = _ZN4core3fmt8builders8DebugSet5entry17he2607966213fa565E(i0, i1, i2);
    i0 = p0;
    i1 = 1u;
    i0 += i1;
    p0 = i0;
    i0 = l3;
    i1 = 4294967295u;
    i0 += i1;
    l3 = i0;
    if (i0) {goto L1;}
  B0:;
  i0 = l2;
  i0 = _ZN4core3fmt8builders9DebugList6finish17hf24d2051438d787aE(i0);
  p0 = i0;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN57__LT_std__io__error__Repr_u20_as_u20_core__fmt__Debug_GT_3fmt17h35f993de34bdfaf1E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  switch (i0) {
    case 0: goto B2;
    case 1: goto B3;
    case 2: goto B1;
    default: goto B2;
  }
  B3:;
  i0 = l2;
  i1 = p0;
  i1 = i32_load8_u((&memory), (u64)(i1 + 1));
  i32_store8((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = p1;
  i2 = 1052565u;
  i3 = 4u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = l2;
  i2 = 16u;
  i1 += i2;
  i2 = 1052572u;
  i0 = _ZN4core3fmt8builders10DebugTuple5field17h16202dfa3a9387a4E(i0, i1, i2);
  i0 = _ZN4core3fmt8builders10DebugTuple6finish17h540db6bc8e5a3697E(i0);
  p0 = i0;
  goto B0;
  B2:;
  i0 = l2;
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 1052588u;
  i3 = 2u;
  _ZN4core3fmt9Formatter12debug_struct17h46183d60fb16cd21E(i0, i1, i2, i3);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i1 = 1052590u;
  i2 = 4u;
  i3 = l2;
  i4 = 12u;
  i3 += i4;
  i4 = 1052596u;
  i0 = _ZN4core3fmt8builders11DebugStruct5field17h8526abf557e6a496E(i0, i1, i2, i3, i4);
  p0 = i0;
  i0 = l2;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 12));
  i1 = _ZN3std3sys4wasi17decode_error_kind17he23a249a9ada7316E(i1);
  i2 = 255u;
  i1 &= i2;
  i32_store8((&memory), (u64)(i0 + 31), i1);
  i0 = p0;
  i1 = 1052612u;
  i2 = 4u;
  i3 = l2;
  i4 = 31u;
  i3 += i4;
  i4 = 1052572u;
  i0 = _ZN4core3fmt8builders11DebugStruct5field17h8526abf557e6a496E(i0, i1, i2, i3, i4);
  p0 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 12));
  _ZN3std3sys4wasi2os12error_string17h2cf85a3df68353a7E(i0, i1);
  i0 = p0;
  i1 = 1052616u;
  i2 = 7u;
  i3 = l2;
  i4 = 32u;
  i3 += i4;
  i4 = 1052624u;
  i0 = _ZN4core3fmt8builders11DebugStruct5field17h8526abf557e6a496E(i0, i1, i2, i3, i4);
  i0 = _ZN4core3fmt8builders11DebugStruct6finish17hab8f7dfb856acfc0E(i0);
  p0 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 32));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 36));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = l3;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  goto B0;
  B1:;
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = p1;
  i2 = 1054549u;
  i3 = 6u;
  _ZN4core3fmt9Formatter12debug_struct17h46183d60fb16cd21E(i0, i1, i2, i3);
  i0 = l2;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 1052612u;
  i2 = 4u;
  i3 = l2;
  i4 = 16u;
  i3 += i4;
  i4 = 1054556u;
  i0 = _ZN4core3fmt8builders11DebugStruct5field17h8526abf557e6a496E(i0, i1, i2, i3, i4);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 1054544u;
  i2 = 5u;
  i3 = l2;
  i4 = 16u;
  i3 += i4;
  i4 = 1054572u;
  i0 = _ZN4core3fmt8builders11DebugStruct5field17h8526abf557e6a496E(i0, i1, i2, i3, i4);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i0 = _ZN4core3fmt8builders11DebugStruct6finish17hab8f7dfb856acfc0E(i0);
  p0 = i0;
  B0:;
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN58__LT_std__ffi__c_str__CStr_u20_as_u20_core__fmt__Debug_GT_3fmt17h28e0d8bc9678db10E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0;
  u64 l8 = 0, l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 112u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = 76u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l3;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 60), j1);
  i0 = l3;
  i1 = 1052044u;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = 1u;
  l4 = i0;
  i0 = p2;
  i1 = l3;
  i2 = 56u;
  i1 += i2;
  i0 = _ZN4core3fmt9Formatter9write_fmt17h5f4a789bf06948b3E(i0, i1);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 4294967295u;
  i0 += i1;
  l4 = i0;
  i0 = p1;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l3;
  i1 = 40u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l3;
  i2 = 56u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 24u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l3;
  i2 = 100u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  l6 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  l7 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 56));
  l8 = j1;
  i64_store((&memory), (u64)(i0 + 40), j1);
  i0 = l3;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 100));
  l9 = j1;
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l3;
  i1 = 68u;
  i0 += i1;
  p1 = i0;
  j1 = l8;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 76u;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 84u;
  i0 += i1;
  l5 = i0;
  j1 = l9;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 92u;
  i0 += i1;
  i1 = l7;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 64), i1);
  i0 = l3;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 80), i1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l3;
  i1 = p0;
  i2 = l4;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 60), i1);
  i0 = 0u;
  l4 = i0;
  L2: 
    i0 = l4;
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B4;}
    i0 = 0u;
    l4 = i0;
    goto B3;
    B4:;
    i0 = 1u;
    l4 = i0;
    B3:;
    L5: 
      i0 = l4;
      switch (i0) {
        case 0: goto B10;
        case 1: goto B9;
        default: goto B9;
      }
      B10:;
      i0 = l3;
      i1 = 16u;
      i0 += i1;
      i1 = p1;
      _ZN85__LT_core__ascii__EscapeDefault_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17h75372c571a88c631E(i0, i1);
      i0 = l3;
      i0 = i32_load8_u((&memory), (u64)(i0 + 16));
      i1 = 1u;
      i0 &= i1;
      i0 = !(i0);
      if (i0) {goto B11;}
      i0 = l3;
      i0 = i32_load8_u((&memory), (u64)(i0 + 17));
      l4 = i0;
      goto B8;
      B11:;
      i0 = l3;
      i1 = 0u;
      i32_store((&memory), (u64)(i0 + 64), i1);
      i0 = 1u;
      l4 = i0;
      goto L5;
      B9:;
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 60));
      i1 = l3;
      i1 = i32_load((&memory), (u64)(i1 + 56));
      l4 = i1;
      i0 = i0 == i1;
      if (i0) {goto B12;}
      i0 = l3;
      i1 = l4;
      i2 = 1u;
      i1 += i2;
      i32_store((&memory), (u64)(i0 + 56), i1);
      i0 = l3;
      i1 = 100u;
      i0 += i1;
      i1 = l4;
      i1 = i32_load8_u((&memory), (u64)(i1));
      _ZN4core5ascii14escape_default17h0c71e6816c4ab86eE(i0, i1);
      i0 = p1;
      i1 = l3;
      j1 = i64_load((&memory), (u64)(i1 + 100));
      i64_store((&memory), (u64)(i0), j1);
      i0 = p1;
      i1 = 8u;
      i0 += i1;
      i1 = l6;
      i1 = i32_load((&memory), (u64)(i1));
      i32_store((&memory), (u64)(i0), i1);
      i0 = l3;
      i1 = 1u;
      i32_store((&memory), (u64)(i0 + 64), i1);
      goto B6;
      B12:;
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 80));
      i1 = 1u;
      i0 = i0 != i1;
      if (i0) {goto B7;}
      i0 = l3;
      i1 = 8u;
      i0 += i1;
      i1 = l5;
      _ZN85__LT_core__ascii__EscapeDefault_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17h75372c571a88c631E(i0, i1);
      i0 = l3;
      i0 = i32_load8_u((&memory), (u64)(i0 + 8));
      i1 = 1u;
      i0 &= i1;
      i0 = !(i0);
      if (i0) {goto B7;}
      i0 = l3;
      i0 = i32_load8_u((&memory), (u64)(i0 + 9));
      l4 = i0;
      B8:;
      i0 = p2;
      i1 = l4;
      i2 = 255u;
      i1 &= i2;
      i0 = _ZN57__LT_core__fmt__Formatter_u20_as_u20_core__fmt__Write_GT_10write_char17h22afcca50c7c4efdE(i0, i1);
      if (i0) {goto B13;}
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 64));
      l4 = i0;
      goto L2;
      B13:;
      i0 = 1u;
      l4 = i0;
      goto B0;
      B7:;
      i0 = l3;
      i1 = 76u;
      i0 += i1;
      i1 = 0u;
      i32_store((&memory), (u64)(i0), i1);
      i0 = l3;
      i1 = 1051284u;
      i32_store((&memory), (u64)(i0 + 72), i1);
      i0 = l3;
      j1 = 1ull;
      i64_store((&memory), (u64)(i0 + 60), j1);
      i0 = l3;
      i1 = 1052044u;
      i32_store((&memory), (u64)(i0 + 56), i1);
      i0 = p2;
      i1 = l3;
      i2 = 56u;
      i1 += i2;
      i0 = _ZN4core3fmt9Formatter9write_fmt17h5f4a789bf06948b3E(i0, i1);
      l4 = i0;
      goto B0;
      B6:;
      i0 = 0u;
      l4 = i0;
      goto L5;
  B1:;
  i0 = l4;
  i1 = 0u;
  i2 = 1052108u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l3;
  i1 = 112u;
  i0 += i1;
  g0 = i0;
  i0 = l4;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17hed958284c2b6c751E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i0 = _ZN62__LT_std__io__error__ErrorKind_u20_as_u20_core__fmt__Debug_GT_3fmt17h3ea22aa413b60deaE(i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN62__LT_std__io__error__ErrorKind_u20_as_u20_core__fmt__Debug_GT_3fmt17h3ea22aa413b60deaE(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  switch (i0) {
    case 0: goto B17;
    case 1: goto B16;
    case 2: goto B15;
    case 3: goto B14;
    case 4: goto B13;
    case 5: goto B12;
    case 6: goto B11;
    case 7: goto B10;
    case 8: goto B9;
    case 9: goto B8;
    case 10: goto B7;
    case 11: goto B6;
    case 12: goto B5;
    case 13: goto B4;
    case 14: goto B3;
    case 15: goto B2;
    case 16: goto B1;
    case 17: goto B18;
    default: goto B17;
  }
  B18:;
  i0 = l2;
  i1 = p1;
  i2 = 1054588u;
  i3 = 13u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B17:;
  i0 = l2;
  i1 = p1;
  i2 = 1054792u;
  i3 = 8u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B16:;
  i0 = l2;
  i1 = p1;
  i2 = 1054776u;
  i3 = 16u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B15:;
  i0 = l2;
  i1 = p1;
  i2 = 1054759u;
  i3 = 17u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B14:;
  i0 = l2;
  i1 = p1;
  i2 = 1054744u;
  i3 = 15u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B13:;
  i0 = l2;
  i1 = p1;
  i2 = 1054727u;
  i3 = 17u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B12:;
  i0 = l2;
  i1 = p1;
  i2 = 1054715u;
  i3 = 12u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B11:;
  i0 = l2;
  i1 = p1;
  i2 = 1054706u;
  i3 = 9u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B10:;
  i0 = l2;
  i1 = p1;
  i2 = 1054690u;
  i3 = 16u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B9:;
  i0 = l2;
  i1 = p1;
  i2 = 1054680u;
  i3 = 10u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B8:;
  i0 = l2;
  i1 = p1;
  i2 = 1054667u;
  i3 = 13u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B7:;
  i0 = l2;
  i1 = p1;
  i2 = 1054657u;
  i3 = 10u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B6:;
  i0 = l2;
  i1 = p1;
  i2 = 1054645u;
  i3 = 12u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B5:;
  i0 = l2;
  i1 = p1;
  i2 = 1054634u;
  i3 = 11u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B4:;
  i0 = l2;
  i1 = p1;
  i2 = 1054626u;
  i3 = 8u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B3:;
  i0 = l2;
  i1 = p1;
  i2 = 1054617u;
  i3 = 9u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B2:;
  i0 = l2;
  i1 = p1;
  i2 = 1054606u;
  i3 = 11u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  goto B0;
  B1:;
  i0 = l2;
  i1 = p1;
  i2 = 1054601u;
  i3 = 5u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  B0:;
  i0 = l2;
  i0 = _ZN4core3fmt8builders10DebugTuple6finish17h540db6bc8e5a3697E(i0);
  p1 = i0;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17h30c05985b633232cE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = p1;
  i0 = _ZN42__LT_str_u20_as_u20_core__fmt__Display_GT_3fmt17h503be603f26e92cbE(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17hb42a3b6b7f8cdfc5E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i0 = _ZN60__LT_core__panic__Location_u20_as_u20_core__fmt__Display_GT_3fmt17h5a11f7908f87d86dE(i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN45__LT__RF_T_u20_as_u20_core__fmt__UpperHex_GT_3fmt17h7be854885e27c6ffE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i0 = _ZN4core3fmt3num52__LT_impl_u20_core__fmt__UpperHex_u20_for_u20_i8_GT_3fmt17h768b96441edb650eE(i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt3num50__LT_impl_u20_core__fmt__Debug_u20_for_u20_i32_GT_3fmt17h1f2c474a10b11f09E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p1;
  i0 = _ZN4core3fmt9Formatter15debug_lower_hex17h613d71a0ae3bc060E(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i0 = _ZN4core3fmt9Formatter15debug_upper_hex17h5c3e903ff5236763E(i0);
  if (i0) {goto B1;}
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num3imp52__LT_impl_u20_core__fmt__Display_u20_for_u20_i32_GT_3fmt17hcf6a92db823ff527E(i0, i1);
  goto Bfunc;
  B1:;
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num53__LT_impl_u20_core__fmt__UpperHex_u20_for_u20_i32_GT_3fmt17hac44606703ee1b92E(i0, i1);
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num53__LT_impl_u20_core__fmt__LowerHex_u20_for_u20_i32_GT_3fmt17h4b124e18148b69c3E(i0, i1);
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt5Write10write_char17h0b163bb0f36a33d5E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l5 = 0;
  u64 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p1;
  i1 = 128u;
  i0 = i0 < i1;
  if (i0) {goto B3;}
  i0 = p1;
  i1 = 2048u;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 65536u;
  i0 = i0 >= i1;
  if (i0) {goto B1;}
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 6), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 15u;
  i1 &= i2;
  i2 = 224u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = 3u;
  p1 = i0;
  goto B0;
  B3:;
  i0 = l2;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = 1u;
  p1 = i0;
  goto B0;
  B2:;
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 31u;
  i1 &= i2;
  i2 = 192u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = 2u;
  p1 = i0;
  goto B0;
  B1:;
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 7), i1);
  i0 = l2;
  i1 = p1;
  i2 = 18u;
  i1 >>= (i2 & 31);
  i2 = 240u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 6), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = 4u;
  p1 = i0;
  B0:;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = l3;
  i3 = p1;
  _ZN3std2io5Write9write_all17h3c6b69cf0d5dfa52E(i0, i1, i2, i3);
  i0 = 0u;
  p1 = i0;
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  i1 = 3u;
  i0 = i0 == i1;
  if (i0) {goto B4;}
  i0 = l2;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l4 = j0;
  i0 = 0u;
  if (i0) {goto B6;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B5;}
  B6:;
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i2 = l3;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B7:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B5:;
  i0 = p0;
  j1 = l4;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = 1u;
  p1 = i0;
  B4:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std2io5Write9write_all17h3c6b69cf0d5dfa52E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p3;
  i0 = !(i0);
  if (i0) {goto B1;}
  L2: 
    i0 = l4;
    i1 = p3;
    i32_store((&memory), (u64)(i0 + 12), i1);
    i0 = l4;
    i1 = p2;
    i32_store((&memory), (u64)(i0 + 8), i1);
    i0 = l4;
    i1 = 16u;
    i0 += i1;
    i1 = 2u;
    i2 = l4;
    i3 = 8u;
    i2 += i3;
    i3 = 1u;
    _ZN4wasi13lib_generated8fd_write17hacbf9079620e9958E(i0, i1, i2, i3);
    i0 = l4;
    i0 = i32_load16_u((&memory), (u64)(i0 + 16));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B8;}
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 20));
    l5 = i0;
    if (i0) {goto B9;}
    i0 = 28u;
    i1 = 1u;
    i0 = __rust_alloc(i0, i1);
    p3 = i0;
    i0 = !(i0);
    if (i0) {goto B7;}
    i0 = p3;
    i1 = 24u;
    i0 += i1;
    i1 = 0u;
    i1 = i32_load((&memory), (u64)(i1 + 1052748));
    i32_store((&memory), (u64)(i0), i1);
    i0 = p3;
    i1 = 16u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052740));
    i64_store((&memory), (u64)(i0), j1);
    i0 = p3;
    i1 = 8u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052732));
    i64_store((&memory), (u64)(i0), j1);
    i0 = p3;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052724));
    i64_store((&memory), (u64)(i0), j1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    p2 = i0;
    i0 = !(i0);
    if (i0) {goto B6;}
    i0 = p2;
    j1 = 120259084316ull;
    i64_store((&memory), (u64)(i0 + 4), j1);
    i0 = p2;
    i1 = p3;
    i32_store((&memory), (u64)(i0), i1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    p3 = i0;
    i0 = !(i0);
    if (i0) {goto B5;}
    i0 = p3;
    i1 = 14u;
    i32_store8((&memory), (u64)(i0 + 8), i1);
    i0 = p3;
    i1 = 1052004u;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = p3;
    i1 = p2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p3;
    i1 = l4;
    i1 = i32_load16_u((&memory), (u64)(i1 + 16));
    i32_store16((&memory), (u64)(i0 + 9), i1);
    i0 = p3;
    i1 = 11u;
    i0 += i1;
    i1 = l4;
    i2 = 16u;
    i1 += i2;
    i2 = 2u;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4u;
    i0 += i1;
    i1 = p3;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 2u;
    i32_store((&memory), (u64)(i0), i1);
    goto B0;
    B9:;
    i0 = p3;
    i1 = l5;
    i0 = i0 < i1;
    if (i0) {goto B4;}
    i0 = p2;
    i1 = l5;
    i0 += i1;
    p2 = i0;
    i0 = p3;
    i1 = l5;
    i0 -= i1;
    p3 = i0;
    goto B3;
    B8:;
    i0 = l4;
    i1 = l4;
    i1 = i32_load16_u((&memory), (u64)(i1 + 18));
    i32_store16((&memory), (u64)(i0 + 30), i1);
    i0 = l4;
    i1 = 30u;
    i0 += i1;
    i0 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i0);
    i1 = 65535u;
    i0 &= i1;
    l5 = i0;
    i0 = _ZN3std3sys4wasi17decode_error_kind17he23a249a9ada7316E(i0);
    i1 = 255u;
    i0 &= i1;
    i1 = 15u;
    i0 = i0 == i1;
    if (i0) {goto B3;}
    i0 = p0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4u;
    i0 += i1;
    i1 = l5;
    i32_store((&memory), (u64)(i0), i1);
    goto B0;
    B7:;
    i0 = 28u;
    i1 = 1u;
    _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
    UNREACHABLE;
    B6:;
    i0 = 12u;
    i1 = 4u;
    _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
    UNREACHABLE;
    B5:;
    i0 = 12u;
    i1 = 4u;
    _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
    UNREACHABLE;
    B4:;
    i0 = l5;
    i1 = p3;
    i2 = 1053032u;
    _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
    UNREACHABLE;
    B3:;
    i0 = p3;
    if (i0) {goto L2;}
  B1:;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  B0:;
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3fmt5Write10write_char17hd5e375ed7cc26f67E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l5 = 0;
  u64 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p1;
  i1 = 128u;
  i0 = i0 < i1;
  if (i0) {goto B3;}
  i0 = p1;
  i1 = 2048u;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 65536u;
  i0 = i0 >= i1;
  if (i0) {goto B1;}
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 6), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 15u;
  i1 &= i2;
  i2 = 224u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = 3u;
  p1 = i0;
  goto B0;
  B3:;
  i0 = l2;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = 1u;
  p1 = i0;
  goto B0;
  B2:;
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 31u;
  i1 &= i2;
  i2 = 192u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = 2u;
  p1 = i0;
  goto B0;
  B1:;
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 7), i1);
  i0 = l2;
  i1 = p1;
  i2 = 18u;
  i1 >>= (i2 & 31);
  i2 = 240u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 6), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = 4u;
  p1 = i0;
  B0:;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = l3;
  i3 = p1;
  _ZN3std2io5Write9write_all17h0ac6a6a37a604fceE(i0, i1, i2, i3);
  i0 = 0u;
  p1 = i0;
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  i1 = 3u;
  i0 = i0 == i1;
  if (i0) {goto B4;}
  i0 = l2;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l4 = j0;
  i0 = 0u;
  if (i0) {goto B6;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B5;}
  B6:;
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i2 = l3;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B7:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B5:;
  i0 = p0;
  j1 = l4;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = 1u;
  p1 = i0;
  B4:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std2io5Write9write_all17h0ac6a6a37a604fceE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0, l7 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p3;
  i0 = !(i0);
  if (i0) {goto B5;}
  L6: 
    i0 = l4;
    i1 = p1;
    i2 = p2;
    i3 = p3;
    _ZN61__LT_std__io__stdio__StdoutLock_u20_as_u20_std__io__Write_GT_5write17h50f86d8404c780efE(i0, i1, i2, i3);
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B8;}
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l5 = i0;
    if (i0) {goto B9;}
    i0 = 28u;
    i1 = 1u;
    i0 = __rust_alloc(i0, i1);
    p3 = i0;
    i0 = !(i0);
    if (i0) {goto B4;}
    i0 = p3;
    i1 = 24u;
    i0 += i1;
    i1 = 0u;
    i1 = i32_load((&memory), (u64)(i1 + 1052748));
    i32_store((&memory), (u64)(i0), i1);
    i0 = p3;
    i1 = 16u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052740));
    i64_store((&memory), (u64)(i0), j1);
    i0 = p3;
    i1 = 8u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052732));
    i64_store((&memory), (u64)(i0), j1);
    i0 = p3;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052724));
    i64_store((&memory), (u64)(i0), j1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    p2 = i0;
    i0 = !(i0);
    if (i0) {goto B3;}
    i0 = p2;
    j1 = 120259084316ull;
    i64_store((&memory), (u64)(i0 + 4), j1);
    i0 = p2;
    i1 = p3;
    i32_store((&memory), (u64)(i0), i1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    p3 = i0;
    i0 = !(i0);
    if (i0) {goto B2;}
    i0 = p3;
    i1 = 14u;
    i32_store8((&memory), (u64)(i0 + 8), i1);
    i0 = p3;
    i1 = 1052004u;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = p3;
    i1 = p2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p3;
    i1 = l4;
    i1 = i32_load16_u((&memory), (u64)(i1 + 13));
    i32_store16((&memory), (u64)(i0 + 9), i1);
    i0 = p3;
    i1 = 11u;
    i0 += i1;
    i1 = l4;
    i2 = 13u;
    i1 += i2;
    i2 = 2u;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4u;
    i0 += i1;
    i1 = p3;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 2u;
    i32_store((&memory), (u64)(i0), i1);
    goto B0;
    B9:;
    i0 = p3;
    i1 = l5;
    i0 = i0 < i1;
    if (i0) {goto B1;}
    i0 = p2;
    i1 = l5;
    i0 += i1;
    p2 = i0;
    i0 = p3;
    i1 = l5;
    i0 -= i1;
    p3 = i0;
    goto B7;
    B8:;
    i0 = l4;
    i0 = i32_load8_u((&memory), (u64)(i0 + 4));
    l6 = i0;
    switch (i0) {
      case 0: goto B12;
      case 1: goto B13;
      case 2: goto B11;
      default: goto B12;
    }
    B13:;
    i0 = l4;
    i0 = i32_load8_u((&memory), (u64)(i0 + 5));
    l5 = i0;
    goto B10;
    B12:;
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    i0 = _ZN3std3sys4wasi17decode_error_kind17he23a249a9ada7316E(i0);
    i1 = 255u;
    i0 &= i1;
    l5 = i0;
    goto B10;
    B11:;
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    i0 = i32_load8_u((&memory), (u64)(i0 + 8));
    l5 = i0;
    B10:;
    i0 = l5;
    i1 = 255u;
    i0 &= i1;
    i1 = 15u;
    i0 = i0 == i1;
    if (i0) {goto B14;}
    i0 = p0;
    i1 = l4;
    j1 = i64_load((&memory), (u64)(i1 + 4));
    i64_store((&memory), (u64)(i0), j1);
    goto B0;
    B14:;
    i0 = l6;
    i1 = 2u;
    i0 = i0 < i1;
    if (i0) {goto B7;}
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    l5 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l5;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i1 = i32_load((&memory), (u64)(i1));
    CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
    i0 = l5;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l6 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l7 = i0;
    i0 = !(i0);
    if (i0) {goto B15;}
    i0 = l5;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l7;
    i2 = l6;
    i2 = i32_load((&memory), (u64)(i2 + 8));
    __rust_dealloc(i0, i1, i2);
    B15:;
    i0 = l5;
    i1 = 12u;
    i2 = 4u;
    __rust_dealloc(i0, i1, i2);
    B7:;
    i0 = p3;
    if (i0) {goto L6;}
  B5:;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  goto B0;
  B4:;
  i0 = 28u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B3:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B2:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = l5;
  i1 = p3;
  i2 = 1053032u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3fmt5Write9write_fmt17h0c6297cc94671fdbE(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  i1 = 1050880u;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p1 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt5Write9write_fmt17hef4ec0875f790078E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  i1 = 1050928u;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p1 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std9panicking12default_hook17h61085b8eace1a41cE(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l7 = 0;
  u64 l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 96u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = 1u;
  l2 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061728));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B2;}
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061728), j1);
  goto B1;
  B2:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061732));
  i1 = 1u;
  i0 = i0 > i1;
  if (i0) {goto B0;}
  B1:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061660));
  l2 = i0;
  i1 = 2u;
  i0 = i0 <= i1;
  if (i0) {goto B3;}
  i0 = 1u;
  l2 = i0;
  goto B0;
  B3:;
  i0 = l2;
  switch (i0) {
    case 0: goto B6;
    case 1: goto B5;
    case 2: goto B4;
    default: goto B6;
  }
  B6:;
  i0 = l1;
  i1 = 64u;
  i0 += i1;
  i1 = 1051901u;
  i2 = 14u;
  _ZN3std3env7_var_os17h65122ae02361542aE(i0, i1, i2);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 64));
  l3 = i0;
  if (i0) {goto B8;}
  i0 = 5u;
  l2 = i0;
  goto B7;
  B8:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 68));
  l4 = i0;
  i0 = l1;
  i1 = 72u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 4294967295u;
  i0 += i1;
  l2 = i0;
  i1 = 3u;
  i0 = i0 > i1;
  if (i0) {goto B10;}
  i0 = l2;
  switch (i0) {
    case 0: goto B12;
    case 1: goto B10;
    case 2: goto B10;
    case 3: goto B11;
    default: goto B12;
  }
  B12:;
  i0 = 4u;
  l2 = i0;
  i0 = 1u;
  l5 = i0;
  i0 = l3;
  i1 = 1051915u;
  i0 = i0 == i1;
  if (i0) {goto B9;}
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 48u;
  i0 = i0 != i1;
  if (i0) {goto B10;}
  goto B9;
  B11:;
  i0 = 1u;
  l2 = i0;
  i0 = 3u;
  l5 = i0;
  i0 = l3;
  i1 = 1053680u;
  i0 = i0 == i1;
  if (i0) {goto B9;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 1819047270u;
  i0 = i0 == i1;
  if (i0) {goto B9;}
  B10:;
  i0 = 0u;
  l2 = i0;
  i0 = 2u;
  l5 = i0;
  B9:;
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = l3;
  i1 = l4;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B7:;
  i0 = 0u;
  i1 = 1u;
  i2 = l5;
  i3 = l2;
  i4 = 5u;
  i3 = i3 == i4;
  l3 = i3;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0 + 1061660), i1);
  i0 = 4u;
  i1 = l2;
  i2 = l3;
  i0 = i2 ? i0 : i1;
  l2 = i0;
  goto B0;
  B5:;
  i0 = 4u;
  l2 = i0;
  goto B0;
  B4:;
  i0 = 0u;
  l2 = i0;
  B0:;
  i0 = l1;
  i1 = l2;
  i32_store8((&memory), (u64)(i0 + 35), i1);
  i0 = p0;
  i0 = _ZN4core5panic9PanicInfo8location17hadae980b9a5e60d2E(i0);
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B15;}
  i0 = l1;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l1;
  i1 = 24u;
  i0 += i1;
  i1 = p0;
  _ZN4core5panic8Location4file17hd78f3cde5f346820E(i0, i1);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l2 = i0;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 28));
  i1 = i32_load((&memory), (u64)(i1 + 12));
  j0 = CALL_INDIRECT(T0, u64 (*)(u32), 4, i1, i0);
  l6 = j0;
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B16;}
  j0 = l6;
  j1 = 1229646359891580772ull;
  i0 = j0 == j1;
  if (i0) {goto B14;}
  B16:;
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  i1 = p0;
  _ZN4core5panic8Location4file17hd78f3cde5f346820E(i0, i1);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l2 = i0;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  i1 = i32_load((&memory), (u64)(i1 + 12));
  j0 = CALL_INDIRECT(T0, u64 (*)(u32), 4, i1, i0);
  l6 = j0;
  i0 = 8u;
  p0 = i0;
  i0 = 1054016u;
  l5 = i0;
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B17;}
  j0 = l6;
  j1 = 10536124946013174407ull;
  i0 = j0 != j1;
  if (i0) {goto B17;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p0 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  B17:;
  i0 = l1;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 40), i1);
  goto B13;
  B15:;
  i0 = 1051328u;
  i1 = 43u;
  i2 = 1054000u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B14:;
  i0 = l1;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p0 = i0;
  B13:;
  i0 = l1;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = 0u;
  p0 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061716));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B18;}
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061716), j1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061724), i1);
  B18:;
  i0 = l1;
  i1 = 1061720u;
  i1 = _ZN3std10sys_common11thread_info10ThreadInfo4with28__u7b__u7b_closure_u7d__u7d_17h4f4afda818addf88E(i1);
  l2 = i1;
  i32_store((&memory), (u64)(i0 + 52), i1);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l5 = i0;
  if (i0) {goto B21;}
  goto B20;
  B21:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i1 = 0u;
  i2 = l5;
  i0 = i2 ? i0 : i1;
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i1 = 4294967295u;
  i0 += i1;
  l5 = i0;
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B19;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  B20:;
  i0 = l1;
  i1 = l5;
  i2 = 9u;
  i3 = p0;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0 + 60), i1);
  i0 = l1;
  i1 = p0;
  i2 = 1054024u;
  i3 = p0;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l1;
  i1 = l1;
  i2 = 35u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 76), i1);
  i0 = l1;
  i1 = l1;
  i2 = 36u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l1;
  i1 = l1;
  i2 = 40u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 68), i1);
  i0 = l1;
  i1 = l1;
  i2 = 56u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 64), i1);
  i0 = 0u;
  l3 = i0;
  i0 = l1;
  i1 = 8u;
  i0 += i1;
  i1 = 0u;
  i2 = l1;
  _ZN3std2io5stdio9set_panic17h73ed222c0f64725fE(i0, i1, i2);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l5 = i0;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B23;}
  i0 = l1;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 84), i1);
  i0 = l1;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 80), i1);
  i0 = l1;
  i1 = 64u;
  i0 += i1;
  i1 = l1;
  i2 = 80u;
  i1 += i2;
  i2 = 1054076u;
  _ZN3std9panicking12default_hook28__u7b__u7b_closure_u7d__u7d_17h586ab2a6a28d8372E(i0, i1, i2);
  i0 = l1;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 80));
  i2 = l1;
  i2 = i32_load((&memory), (u64)(i2 + 84));
  _ZN3std2io5stdio9set_panic17h73ed222c0f64725fE(i0, i1, i2);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B24;}
  i0 = l3;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  l4 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l7 = i0;
  i0 = !(i0);
  if (i0) {goto B24;}
  i0 = l3;
  i1 = l7;
  i2 = l4;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B24:;
  i0 = 1u;
  l3 = i0;
  goto B22;
  B23:;
  i0 = l1;
  i1 = 64u;
  i0 += i1;
  i1 = l1;
  i2 = 88u;
  i1 += i2;
  i2 = 1054036u;
  _ZN3std9panicking12default_hook28__u7b__u7b_closure_u7d__u7d_17h586ab2a6a28d8372E(i0, i1, i2);
  B22:;
  i0 = l2;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1));
  l4 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B25;}
  i0 = l1;
  i1 = 52u;
  i0 += i1;
  _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h54081c59c02bd7eaE(i0);
  B25:;
  i0 = p0;
  i1 = 0u;
  i0 = i0 != i1;
  i1 = l3;
  i2 = 1u;
  i1 ^= i2;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B26;}
  i0 = p0;
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B26;}
  i0 = p0;
  i1 = l2;
  i2 = l5;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B26:;
  i0 = l1;
  i1 = 96u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B19:;
  i0 = l5;
  i1 = 0u;
  i2 = 1052108u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h2bc8b0235c26cfedE(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 12u;
  i0 += i1;
  i1 = p1;
  _ZN3std4sync4once4Once9call_once28__u7b__u7b_closure_u7d__u7d_17ha8365db8fceb4f2cE(i0, i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN3std4sync4once4Once9call_once28__u7b__u7b_closure_u7d__u7d_17ha8365db8fceb4f2cE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  l2 = i0;
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = 1u;
  l3 = i0;
  L1: 
    i0 = 0u;
    i0 = i32_load8_u((&memory), (u64)(i0 + 1061737));
    if (i0) {goto B5;}
    i0 = 0u;
    i0 = i32_load((&memory), (u64)(i0 + 1061656));
    l4 = i0;
    i0 = 0u;
    i1 = l3;
    i2 = 10u;
    i1 = i1 == i2;
    i32_store((&memory), (u64)(i0 + 1061656), i1);
    i0 = 0u;
    i1 = 0u;
    i32_store8((&memory), (u64)(i0 + 1061737), i1);
    i0 = l4;
    i1 = 1u;
    i0 = i0 > i1;
    if (i0) {goto B6;}
    i0 = l4;
    switch (i0) {
      case 0: goto B2;
      case 1: goto B7;
      default: goto B2;
    }
    B7:;
    i0 = 1053452u;
    i1 = 31u;
    i2 = 1053520u;
    _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
    UNREACHABLE;
    B6:;
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    l5 = i0;
    i1 = l4;
    i1 = i32_load((&memory), (u64)(i1 + 8));
    l2 = i1;
    i2 = 3u;
    i1 <<= (i2 & 31);
    i0 += i1;
    l6 = i0;
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l7 = i0;
    i0 = l5;
    p0 = i0;
    i0 = l2;
    i0 = !(i0);
    if (i0) {goto B4;}
    i0 = l5;
    p0 = i0;
    L8: 
      i0 = p0;
      i0 = i32_load((&memory), (u64)(i0));
      l2 = i0;
      if (i0) {goto B9;}
      i0 = p0;
      i1 = 8u;
      i0 += i1;
      p0 = i0;
      goto B4;
      B9:;
      i0 = l2;
      i1 = p0;
      i2 = 4u;
      i1 += i2;
      i1 = i32_load((&memory), (u64)(i1));
      l8 = i1;
      i1 = i32_load((&memory), (u64)(i1 + 12));
      CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
      i0 = l8;
      i0 = i32_load((&memory), (u64)(i0 + 4));
      l9 = i0;
      i0 = !(i0);
      if (i0) {goto B10;}
      i0 = l2;
      i1 = l9;
      i2 = l8;
      i2 = i32_load((&memory), (u64)(i2 + 8));
      __rust_dealloc(i0, i1, i2);
      B10:;
      i0 = p0;
      i1 = 8u;
      i0 += i1;
      p0 = i0;
      i1 = l6;
      i0 = i0 != i1;
      if (i0) {goto L8;}
      goto B3;
    B5:;
    i0 = 1055072u;
    i1 = 32u;
    i2 = 1055140u;
    _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
    UNREACHABLE;
    B4:;
    i0 = l6;
    i1 = p0;
    i0 = i0 == i1;
    if (i0) {goto B3;}
    L11: 
      i0 = p0;
      i0 = i32_load((&memory), (u64)(i0));
      i1 = p0;
      i2 = 4u;
      i1 += i2;
      l2 = i1;
      i1 = i32_load((&memory), (u64)(i1));
      i1 = i32_load((&memory), (u64)(i1));
      CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
      i0 = l2;
      i0 = i32_load((&memory), (u64)(i0));
      l2 = i0;
      i0 = i32_load((&memory), (u64)(i0 + 4));
      l8 = i0;
      i0 = !(i0);
      if (i0) {goto B12;}
      i0 = p0;
      i0 = i32_load((&memory), (u64)(i0));
      i1 = l8;
      i2 = l2;
      i2 = i32_load((&memory), (u64)(i2 + 8));
      __rust_dealloc(i0, i1, i2);
      B12:;
      i0 = p0;
      i1 = 8u;
      i0 += i1;
      p0 = i0;
      i1 = l6;
      i0 = i0 != i1;
      if (i0) {goto L11;}
    B3:;
    i0 = l7;
    i0 = !(i0);
    if (i0) {goto B13;}
    i0 = l7;
    i1 = 3u;
    i0 <<= (i1 & 31);
    p0 = i0;
    i0 = !(i0);
    if (i0) {goto B13;}
    i0 = l5;
    i1 = p0;
    i2 = 4u;
    __rust_dealloc(i0, i1, i2);
    B13:;
    i0 = l4;
    i1 = 12u;
    i2 = 4u;
    __rust_dealloc(i0, i1, i2);
    B2:;
    i0 = l3;
    i1 = 9u;
    i0 = i0 > i1;
    p0 = i0;
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    i1 = 10u;
    i2 = l3;
    i3 = 10u;
    i2 = i2 < i3;
    i0 = i2 ? i0 : i1;
    l2 = i0;
    l3 = i0;
    i0 = l2;
    i1 = 11u;
    i0 = i0 < i1;
    i1 = p0;
    i2 = 1u;
    i1 ^= i2;
    i0 &= i1;
    if (i0) {goto L1;}
  goto Bfunc;
  B0:;
  i0 = 1051328u;
  i1 = 43u;
  i2 = 1053268u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h458ee20a9f44d36bE(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  p0 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = l1;
  _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h636c01c268505f2aE(i0);
  B1:;
  i0 = l1;
  i1 = 4u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  goto Bfunc;
  B0:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h636c01c268505f2aE(u32 p0) {
  u32 l1 = 0, l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 1u;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  i0 = l1;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  l1 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l1;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 36u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  FUNC_EPILOGUE;
}

static void _ZN3std9panicking11begin_panic17h03009c70f59374e1E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = 1054332u;
  i2 = 0u;
  i3 = p2;
  i3 = _ZN4core5panic8Location6caller17ha977844962a520efE(i3);
  _ZN3std9panicking20rust_panic_with_hook17hb8132b4308a71007E(i0, i1, i2, i3);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h717d1eb4223145c5E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = 1053684u;
  p2 = i0;
  i0 = 9u;
  l4 = i0;
  goto B0;
  B1:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  i1 = p2;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = p2;
  i3 = 8u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  _ZN4core3str9from_utf817he6f02ee8cec749d4E(i0, i1, i2);
  i0 = 1053684u;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  i2 = l3;
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i3 = 1u;
  i2 = i2 == i3;
  l4 = i2;
  i0 = i2 ? i0 : i1;
  p2 = i0;
  i0 = 9u;
  i1 = l3;
  i2 = 16u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = l4;
  i0 = i2 ? i0 : i1;
  l4 = i0;
  B0:;
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  i2 = l4;
  _ZN4core3str5lossy9Utf8Lossy10from_bytes17h1fc730ab18994b0dE(i0, i1, i2);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1 + 12));
  i2 = p1;
  i0 = _ZN66__LT_core__str__lossy__Utf8Lossy_u20_as_u20_core__fmt__Display_GT_3fmt17h9396f0cf1136f103E(i0, i1, i2);
  p2 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p1;
  i1 = p0;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B2:;
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p2;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17hfef0f420f30980acE(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  p0 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = l1;
  _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h76eb5b162db06de2E(i0);
  B1:;
  i0 = l1;
  i1 = 4u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  goto Bfunc;
  B0:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h76eb5b162db06de2E(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 2u;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = l2;
  i1 = 25u;
  i0 += i1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  if (i0) {goto B0;}
  i0 = l1;
  i1 = 8u;
  i0 += i1;
  i1 = l2;
  i2 = 12u;
  i1 += i2;
  _ZN3std2io8buffered18BufWriter_LT_W_GT_9flush_buf17hd67ccca3c7d9e3cdE(i0, i1);
  i0 = 0u;
  if (i0) {goto B1;}
  i0 = l1;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  B1:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l4 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i2 = l4;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B2:;
  i0 = l3;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l3;
  i1 = l2;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  l2 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 32u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B4:;
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17h02dece875a093ec5E(u32 p0) {
  FUNC_PROLOGUE;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17h049ce136079928c5E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  u64 j1;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  if (i0) {goto B0;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061728));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061728), j1);
  goto B0;
  B1:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061732));
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  B0:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17h12fdb55a43c98e2eE(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i1 = p0;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17h1bc2903d971cdafdE(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i1 = p0;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17h357736d8dd8f427cE(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i1 = p0;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17h4fb62c5b377abd3dE(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = 0u;
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  B1:;
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l3;
  i2 = l2;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B2:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17had9a6dbef51e0932E(u32 p0) {
  u32 l1 = 0, l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = l1;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B0:;
  FUNC_EPILOGUE;
}

static void _ZN4core3ptr13drop_in_place17hfd7be1f615408ba6E(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i1 = p0;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  FUNC_EPILOGUE;
}

static u32 _ZN4core6option15Option_LT_T_GT_6unwrap17hcef08ddb8cf9885dE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  if (i0) {goto B0;}
  i0 = 1051328u;
  i1 = 43u;
  i2 = p1;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core6option15Option_LT_T_GT_6unwrap17hf88ae310ea733521E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  if (i0) {goto B0;}
  i0 = 1051328u;
  i1 = 43u;
  i2 = 1054280u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17h1148e112010023a0E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = p1;
  i1 = 128u;
  i0 = i0 < i1;
  if (i0) {goto B5;}
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p1;
  i1 = 2048u;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l2;
  i1 = 12u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 65536u;
  i0 = i0 >= i1;
  if (i0) {goto B6;}
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 15u;
  i1 &= i2;
  i2 = 224u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 3u;
  p1 = i0;
  goto B1;
  B6:;
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 15), i1);
  i0 = l2;
  i1 = p1;
  i2 = 18u;
  i1 >>= (i2 & 31);
  i2 = 240u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = 4u;
  p1 = i0;
  goto B1;
  B5:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l3 = i0;
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i0 = i0 == i1;
  if (i0) {goto B7;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  goto B2;
  B7:;
  i0 = l3;
  i1 = 1u;
  i0 += i1;
  l4 = i0;
  i1 = l3;
  i0 = i0 < i1;
  if (i0) {goto B10;}
  i0 = l3;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l4;
  i2 = l5;
  i3 = l4;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B10;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  if (i0) {goto B11;}
  B12:;
  i0 = l5;
  if (i0) {goto B9;}
  i0 = 1u;
  l4 = i0;
  goto B3;
  B11:;
  i0 = l3;
  i1 = l5;
  i0 = i0 == i1;
  if (i0) {goto B13;}
  i0 = l4;
  i1 = l3;
  i2 = 1u;
  i3 = l5;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l4 = i0;
  B13:;
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l3 = i0;
  goto B3;
  B10:;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  B9:;
  i0 = l5;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  if (i0) {goto B3;}
  B8:;
  i0 = l5;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B4:;
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 31u;
  i1 &= i2;
  i2 = 192u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 12u;
  i0 += i1;
  l3 = i0;
  i0 = 2u;
  p1 = i0;
  goto B1;
  B3:;
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  B2:;
  i0 = l4;
  i1 = l3;
  i0 += i1;
  i1 = p1;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto B0;
  B1:;
  i0 = p0;
  i1 = l3;
  i2 = l3;
  i3 = p1;
  i2 += i3;
  _ZN109__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_alloc__vec__SpecExtend_LT__RF_T_C_core__slice__Iter_LT_T_GT__GT__GT_11spec_extend17hce2eec127ad34cc7E(i0, i1, i2);
  B0:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = 0u;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17h847b5ed38de6fefaE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i0 = _ZN4core3fmt5Write10write_char17hd5e375ed7cc26f67E(i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17hd2e1f2321b48f67eE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i0 = _ZN4core3fmt5Write10write_char17h0b163bb0f36a33d5E(i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17h3b7bf02809848e00E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  i1 = 1050928u;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p1 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17h64f54daf655ce739E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  i1 = 1050880u;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p1 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17hdd5646de992e1c42E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  i1 = 1050904u;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p1 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h17594c444a344b88E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l5 = 0;
  u64 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  p0 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p1;
  i3 = p2;
  _ZN3std2io5Write9write_all17h3c6b69cf0d5dfa52E(i0, i1, i2, i3);
  i0 = 0u;
  p1 = i0;
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  i1 = 3u;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = l3;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l4 = j0;
  i0 = 0u;
  if (i0) {goto B2;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  B2:;
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p2 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  i0 = p0;
  j1 = l4;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = 1u;
  p1 = i0;
  B0:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h2ccf06e1a3fafb6aE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l5 = 0;
  u64 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  p0 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p1;
  i3 = p2;
  _ZN3std2io5Write9write_all17h0ac6a6a37a604fceE(i0, i1, i2, i3);
  i0 = 0u;
  p1 = i0;
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  i1 = 3u;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = l3;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l4 = j0;
  i0 = 0u;
  if (i0) {goto B2;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  B2:;
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p2 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  i0 = p0;
  j1 = l4;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = 1u;
  p1 = i0;
  B0:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h43a4a1478c7fe4a7E(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p1;
  i3 = p2;
  i2 += i3;
  _ZN109__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_alloc__vec__SpecExtend_LT__RF_T_C_core__slice__Iter_LT_T_GT__GT__GT_11spec_extend17hce2eec127ad34cc7E(i0, i1, i2);
  i0 = 0u;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN58__LT_alloc__string__String_u20_as_u20_core__fmt__Debug_GT_3fmt17h2cea2baa4dfef855E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i2 = p1;
  i0 = _ZN40__LT_str_u20_as_u20_core__fmt__Debug_GT_3fmt17hc81f6984a0ce9960E(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h54081c59c02bd7eaE(u32 p0) {
  u32 l1 = 0, l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l2;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  i1 = l2;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = l1;
  i1 = 28u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 1u;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  l1 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l1;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 48u;
  i2 = 8u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  FUNC_EPILOGUE;
}

static void _ZN3std2io8buffered18BufWriter_LT_W_GT_9flush_buf17hd67ccca3c7d9e3cdE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  if (i0) {goto B2;}
  i0 = 3u;
  l5 = i0;
  goto B1;
  B2:;
  i0 = 0u;
  l6 = i0;
  L9: 
    i0 = p1;
    i1 = 1u;
    i32_store8((&memory), (u64)(i0 + 13), i1);
    i0 = p1;
    i0 = i32_load8_u((&memory), (u64)(i0 + 12));
    l7 = i0;
    i1 = 2u;
    i0 = i0 == i1;
    if (i0) {goto B8;}
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0));
    l5 = i0;
    i1 = l6;
    i0 = i0 < i1;
    if (i0) {goto B7;}
    i0 = l5;
    i1 = l6;
    i0 -= i1;
    l5 = i0;
    i0 = l7;
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B11;}
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0));
    l7 = i0;
    i0 = l2;
    i1 = l5;
    i32_store((&memory), (u64)(i0 + 12), i1);
    i0 = l2;
    i1 = l7;
    i2 = l6;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 8), i1);
    i0 = l2;
    i1 = 16u;
    i0 += i1;
    i1 = 1u;
    i2 = l2;
    i3 = 8u;
    i2 += i3;
    i3 = 1u;
    _ZN4wasi13lib_generated8fd_write17hacbf9079620e9958E(i0, i1, i2, i3);
    i0 = l2;
    i0 = i32_load16_u((&memory), (u64)(i0 + 16));
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B12;}
    i0 = l2;
    i1 = l2;
    i1 = i32_load16_u((&memory), (u64)(i1 + 18));
    i32_store16((&memory), (u64)(i0 + 30), i1);
    i0 = l2;
    i1 = 30u;
    i0 += i1;
    i0 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i0);
    i1 = 65535u;
    i0 &= i1;
    l7 = i0;
    i1 = 8u;
    i0 = i0 == i1;
    if (i0) {goto B11;}
    i0 = 0u;
    l5 = i0;
    i0 = p1;
    i1 = 0u;
    i32_store8((&memory), (u64)(i0 + 13), i1);
    i0 = l7;
    i0 = _ZN3std3sys4wasi17decode_error_kind17he23a249a9ada7316E(i0);
    i1 = 255u;
    i0 &= i1;
    i1 = 15u;
    i0 = i0 != i1;
    if (i0) {goto B3;}
    goto B10;
    B12:;
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0 + 20));
    l5 = i0;
    B11:;
    i0 = p1;
    i1 = 0u;
    i32_store8((&memory), (u64)(i0 + 13), i1);
    i0 = l5;
    if (i0) {goto B13;}
    i0 = 33u;
    i1 = 1u;
    i0 = __rust_alloc(i0, i1);
    l5 = i0;
    i0 = !(i0);
    if (i0) {goto B6;}
    i0 = l5;
    i1 = 32u;
    i0 += i1;
    i1 = 0u;
    i1 = i32_load8_u((&memory), (u64)(i1 + 1052232));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = l5;
    i1 = 24u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052224));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l5;
    i1 = 16u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052216));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l5;
    i1 = 8u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052208));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l5;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052200));
    i64_store((&memory), (u64)(i0), j1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    l3 = i0;
    i0 = !(i0);
    if (i0) {goto B5;}
    i0 = l3;
    j1 = 141733920801ull;
    i64_store((&memory), (u64)(i0 + 4), j1);
    i0 = l3;
    i1 = l5;
    i32_store((&memory), (u64)(i0), i1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    l7 = i0;
    i0 = !(i0);
    if (i0) {goto B4;}
    i0 = l7;
    i1 = 14u;
    i32_store8((&memory), (u64)(i0 + 8), i1);
    i0 = l7;
    i1 = 1052004u;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l7;
    i1 = l3;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l7;
    i1 = l2;
    i1 = i32_load16_u((&memory), (u64)(i1 + 16));
    i32_store16((&memory), (u64)(i0 + 9), i1);
    i0 = 2u;
    l5 = i0;
    i0 = l7;
    i1 = 11u;
    i0 += i1;
    i1 = l2;
    i2 = 16u;
    i1 += i2;
    i2 = 2u;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    goto B3;
    B13:;
    i0 = l5;
    i1 = l6;
    i0 += i1;
    l6 = i0;
    B10:;
    i0 = l6;
    i1 = l4;
    i0 = i0 < i1;
    if (i0) {goto L9;}
  i0 = 3u;
  l5 = i0;
  goto B3;
  B8:;
  i0 = 1051328u;
  i1 = 43u;
  i2 = 1052168u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B7:;
  i0 = l6;
  i1 = l5;
  i2 = 1052184u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B6:;
  i0 = 33u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B5:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B4:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B3:;
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i1 = l6;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = l3;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l6;
  i0 -= i1;
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i1 = l4;
  i2 = l6;
  i1 += i2;
  i2 = l3;
  i0 = memmove_0(i0, i1, i2);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  B1:;
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l7;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B0:;
  i0 = l6;
  i1 = l4;
  _ZN5alloc3vec12Vec_LT_T_GT_5drain17end_assert_failed17hccc4a24f1f7369a6E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN5alloc5slice29__LT_impl_u20__u5b_T_u5d__GT_6to_vec17h2392cf0518e8ca41E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p2;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  i0 = p2;
  if (i0) {goto B4;}
  i0 = 0u;
  l3 = i0;
  i0 = 1u;
  l4 = i0;
  goto B3;
  B4:;
  i0 = p2;
  l3 = i0;
  i0 = p2;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  B3:;
  i0 = l3;
  i1 = p2;
  i0 = i0 >= i1;
  if (i0) {goto B6;}
  i0 = l3;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = p2;
  i2 = l5;
  i3 = p2;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B5;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = l4;
  if (i0) {goto B8;}
  B9:;
  i0 = l5;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  if (i0) {goto B7;}
  goto B0;
  B8:;
  i0 = l3;
  i1 = l5;
  i0 = i0 == i1;
  if (i0) {goto B6;}
  i0 = l4;
  i1 = l3;
  i2 = 1u;
  i3 = l5;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  B7:;
  i0 = l5;
  l3 = i0;
  B6:;
  i0 = l4;
  i1 = p1;
  i2 = p2;
  i0 = memcpy_0(i0, i1, i2);
  l4 = i0;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B5:;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  B2:;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h132ff70aff78c839E();
  UNREACHABLE;
  B1:;
  i0 = p2;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = l5;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h132ff70aff78c839E(void) {
  FUNC_PROLOGUE;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p1;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN60__LT_alloc__string__String_u20_as_u20_core__fmt__Display_GT_3fmt17h88e8485f1d902f65E_1(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i2 = p1;
  i0 = _ZN42__LT_str_u20_as_u20_core__fmt__Display_GT_3fmt17h503be603f26e92cbE(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN3std10sys_common11thread_info10ThreadInfo4with28__u7b__u7b_closure_u7d__u7d_17h4f4afda818addf88E(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i1 = 1u;
  i0 += i1;
  i1 = 0u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B3;}
  i0 = p0;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  if (i0) {goto B4;}
  i0 = l1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l1;
  i1 = 8u;
  i0 += i1;
  i0 = _ZN3std6thread6Thread3new17h1d02bb6db813b9d0E(i0);
  l3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  if (i0) {goto B2;}
  i0 = p0;
  i1 = 4294967295u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = l2;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1));
  l4 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B5;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h54081c59c02bd7eaE(i0);
  B5:;
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 1u;
  i1 += i2;
  l2 = i1;
  i32_store((&memory), (u64)(i0), i1);
  B4:;
  i0 = l2;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4294967295u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = l3;
  goto Bfunc;
  B3:;
  i0 = 1051160u;
  i1 = 24u;
  i2 = l1;
  i3 = 24u;
  i2 += i3;
  i3 = 1051404u;
  i4 = 1051184u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B2:;
  i0 = 1051060u;
  i1 = 16u;
  i2 = l1;
  i3 = 24u;
  i2 += i3;
  i3 = 1051372u;
  i4 = 1051144u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B1:;
  i0 = 1051060u;
  i1 = 16u;
  i2 = l1;
  i3 = 24u;
  i2 += i3;
  i3 = 1051372u;
  i4 = 1051144u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B0:;
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std6thread4park17haa34f1fc5521730bE(void) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 96u;
  i0 -= i1;
  l0 = i0;
  g0 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061716));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061716), j1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061724), i1);
  B0:;
  i0 = 1061720u;
  i0 = _ZN3std10sys_common11thread_info10ThreadInfo4with28__u7b__u7b_closure_u7d__u7d_17h4f4afda818addf88E(i0);
  l1 = i0;
  i1 = 0u;
  i2 = l1;
  i2 = i32_load((&memory), (u64)(i2 + 24));
  l2 = i2;
  i3 = l2;
  i4 = 2u;
  i3 = i3 == i4;
  l2 = i3;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l0;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  if (i0) {goto B1;}
  i0 = l0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l1 = i0;
  i1 = 28u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  if (i0) {goto B5;}
  i0 = l2;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = 0u;
  l4 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061728));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B7;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061732));
  l4 = i0;
  goto B6;
  B7:;
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061728), j1);
  B6:;
  i0 = 0u;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 1061732), i1);
  i0 = l1;
  i0 = i32_load8_u((&memory), (u64)(i0 + 32));
  if (i0) {goto B4;}
  i0 = l1;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 24));
  l2 = i1;
  i2 = 1u;
  i3 = l2;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l2;
  if (i0) {goto B8;}
  i0 = l0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 36u;
  i0 += i1;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1));
  _ZN3std4sync7condvar7Condvar6verify17h950e8c3c7a86a681E(i0, i1);
  _ZN3std10sys_common7condvar7Condvar4wait17hb99804595d9707a7E();
  UNREACHABLE;
  B8:;
  i0 = l2;
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B3;}
  i0 = l0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l5 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l2 = i0;
  i0 = l5;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l0;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B2;}
  i0 = l4;
  if (i0) {goto B9;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061728));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B10;}
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061728), j1);
  goto B9;
  B10:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061732));
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = l1;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 32), i1);
  B9:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  goto B1;
  B5:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B4:;
  i0 = l0;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l0;
  i1 = l4;
  i2 = 0u;
  i1 = i1 != i2;
  i32_store8((&memory), (u64)(i0 + 76), i1);
  i0 = 1051420u;
  i1 = 43u;
  i2 = l0;
  i3 = 72u;
  i2 += i3;
  i3 = 1051464u;
  i4 = 1051572u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B3:;
  i0 = 1051588u;
  i1 = 23u;
  i2 = 1051612u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B2:;
  i0 = l0;
  i1 = 40u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 27u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = 52u;
  i0 += i1;
  i1 = 30u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = l0;
  i2 = 12u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 64), i1);
  i0 = l0;
  i1 = 1051628u;
  i32_store((&memory), (u64)(i0 + 68), i1);
  i0 = l0;
  i1 = 72u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l0;
  j1 = 3ull;
  i64_store((&memory), (u64)(i0 + 20), j1);
  i0 = l0;
  i1 = 1051304u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l0;
  i1 = 30u;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l0;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 88), i1);
  i0 = l0;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 76), j1);
  i0 = l0;
  i1 = 1051664u;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l0;
  i1 = l0;
  i2 = 40u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l0;
  i1 = l0;
  i2 = 72u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l0;
  i1 = l0;
  i2 = 68u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l0;
  i1 = l0;
  i2 = 64u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  i1 = 1051672u;
  _ZN3std9panicking15begin_panic_fmt17h3bc495be3b042206E(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = l0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l1 = i0;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1));
  l1 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B11;}
  i0 = l0;
  i1 = 8u;
  i0 += i1;
  _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h54081c59c02bd7eaE(i0);
  B11:;
  i0 = l0;
  i1 = 96u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN3std4sync7condvar7Condvar6verify17h950e8c3c7a86a681E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  l2 = i1;
  i2 = p1;
  i3 = l2;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l2;
  i1 = p1;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = 1053128u;
  i1 = 54u;
  i2 = 1053208u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  FUNC_EPILOGUE;
}

static void _ZN3std10sys_common7condvar7Condvar4wait17hb99804595d9707a7E(void) {
  u32 l0 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = l0;
  i1 = l0;
  _ZN3std3sys4wasi7condvar7Condvar4wait17h08e64e77fb399e8fE(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN3std9panicking15begin_panic_fmt17h3bc495be3b042206E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p1;
  i1 = _ZN4core5panic8Location6caller17ha977844962a520efE(i1);
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  rust_begin_unwind(i0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN3std6thread6Thread3new17h1d02bb6db813b9d0E(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0;
  u64 l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1, j2;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  if (i0) {goto B5;}
  i0 = 0u;
  l3 = i0;
  goto B4;
  B5:;
  i0 = l1;
  i1 = p0;
  j1 = i64_load((&memory), (u64)(i1 + 4));
  i64_store((&memory), (u64)(i0 + 36), j1);
  i0 = l1;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  i1 = l1;
  i2 = 32u;
  i1 += i2;
  _ZN5alloc6string104__LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__vec__Vec_LT_u8_GT__GT_4from17h645290af10f55923E(i0, i1);
  i0 = l1;
  i1 = 8u;
  i0 += i1;
  i1 = 0u;
  i2 = l1;
  i2 = i32_load((&memory), (u64)(i2 + 16));
  p0 = i2;
  i3 = l1;
  i3 = i32_load((&memory), (u64)(i3 + 24));
  _ZN4core5slice6memchr6memchr17h4b6f86a8dda0136aE(i0, i1, i2, i3);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  if (i0) {goto B3;}
  i0 = l1;
  i1 = 32u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l1;
  i2 = 16u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = l1;
  j1 = i64_load((&memory), (u64)(i1 + 16));
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = l1;
  i1 = l1;
  i2 = 32u;
  i1 += i2;
  _ZN3std3ffi5c_str7CString18from_vec_unchecked17h48bedb0a7532b717E(i0, i1);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l4 = i0;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  B4:;
  i0 = 0u;
  i0 = i32_load8_u((&memory), (u64)(i0 + 1061736));
  if (i0) {goto B2;}
  i0 = 0u;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 1061736), i1);
  i0 = 0u;
  j0 = i64_load((&memory), (u64)(i0 + 1061624));
  l5 = j0;
  j1 = 18446744073709551615ull;
  i0 = j0 == j1;
  if (i0) {goto B7;}
  i0 = 0u;
  j1 = l5;
  j2 = 1ull;
  j1 += j2;
  i64_store((&memory), (u64)(i0 + 1061624), j1);
  j0 = l5;
  j1 = 0ull;
  i0 = j0 != j1;
  if (i0) {goto B6;}
  i0 = 1051328u;
  i1 = 43u;
  i2 = 1051760u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B7:;
  i0 = 1051688u;
  i1 = 55u;
  i2 = 1051744u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B6:;
  i0 = 0u;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1061736), i1);
  i0 = 1u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l2;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = 48u;
  i1 = 8u;
  i0 = __rust_alloc(i0, i1);
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 36), j1);
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = p0;
  j1 = l5;
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = p0;
  j1 = 4294967297ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = l2;
  j1 = (u64)(i1);
  i64_store((&memory), (u64)(i0 + 28), j1);
  i0 = l1;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  goto Bfunc;
  B3:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l2 = i0;
  i0 = l1;
  i1 = 40u;
  i0 += i1;
  i1 = l1;
  j1 = i64_load((&memory), (u64)(i1 + 20));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l1;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = 1051776u;
  i1 = 47u;
  i2 = l1;
  i3 = 32u;
  i2 += i3;
  i3 = 1051388u;
  i4 = 1051824u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B2:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = 1u;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 48u;
  i1 = 8u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std3ffi5c_str7CString18from_vec_unchecked17h48bedb0a7532b717E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  l3 = i1;
  i0 = i0 != i1;
  if (i0) {goto B5;}
  i0 = l3;
  i1 = 1u;
  i0 += i1;
  l2 = i0;
  i1 = l3;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l2;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B4;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  if (i0) {goto B9;}
  B10:;
  i0 = l2;
  if (i0) {goto B8;}
  i0 = 1u;
  l4 = i0;
  goto B6;
  B9:;
  i0 = l3;
  i1 = l2;
  i0 = i0 == i1;
  if (i0) {goto B11;}
  i0 = l4;
  i1 = l3;
  i2 = 1u;
  i3 = l2;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l4 = i0;
  B11:;
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B7;}
  goto B6;
  B8:;
  i0 = l2;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  if (i0) {goto B6;}
  B7:;
  i0 = l2;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B6:;
  i0 = p1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  B5:;
  i0 = l3;
  i1 = l2;
  i0 = i0 == i1;
  if (i0) {goto B12;}
  i0 = l3;
  i1 = 1u;
  i0 += i1;
  l4 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  goto B0;
  B12:;
  i0 = l3;
  i1 = 1u;
  i0 += i1;
  l4 = i0;
  i1 = l3;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l3;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l2 = i0;
  i1 = l4;
  i2 = l2;
  i3 = l4;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l2 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B4;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B14;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  if (i0) {goto B13;}
  B14:;
  i0 = l2;
  if (i0) {goto B3;}
  i0 = 1u;
  l5 = i0;
  goto B1;
  B13:;
  i0 = l3;
  i1 = l2;
  i0 = i0 == i1;
  if (i0) {goto B15;}
  i0 = l5;
  i1 = l3;
  i2 = 1u;
  i3 = l2;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l5 = i0;
  B15:;
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B2;}
  goto B1;
  B4:;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  B3:;
  i0 = l2;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l5 = i0;
  if (i0) {goto B1;}
  B2:;
  i0 = l2;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = p1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  B0:;
  i0 = l5;
  i1 = l3;
  i0 += i1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = l4;
  i0 = i0 != i1;
  if (i0) {goto B17;}
  i0 = l5;
  l3 = i0;
  goto B16;
  B17:;
  i0 = l2;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B19;}
  i0 = l2;
  if (i0) {goto B18;}
  i0 = l5;
  l3 = i0;
  goto B16;
  B19:;
  i0 = 1051496u;
  i1 = 36u;
  i2 = 1051044u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B18:;
  i0 = l4;
  if (i0) {goto B20;}
  i0 = 1u;
  l3 = i0;
  i0 = l5;
  i1 = l2;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  goto B16;
  B20:;
  i0 = l5;
  i1 = l2;
  i2 = 1u;
  i3 = l4;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l3 = i0;
  if (i0) {goto B16;}
  i0 = l4;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B16:;
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN3std3sys4wasi11unsupported17hd974f16cf85baeceE(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = 35u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 31u;
  i0 += i1;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1055299));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 24u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1055292));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1055284));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1055276));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1055268));
  i64_store((&memory), (u64)(i0), j1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l3;
  j1 = 150323855395ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l3;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l2;
  i1 = 16u;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 1052004u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l1;
  i1 = i32_load16_u((&memory), (u64)(i1 + 13));
  i32_store16((&memory), (u64)(i0 + 9), i1);
  i0 = l2;
  i1 = 11u;
  i0 += i1;
  i1 = l1;
  i2 = 15u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  j1 = 8589934593ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B2:;
  i0 = 35u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN3std3env7_var_os17h65122ae02361542aE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0;
  u64 l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 80u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l3;
  i1 = 64u;
  i0 += i1;
  i1 = p1;
  i2 = p2;
  _ZN70__LT__RF_str_u20_as_u20_std__ffi__c_str__CString__new__SpecIntoVec_GT_8into_vec17h65a4d42209f91185E(i0, i1, i2);
  i0 = 0u;
  p1 = i0;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  i1 = 0u;
  i2 = l3;
  i2 = i32_load((&memory), (u64)(i2 + 64));
  p2 = i2;
  i3 = l3;
  i3 = i32_load((&memory), (u64)(i3 + 72));
  _ZN4core5slice6memchr6memchr17h4b6f86a8dda0136aE(i0, i1, i2, i3);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  if (i0) {goto B0;}
  i0 = l3;
  i1 = 40u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l3;
  i2 = 64u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 64));
  i64_store((&memory), (u64)(i0 + 40), j1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = l3;
  i2 = 40u;
  i1 += i2;
  _ZN3std3ffi5c_str7CString18from_vec_unchecked17h48bedb0a7532b717E(i0, i1);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l4 = i0;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l5 = i0;
  i0 = getenv(i0);
  l6 = i0;
  if (i0) {goto B3;}
  goto B2;
  B3:;
  i0 = l6;
  i0 = i32_load8_u((&memory), (u64)(i0));
  if (i0) {goto B5;}
  i0 = 0u;
  l7 = i0;
  goto B4;
  B5:;
  i0 = l6;
  i1 = 1u;
  i0 += i1;
  l8 = i0;
  i0 = 0u;
  p1 = i0;
  L6: 
    i0 = l8;
    i1 = p1;
    i0 += i1;
    p2 = i0;
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    l7 = i0;
    p1 = i0;
    i0 = p2;
    i0 = i32_load8_u((&memory), (u64)(i0));
    if (i0) {goto L6;}
  i0 = l7;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  B4:;
  i0 = l3;
  i1 = 40u;
  i0 += i1;
  i1 = l6;
  i2 = l7;
  _ZN5alloc5slice29__LT_impl_u20__u5b_T_u5d__GT_6to_vec17h2392cf0518e8ca41E(i0, i1, i2);
  i0 = l3;
  j0 = i64_load((&memory), (u64)(i0 + 44));
  l9 = j0;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 40));
  p1 = i0;
  B2:;
  i0 = l5;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = l5;
  i1 = l4;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B7:;
  i0 = p0;
  j1 = l9;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 80u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B1:;
  i0 = l7;
  i1 = 0u;
  i2 = 1052108u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  p1 = i0;
  i0 = l3;
  i1 = 48u;
  i0 += i1;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 68));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l3;
  i1 = 64u;
  i0 += i1;
  i1 = l3;
  i2 = 40u;
  i1 += i2;
  _ZN3std3ffi5c_str104__LT_impl_u20_core__convert__From_LT_std__ffi__c_str__NulError_GT__u20_for_u20_std__io__error__Error_GT_4from17he7bd34cf5a7ddaa1E(i0, i1);
  i0 = l3;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 64));
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = l3;
  i1 = 60u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 76u;
  i0 += i1;
  i1 = 31u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 44), j1);
  i0 = l3;
  i1 = 1051972u;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l3;
  i1 = 32u;
  i32_store((&memory), (u64)(i0 + 68), i1);
  i0 = l3;
  i1 = l3;
  i2 = 64u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l3;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l3;
  i1 = l3;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 64), i1);
  i0 = l3;
  i1 = 40u;
  i0 += i1;
  i1 = 1051988u;
  _ZN3std9panicking15begin_panic_fmt17h3bc495be3b042206E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN70__LT__RF_str_u20_as_u20_std__ffi__c_str__CString__new__SpecIntoVec_GT_8into_vec17h65a4d42209f91185E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = 1u;
  l3 = i0;
  i0 = p2;
  i1 = 1u;
  i0 += i1;
  l4 = i0;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B4;}
  i0 = l4;
  if (i0) {goto B6;}
  i0 = 0u;
  l4 = i0;
  goto B5;
  B6:;
  i0 = l4;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  B5:;
  i0 = l4;
  i1 = p2;
  i0 = i0 >= i1;
  if (i0) {goto B0;}
  i0 = l4;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = p2;
  i2 = l5;
  i3 = p2;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = l3;
  if (i0) {goto B8;}
  B9:;
  i0 = l5;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l3 = i0;
  if (i0) {goto B1;}
  goto B7;
  B8:;
  i0 = l4;
  i1 = l5;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = l3;
  i1 = l4;
  i2 = 1u;
  i3 = l5;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l3 = i0;
  if (i0) {goto B1;}
  B7:;
  i0 = l5;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B4:;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h132ff70aff78c839E();
  UNREACHABLE;
  B3:;
  i0 = l4;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B2:;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  B1:;
  i0 = l5;
  l4 = i0;
  B0:;
  i0 = l3;
  i1 = p1;
  i2 = p2;
  i0 = memcpy_0(i0, i1, i2);
  l3 = i0;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN3std3ffi5c_str104__LT_impl_u20_core__convert__From_LT_std__ffi__c_str__NulError_GT__u20_for_u20_std__io__error__Error_GT_4from17he7bd34cf5a7ddaa1E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = 33u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  i1 = 0u;
  i1 = i32_load8_u((&memory), (u64)(i1 + 1052084));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 24u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1052076));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1052068));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1052060));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1052052));
  i64_store((&memory), (u64)(i0), j1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l4;
  j1 = 141733920801ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l4;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l3;
  i1 = 11u;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = 1052004u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l2;
  i1 = i32_load16_u((&memory), (u64)(i1 + 13));
  i32_store16((&memory), (u64)(i0 + 9), i1);
  i0 = l3;
  i1 = 11u;
  i0 += i1;
  i1 = l2;
  i2 = 13u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 2u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l2;
  i1 = i32_load16_u((&memory), (u64)(i1 + 10));
  i32_store16((&memory), (u64)(i0 + 1), i1);
  i0 = p0;
  i1 = 3u;
  i0 += i1;
  i1 = l2;
  i2 = 10u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l3;
  i1 = p0;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B2:;
  i0 = 33u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 _ZN60__LT_std__io__error__Error_u20_as_u20_core__fmt__Display_GT_3fmt17h12ea3a633b564efaE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  switch (i0) {
    case 0: goto B2;
    case 1: goto B3;
    case 2: goto B1;
    default: goto B2;
  }
  B3:;
  i0 = 1052268u;
  l3 = i0;
  i0 = 22u;
  l4 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 1));
  switch (i0) {
    case 0: goto B22;
    case 1: goto B21;
    case 2: goto B20;
    case 3: goto B19;
    case 4: goto B18;
    case 5: goto B17;
    case 6: goto B16;
    case 7: goto B15;
    case 8: goto B14;
    case 9: goto B13;
    case 10: goto B12;
    case 11: goto B11;
    case 12: goto B10;
    case 13: goto B9;
    case 14: goto B8;
    case 15: goto B7;
    case 16: goto B6;
    case 17: goto B4;
    default: goto B22;
  }
  B22:;
  i0 = 1052549u;
  l3 = i0;
  i0 = 16u;
  l4 = i0;
  goto B4;
  B21:;
  i0 = 1052532u;
  l3 = i0;
  i0 = 17u;
  l4 = i0;
  goto B4;
  B20:;
  i0 = 1052514u;
  l3 = i0;
  i0 = 18u;
  l4 = i0;
  goto B4;
  B19:;
  i0 = 1052498u;
  l3 = i0;
  i0 = 16u;
  l4 = i0;
  goto B4;
  B18:;
  i0 = 1052480u;
  l3 = i0;
  i0 = 18u;
  l4 = i0;
  goto B4;
  B17:;
  i0 = 1052467u;
  l3 = i0;
  i0 = 13u;
  l4 = i0;
  goto B4;
  B16:;
  i0 = 1052453u;
  l3 = i0;
  goto B5;
  B15:;
  i0 = 1052432u;
  l3 = i0;
  i0 = 21u;
  l4 = i0;
  goto B4;
  B14:;
  i0 = 1052421u;
  l3 = i0;
  i0 = 11u;
  l4 = i0;
  goto B4;
  B13:;
  i0 = 1052400u;
  l3 = i0;
  i0 = 21u;
  l4 = i0;
  goto B4;
  B12:;
  i0 = 1052379u;
  l3 = i0;
  i0 = 21u;
  l4 = i0;
  goto B4;
  B11:;
  i0 = 1052356u;
  l3 = i0;
  i0 = 23u;
  l4 = i0;
  goto B4;
  B10:;
  i0 = 1052344u;
  l3 = i0;
  i0 = 12u;
  l4 = i0;
  goto B4;
  B9:;
  i0 = 1052335u;
  l3 = i0;
  i0 = 9u;
  l4 = i0;
  goto B4;
  B8:;
  i0 = 1052325u;
  l3 = i0;
  i0 = 10u;
  l4 = i0;
  goto B4;
  B7:;
  i0 = 1052304u;
  l3 = i0;
  i0 = 21u;
  l4 = i0;
  goto B4;
  B6:;
  i0 = 1052290u;
  l3 = i0;
  B5:;
  i0 = 14u;
  l4 = i0;
  B4:;
  i0 = l2;
  i1 = 60u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l2;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l2;
  i1 = 33u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 44), j1);
  i0 = l2;
  i1 = 1052640u;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l2;
  i1 = l2;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = p1;
  i1 = l2;
  i2 = 40u;
  i1 += i2;
  i0 = _ZN4core3fmt9Formatter9write_fmt17h5f4a789bf06948b3E(i0, i1);
  p0 = i0;
  goto B0;
  B2:;
  i0 = l2;
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  p0 = i1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  _ZN3std3sys4wasi2os12error_string17h2cf85a3df68353a7E(i0, i1);
  i0 = l2;
  i1 = 60u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 36u;
  i0 += i1;
  i1 = 34u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  j1 = 3ull;
  i64_store((&memory), (u64)(i0 + 44), j1);
  i0 = l2;
  i1 = 1052660u;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l2;
  i1 = 35u;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l2;
  i1 = l2;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l2;
  i1 = l2;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l2;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = p1;
  i1 = l2;
  i2 = 40u;
  i1 += i2;
  i0 = _ZN4core3fmt9Formatter9write_fmt17h5f4a789bf06948b3E(i0, i1);
  p0 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = l3;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  goto B0;
  B1:;
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i2 = i32_load((&memory), (u64)(i2 + 32));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  p0 = i0;
  B0:;
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN55__LT_std__path__Display_u20_as_u20_core__fmt__Debug_GT_3fmt17hfa561203d2c037b8E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p1;
  i0 = _ZN73__LT_std__sys_common__os_str_bytes__Slice_u20_as_u20_core__fmt__Debug_GT_3fmt17h48c636194360662dE(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u64 _ZN3std5error5Error7type_id17h57e588fb6656ec7eE(u32 p0) {
  FUNC_PROLOGUE;
  u64 j0;
  j0 = 5771058436666545696ull;
  FUNC_EPILOGUE;
  return j0;
}

static u32 _ZN3std5error5Error9backtrace17he16cc217c1a2f33bE(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = 0u;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std5error5Error5cause17h4f470d68a88d26ceE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN243__LT_std__error___LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__boxed__Box_LT_dyn_u20_std__error__Error_u2b_core__marker__Sync_u2b_core__marker__Send_GT__GT___from__StringError_u20_as_u20_std__error__Error_GT_11description17h29c39b0cc2d10c9fE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static u32 _ZN244__LT_std__error___LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__boxed__Box_LT_dyn_u20_std__error__Error_u2b_core__marker__Sync_u2b_core__marker__Send_GT__GT___from__StringError_u20_as_u20_core__fmt__Display_GT_3fmt17h36f89103f15672f6E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i2 = p1;
  i0 = _ZN42__LT_str_u20_as_u20_core__fmt__Display_GT_3fmt17h503be603f26e92cbE(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN242__LT_std__error___LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__boxed__Box_LT_dyn_u20_std__error__Error_u2b_core__marker__Sync_u2b_core__marker__Send_GT__GT___from__StringError_u20_as_u20_core__fmt__Debug_GT_3fmt17hd9db4bd6825b019cE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i2 = p1;
  i0 = _ZN40__LT_str_u20_as_u20_core__fmt__Debug_GT_3fmt17hc81f6984a0ce9960E(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN61__LT_std__ffi__c_str__CString_u20_as_u20_core__fmt__Debug_GT_3fmt17h76df9c6c5e27e8efE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = p1;
  i0 = _ZN58__LT_std__ffi__c_str__CStr_u20_as_u20_core__fmt__Debug_GT_3fmt17h28e0d8bc9678db10E(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std3sys4wasi2fs11open_parent17h2bf813dab646b1efE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 80u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = 64u;
  i0 += i1;
  i1 = p1;
  i2 = p2;
  _ZN70__LT__RF_str_u20_as_u20_std__ffi__c_str__CString__new__SpecIntoVec_GT_8into_vec17h65a4d42209f91185E(i0, i1, i2);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = 0u;
  i2 = l3;
  i2 = i32_load((&memory), (u64)(i2 + 64));
  p1 = i2;
  i3 = l3;
  i3 = i32_load((&memory), (u64)(i3 + 72));
  _ZN4core5slice6memchr6memchr17h4b6f86a8dda0136aE(i0, i1, i2, i3);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  if (i0) {goto B6;}
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  p2 = i0;
  i1 = l3;
  i2 = 64u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  l4 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 64));
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = l3;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  _ZN3std3ffi5c_str7CString18from_vec_unchecked17h48bedb0a7532b717E(i0, i1);
  i0 = l3;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = l3;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1));
  p1 = i1;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l3;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = p1;
  i1 = l3;
  i2 = 28u;
  i1 += i2;
  i0 = __wasilibc_find_relpath(i0, i1);
  l5 = i0;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B5;}
  i0 = 0u;
  l6 = i0;
  i0 = 0u;
  l4 = i0;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  l7 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = l7;
  i1 = 1u;
  i0 += i1;
  l8 = i0;
  i0 = 0u;
  p1 = i0;
  L8: 
    i0 = l8;
    i1 = p1;
    i0 += i1;
    p2 = i0;
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    p1 = i0;
    i0 = p2;
    i0 = i32_load8_u((&memory), (u64)(i0));
    if (i0) {goto L8;}
  i0 = l4;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B3;}
  B7:;
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  i1 = l7;
  i2 = l4;
  _ZN5alloc5slice29__LT_impl_u20__u5b_T_u5d__GT_6to_vec17h2392cf0518e8ca41E(i0, i1, i2);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 32));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 16u;
  i0 += i1;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  goto B4;
  B6:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  p2 = i0;
  i0 = l3;
  i1 = 40u;
  i0 += i1;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 68));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l3;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l3;
  i1 = 64u;
  i0 += i1;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  _ZN3std3ffi5c_str104__LT_impl_u20_core__convert__From_LT_std__ffi__c_str__NulError_GT__u20_for_u20_std__io__error__Error_GT_4from17he7bd34cf5a7ddaa1E(i0, i1);
  i0 = p0;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 64));
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  goto B0;
  B5:;
  i0 = l3;
  i1 = 52u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 36), j1);
  i0 = l3;
  i1 = 1054960u;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l3;
  i1 = 36u;
  i32_store((&memory), (u64)(i0 + 60), i1);
  i0 = l3;
  i1 = l3;
  i2 = 56u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l3;
  i1 = l3;
  i2 = 16u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l3;
  i1 = 64u;
  i0 += i1;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  _ZN5alloc3fmt6format17h791816ebd75606e6E(i0, i1);
  i0 = p2;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 64));
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p2;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 32));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p2;
  i1 = 8u;
  i0 += i1;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  i1 = 16u;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = p1;
  i1 = 1052004u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p1;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l3;
  i1 = i32_load16_u((&memory), (u64)(i1 + 32));
  i32_store16((&memory), (u64)(i0 + 9), i1);
  i0 = p1;
  i1 = 11u;
  i0 += i1;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 2u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 1u;
  l6 = i0;
  B4:;
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  i1 = p1;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  goto B0;
  B3:;
  i0 = l4;
  i1 = 0u;
  i2 = 1052108u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B2:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = l3;
  i1 = 80u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN3std3sys4wasi2fs7open_at17h2ff12843dac03953E(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4) {
  u32 l5 = 0, l6 = 0, l7 = 0, l8 = 0;
  u64 l9 = 0, l10 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i8;
  u64 j0, j1, j2, j6, j7;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l5 = i0;
  g0 = i0;
  i0 = p4;
  i0 = i32_load((&memory), (u64)(i0 + 32));
  l6 = i0;
  i0 = l5;
  i1 = p2;
  i2 = p3;
  _ZN3std3sys4wasi2fs9osstr2str17h2b93d5c461792507E(i0, i1, i2);
  i0 = l5;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p2 = i0;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p3 = i0;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0));
  l7 = i0;
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B2;}
  i0 = p4;
  i0 = i32_load16_u((&memory), (u64)(i0 + 38));
  l8 = i0;
  i0 = p4;
  j0 = i64_load((&memory), (u64)(i0));
  l9 = j0;
  j1 = 1ull;
  i0 = j0 == j1;
  if (i0) {goto B4;}
  j0 = 16386ull;
  j1 = 0ull;
  i2 = p4;
  i2 = i32_load8_u((&memory), (u64)(i2 + 40));
  j0 = i2 ? j0 : j1;
  l10 = j0;
  j1 = 4194625ull;
  j0 |= j1;
  j1 = l10;
  i2 = p4;
  i2 = i32_load8_u((&memory), (u64)(i2 + 41));
  j0 = i2 ? j0 : j1;
  j1 = 260554428ull;
  j0 |= j1;
  l10 = j0;
  goto B3;
  B4:;
  i0 = p4;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l10 = j0;
  B3:;
  i0 = p4;
  j0 = i64_load((&memory), (u64)(i0 + 16));
  j1 = 0ull;
  i0 = j0 == j1;
  if (i0) {goto B6;}
  i0 = p4;
  i1 = 24u;
  i0 += i1;
  j0 = i64_load((&memory), (u64)(i0));
  l9 = j0;
  goto B5;
  B6:;
  j0 = l9;
  j1 = 0ull;
  i0 = j0 != j1;
  if (i0) {goto B7;}
  j0 = 16386ull;
  j1 = 0ull;
  i2 = p4;
  i2 = i32_load8_u((&memory), (u64)(i2 + 40));
  j0 = i2 ? j0 : j1;
  l9 = j0;
  j1 = 4194625ull;
  j0 |= j1;
  j1 = l9;
  i2 = p4;
  i2 = i32_load8_u((&memory), (u64)(i2 + 41));
  j0 = i2 ? j0 : j1;
  j1 = 260554428ull;
  j0 |= j1;
  l9 = j0;
  goto B5;
  B7:;
  i0 = p4;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l9 = j0;
  B5:;
  i0 = l5;
  i1 = p1;
  i2 = l6;
  i3 = p3;
  i4 = p2;
  i5 = l8;
  j6 = l10;
  j7 = l9;
  i8 = p4;
  i8 = i32_load16_u((&memory), (u64)(i8 + 36));
  _ZN4wasi13lib_generated9path_open17h60ff9154cd4f4a34E(i0, i1, i2, i3, i4, i5, j6, j7, i8);
  i0 = l5;
  i0 = i32_load16_u((&memory), (u64)(i0));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p4 = i0;
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = p3;
  i1 = 255u;
  i0 &= i1;
  i1 = 2u;
  i0 = i0 < i1;
  if (i0) {goto B8;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p2;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p3 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p3;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B9:;
  i0 = p2;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B8:;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p4;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B0;
  B2:;
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p2;
  j1 = (u64)(i1);
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i2 = p3;
  j2 = (u64)(i2);
  j1 |= j2;
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B0;
  B1:;
  i0 = l5;
  i1 = l5;
  i1 = i32_load16_u((&memory), (u64)(i1 + 2));
  i32_store16((&memory), (u64)(i0), i1);
  i0 = l5;
  i0 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i0);
  p4 = i0;
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p4;
  j1 = (u64)(i1);
  j2 = 65535ull;
  j1 &= j2;
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p3;
  i1 = 255u;
  i0 &= i1;
  i1 = 2u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p2;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p4 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i2 = p4;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B10:;
  i0 = p2;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = l5;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN47__LT_std__fs__File_u20_as_u20_std__io__Read_GT_4read17h1f42a62b4fce9d8aE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1, j2;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = l4;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l4;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = 1u;
  p2 = i0;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = l4;
  i3 = 8u;
  i2 += i3;
  i3 = 1u;
  _ZN4wasi13lib_generated7fd_read17h0d476bb7732cd2ceE(i0, i1, i2, i3);
  i0 = l4;
  i0 = i32_load16_u((&memory), (u64)(i0 + 16));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = l4;
  i1 = l4;
  i1 = i32_load16_u((&memory), (u64)(i1 + 18));
  i32_store16((&memory), (u64)(i0 + 30), i1);
  i0 = p0;
  i1 = l4;
  i2 = 30u;
  i1 += i2;
  i1 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i1);
  j1 = (u64)(i1);
  j2 = 65535ull;
  j1 &= j2;
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B0;
  B1:;
  i0 = p0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  p2 = i0;
  B0:;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN3std2fs11OpenOptions3new17he0d0cef85f34602fE(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  u64 j1;
  i0 = p0;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = p0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = p0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 40u;
  i0 += i1;
  i1 = 0u;
  i32_store16((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static u32 _ZN3std2fs11OpenOptions4read17h7401959d78f75c40E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 40), i1);
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std2fs11OpenOptions5_open17h3cc2934c37bbaa9aE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  u64 l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1, j2, j3, j4;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = l4;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  i2 = p3;
  _ZN3std3sys4wasi2fs11open_parent17h2bf813dab646b1efE(i0, i1, i2);
  i0 = l4;
  j0 = i64_load((&memory), (u64)(i0 + 12));
  l5 = j0;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = l4;
  i1 = 8u;
  i0 += i1;
  j1 = l5;
  i1 = (u32)(j1);
  j2 = l5;
  j3 = 32ull;
  j2 >>= (j3 & 63);
  i2 = (u32)(j2);
  p2 = i2;
  i3 = l4;
  i4 = 20u;
  i3 += i4;
  j3 = i64_load((&memory), (u64)(i3));
  l5 = j3;
  j4 = 32ull;
  j3 >>= (j4 & 63);
  i3 = (u32)(j3);
  i4 = p1;
  _ZN3std3sys4wasi2fs7open_at17h2ff12843dac03953E(i0, i1, i2, i3, i4);
  j0 = l5;
  i0 = (u32)(j0);
  p3 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p2;
  i1 = p3;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  goto B0;
  B1:;
  i0 = l4;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  j1 = l5;
  i64_store((&memory), (u64)(i0 + 12), j1);
  B0:;
  i0 = 1u;
  p2 = i0;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B3;}
  i0 = p0;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1 + 12));
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B2;
  B3:;
  i0 = p0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 12));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  p2 = i0;
  B2:;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN3std3sys4wasi17decode_error_kind17he23a249a9ada7316E(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = 16u;
  l1 = i0;
  i0 = p0;
  i1 = 65535u;
  i0 = i0 > i1;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 65535u;
  i0 &= i1;
  i1 = 4294967294u;
  i0 += i1;
  p0 = i0;
  i1 = 71u;
  i0 = i0 > i1;
  if (i0) {goto B0;}
  i0 = p0;
  switch (i0) {
    case 0: goto B12;
    case 1: goto B7;
    case 2: goto B8;
    case 3: goto B0;
    case 4: goto B1;
    case 5: goto B0;
    case 6: goto B0;
    case 7: goto B0;
    case 8: goto B0;
    case 9: goto B0;
    case 10: goto B0;
    case 11: goto B9;
    case 12: goto B14;
    case 13: goto B13;
    case 14: goto B0;
    case 15: goto B0;
    case 16: goto B0;
    case 17: goto B0;
    case 18: goto B2;
    case 19: goto B0;
    case 20: goto B0;
    case 21: goto B0;
    case 22: goto B0;
    case 23: goto B0;
    case 24: goto B0;
    case 25: goto B5;
    case 26: goto B4;
    case 27: goto B0;
    case 28: goto B0;
    case 29: goto B0;
    case 30: goto B0;
    case 31: goto B0;
    case 32: goto B0;
    case 33: goto B0;
    case 34: goto B0;
    case 35: goto B0;
    case 36: goto B0;
    case 37: goto B0;
    case 38: goto B0;
    case 39: goto B0;
    case 40: goto B0;
    case 41: goto B0;
    case 42: goto B6;
    case 43: goto B0;
    case 44: goto B0;
    case 45: goto B0;
    case 46: goto B0;
    case 47: goto B0;
    case 48: goto B0;
    case 49: goto B0;
    case 50: goto B0;
    case 51: goto B10;
    case 52: goto B0;
    case 53: goto B0;
    case 54: goto B0;
    case 55: goto B0;
    case 56: goto B0;
    case 57: goto B0;
    case 58: goto B0;
    case 59: goto B0;
    case 60: goto B0;
    case 61: goto B12;
    case 62: goto B11;
    case 63: goto B0;
    case 64: goto B0;
    case 65: goto B0;
    case 66: goto B0;
    case 67: goto B0;
    case 68: goto B0;
    case 69: goto B0;
    case 70: goto B0;
    case 71: goto B3;
    default: goto B12;
  }
  B14:;
  i0 = 2u;
  goto Bfunc;
  B13:;
  i0 = 3u;
  goto Bfunc;
  B12:;
  i0 = 1u;
  goto Bfunc;
  B11:;
  i0 = 8u;
  goto Bfunc;
  B10:;
  i0 = 5u;
  goto Bfunc;
  B9:;
  i0 = 4u;
  goto Bfunc;
  B8:;
  i0 = 7u;
  goto Bfunc;
  B7:;
  i0 = 6u;
  goto Bfunc;
  B6:;
  i0 = 0u;
  goto Bfunc;
  B5:;
  i0 = 15u;
  goto Bfunc;
  B4:;
  i0 = 11u;
  goto Bfunc;
  B3:;
  i0 = 13u;
  goto Bfunc;
  B2:;
  i0 = 9u;
  goto Bfunc;
  B1:;
  i0 = 10u;
  l1 = i0;
  B0:;
  i0 = l1;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN72__LT_std__io__buffered__BufWriter_LT_W_GT__u20_as_u20_std__io__Write_GT_5write17h98b8ed5b902ebbc8E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0;
  u64 l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1, j2;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p3;
  i0 += i1;
  i1 = p1;
  i2 = 4u;
  i1 += i2;
  l5 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  i0 = i0 <= i1;
  if (i0) {goto B3;}
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  _ZN3std2io8buffered18BufWriter_LT_W_GT_9flush_buf17hd67ccca3c7d9e3cdE(i0, i1);
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  l6 = i0;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l7 = i0;
  i1 = 255u;
  i0 &= i1;
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B2;}
  i0 = 0u;
  if (i0) {goto B4;}
  i0 = l7;
  i1 = 3u;
  i0 &= i1;
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B3;}
  B4:;
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l7 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l8 = i0;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l8;
  i2 = l7;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B5:;
  i0 = l6;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p3;
  i0 = i0 <= i1;
  if (i0) {goto B1;}
  i0 = p1;
  i1 = p2;
  i2 = p2;
  i3 = p3;
  i2 += i3;
  _ZN109__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_alloc__vec__SpecExtend_LT__RF_T_C_core__slice__Iter_LT_T_GT__GT__GT_11spec_extend17hce2eec127ad34cc7E(i0, i1, i2);
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B0;
  B2:;
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l6;
  j1 = (u64)(i1);
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i2 = l7;
  j2 = (u64)(i2);
  j1 |= j2;
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B0;
  B1:;
  i0 = p1;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = p1;
  i0 = i32_load8_u((&memory), (u64)(i0 + 12));
  i1 = 4294967295u;
  i0 += i1;
  l5 = i0;
  i1 = 1u;
  i0 = i0 > i1;
  if (i0) {goto B7;}
  i0 = l5;
  switch (i0) {
    case 0: goto B8;
    case 1: goto B9;
    default: goto B8;
  }
  B9:;
  i0 = 1051328u;
  i1 = 43u;
  i2 = 1052236u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B8:;
  i0 = p3;
  j0 = (u64)(i0);
  l9 = j0;
  i0 = 0u;
  p3 = i0;
  goto B6;
  B7:;
  i0 = l4;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l4;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = 1u;
  i2 = l4;
  i3 = 8u;
  i2 += i3;
  i3 = 1u;
  _ZN4wasi13lib_generated8fd_write17hacbf9079620e9958E(i0, i1, i2, i3);
  i0 = l4;
  i0 = i32_load16_u((&memory), (u64)(i0 + 16));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B10;}
  i0 = l4;
  j0 = i64_load32_u((&memory), (u64)(i0 + 20));
  l9 = j0;
  i0 = 0u;
  p3 = i0;
  goto B6;
  B10:;
  i0 = l4;
  i1 = l4;
  i1 = i32_load16_u((&memory), (u64)(i1 + 18));
  i32_store16((&memory), (u64)(i0 + 30), i1);
  i0 = p3;
  j0 = (u64)(i0);
  i1 = l4;
  i2 = 30u;
  i1 += i2;
  i1 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i1);
  p3 = i1;
  j1 = (u64)(i1);
  j2 = 65535ull;
  j1 &= j2;
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i2 = p3;
  i3 = 65535u;
  i2 &= i3;
  p3 = i2;
  i3 = 8u;
  i2 = i2 == i3;
  j0 = i2 ? j0 : j1;
  l9 = j0;
  i0 = p3;
  i1 = 8u;
  i0 = i0 != i1;
  p3 = i0;
  B6:;
  i0 = p0;
  j1 = l9;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = p0;
  i1 = p3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  B0:;
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN58__LT_std__io__error__Error_u20_as_u20_core__fmt__Debug_GT_3fmt17he9ea5949f4a2990eE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p1;
  i0 = _ZN57__LT_std__io__error__Repr_u20_as_u20_core__fmt__Debug_GT_3fmt17h35f993de34bdfaf1E(i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std2io5error5Error4_new17h276c50b6edbce93bE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l5 = i0;
  if (i0) {goto B0;}
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = l5;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = l5;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l5;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = l4;
  i1 = i32_load16_u((&memory), (u64)(i1 + 13));
  i32_store16((&memory), (u64)(i0 + 9), i1);
  i0 = l5;
  i1 = 11u;
  i0 += i1;
  i1 = l4;
  i2 = 13u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 2u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l4;
  i1 = i32_load16_u((&memory), (u64)(i1 + 10));
  i32_store16((&memory), (u64)(i0 + 1), i1);
  i0 = p0;
  i1 = 3u;
  i0 += i1;
  i1 = l4;
  i2 = 10u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN3std2io5error5Error4kind17hdcfd08845a3d8932E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  switch (i0) {
    case 0: goto B1;
    case 1: goto B2;
    case 2: goto B0;
    default: goto B1;
  }
  B2:;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 1));
  goto Bfunc;
  B1:;
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = _ZN3std3sys4wasi17decode_error_kind17he23a249a9ada7316E(i0);
  i1 = 255u;
  i0 &= i1;
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std3sys4wasi2os12error_string17h2cf85a3df68353a7E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 1056u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = 0u;
  l3 = i0;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 0u;
  i2 = 1024u;
  i0 = memset_0(i0, i1, i2);
  i0 = p1;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i2 = 1024u;
  i0 = strerror_r(i0, i1, i2);
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 1u;
  i0 += i1;
  l4 = i0;
  i0 = 0u;
  p1 = i0;
  L4: 
    i0 = l4;
    i1 = p1;
    i0 += i1;
    l5 = i0;
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    p1 = i0;
    i0 = l5;
    i0 = i32_load8_u((&memory), (u64)(i0));
    if (i0) {goto L4;}
  i0 = l3;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  B3:;
  i0 = l2;
  i1 = 1032u;
  i0 += i1;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i2 = l3;
  _ZN4core3str9from_utf817he6f02ee8cec749d4E(i0, i1, i2);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 1032));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 1036));
  i2 = l2;
  i3 = 1040u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  _ZN5alloc5slice29__LT_impl_u20__u5b_T_u5d__GT_6to_vec17h2392cf0518e8ca41E(i0, i1, i2);
  i0 = l2;
  i1 = 1056u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B2:;
  i0 = 1055156u;
  i1 = 18u;
  i2 = 1055200u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = l3;
  i1 = 0u;
  i2 = 1052108u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l2;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 1036));
  i64_store((&memory), (u64)(i0 + 1048), j1);
  i0 = 1051420u;
  i1 = 43u;
  i2 = l2;
  i3 = 1048u;
  i2 += i3;
  i3 = 1051480u;
  i4 = 1055216u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_5write17h1f75c072454a7cb2E(u32 p0, u32 p1, u32 p2, u32 p3) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p2;
  i3 = p3;
  i4 = p1;
  i4 = i32_load((&memory), (u64)(i4 + 4));
  i4 = i32_load((&memory), (u64)(i4 + 12));
  CALL_INDIRECT(T0, void (*)(u32, u32, u32, u32), 5, i4, i0, i1, i2, i3);
  FUNC_EPILOGUE;
}

static void _ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_14write_vectored17hdc4c24efc025d6a0E(u32 p0, u32 p1, u32 p2, u32 p3) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p2;
  i3 = p3;
  i4 = p1;
  i4 = i32_load((&memory), (u64)(i4 + 4));
  i4 = i32_load((&memory), (u64)(i4 + 16));
  CALL_INDIRECT(T0, void (*)(u32, u32, u32, u32), 5, i4, i0, i1, i2, i3);
  FUNC_EPILOGUE;
}

static void _ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_5flush17h9425a9f607fd3865E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i2 = i32_load((&memory), (u64)(i2 + 20));
  CALL_INDIRECT(T0, void (*)(u32, u32), 1, i2, i0, i1);
  FUNC_EPILOGUE;
}

static void _ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_9write_all17hce2c6010f31eb804E(u32 p0, u32 p1, u32 p2, u32 p3) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p2;
  i3 = p3;
  i4 = p1;
  i4 = i32_load((&memory), (u64)(i4 + 4));
  i4 = i32_load((&memory), (u64)(i4 + 24));
  CALL_INDIRECT(T0, void (*)(u32, u32, u32, u32), 5, i4, i0, i1, i2, i3);
  FUNC_EPILOGUE;
}

static void _ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_9write_fmt17h1cfe94106c0e4d55E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p2;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = p2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = p0;
  i1 = l4;
  i2 = l3;
  i3 = 8u;
  i2 += i3;
  i3 = p1;
  i3 = i32_load((&memory), (u64)(i3 + 32));
  CALL_INDIRECT(T0, void (*)(u32, u32, u32), 6, i3, i0, i1, i2);
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN60__LT_std__io__stdio__StdoutRaw_u20_as_u20_std__io__Write_GT_5write17h6c80cfd177b83762E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1, j2;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = l4;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l4;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = 1u;
  p2 = i0;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = 1u;
  i2 = l4;
  i3 = 8u;
  i2 += i3;
  i3 = 1u;
  _ZN4wasi13lib_generated8fd_write17hacbf9079620e9958E(i0, i1, i2, i3);
  i0 = l4;
  i0 = i32_load16_u((&memory), (u64)(i0 + 16));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = l4;
  i1 = l4;
  i1 = i32_load16_u((&memory), (u64)(i1 + 18));
  i32_store16((&memory), (u64)(i0 + 30), i1);
  i0 = p0;
  i1 = l4;
  i2 = 30u;
  i1 += i2;
  i1 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i1);
  j1 = (u64)(i1);
  j2 = 65535ull;
  j1 &= j2;
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B0;
  B1:;
  i0 = p0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  p2 = i0;
  B0:;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN60__LT_std__io__stdio__StderrRaw_u20_as_u20_std__io__Write_GT_5write17hf7531ab2fbcf77b3E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1, j2;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = l4;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l4;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = 1u;
  p2 = i0;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = 2u;
  i2 = l4;
  i3 = 8u;
  i2 += i3;
  i3 = 1u;
  _ZN4wasi13lib_generated8fd_write17hacbf9079620e9958E(i0, i1, i2, i3);
  i0 = l4;
  i0 = i32_load16_u((&memory), (u64)(i0 + 16));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = l4;
  i1 = l4;
  i1 = i32_load16_u((&memory), (u64)(i1 + 18));
  i32_store16((&memory), (u64)(i0 + 30), i1);
  i0 = p0;
  i1 = l4;
  i2 = 30u;
  i1 += i2;
  i1 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i1);
  j1 = (u64)(i1);
  j2 = 65535ull;
  j1 &= j2;
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B0;
  B1:;
  i0 = p0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  p2 = i0;
  B0:;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN3std2io5stdio5stdin17h6275b62513a72eaaE(void) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l0 = i0;
  g0 = i0;
  i0 = 0u;
  i0 = i32_load8_u((&memory), (u64)(i0 + 1061644));
  if (i0) {goto B7;}
  i0 = 0u;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 1061644), i1);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061640));
  l1 = i0;
  i1 = 1u;
  i0 = i0 > i1;
  if (i0) {goto B9;}
  i0 = l1;
  switch (i0) {
    case 0: goto B10;
    case 1: goto B11;
    default: goto B10;
  }
  B11:;
  i0 = 0u;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1061644), i1);
  goto B0;
  B10:;
  i0 = 4u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B6;}
  i0 = l1;
  i1 = 1061640u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 1053892u;
  i0 = _ZN3std10sys_common11at_exit_imp4push17h17f1d1a73fe1793aE(i0, i1);
  l2 = i0;
  i0 = 8192u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = l1;
  i1 = 0u;
  i2 = 8192u;
  i0 = memset_0(i0, i1, i2);
  l3 = i0;
  i0 = 1u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l4;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = 2u;
  i0 += i1;
  i1 = 2u;
  i0 += i1;
  l5 = i0;
  i1 = l0;
  i2 = 10u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = 6u;
  i0 += i1;
  i1 = 2u;
  i0 += i1;
  l6 = i0;
  i1 = l0;
  i2 = 13u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = l0;
  i1 = i32_load16_u((&memory), (u64)(i1 + 10));
  i32_store16((&memory), (u64)(i0 + 2), i1);
  i0 = l0;
  i1 = l0;
  i1 = i32_load16_u((&memory), (u64)(i1 + 13));
  i32_store16((&memory), (u64)(i0 + 6), i1);
  i0 = 36u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l1;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l1;
  j1 = 4294967297ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = l0;
  i1 = i32_load16_u((&memory), (u64)(i1 + 6));
  i32_store16((&memory), (u64)(i0 + 13), i1);
  i0 = l1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l1;
  i1 = 8192u;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = l1;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l1;
  i1 = l0;
  i1 = i32_load16_u((&memory), (u64)(i1 + 2));
  i32_store16((&memory), (u64)(i0 + 33), i1);
  i0 = l1;
  i1 = 32u;
  i0 += i1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 15u;
  i0 += i1;
  i1 = l6;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 35u;
  i0 += i1;
  i1 = l5;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = l1;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1));
  l4 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  i0 = 4u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = 0u;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 1061640), i1);
  i0 = l4;
  i1 = l1;
  i32_store((&memory), (u64)(i0), i1);
  goto B8;
  B9:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1));
  l4 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  B8:;
  i0 = 0u;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1061644), i1);
  i0 = l1;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = l1;
  goto Bfunc;
  B7:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B6:;
  i0 = 4u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B5:;
  i0 = 8192u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B4:;
  i0 = 1u;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B3:;
  i0 = 36u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B2:;
  UNREACHABLE;
  B1:;
  i0 = 4u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 1052752u;
  i1 = 35u;
  i2 = 1052812u;
  _ZN4core6option13expect_failed17hdd81bfbb4998aefaE(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN3std10sys_common11at_exit_imp4push17h17f1d1a73fe1793aE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = 0u;
  i0 = i32_load8_u((&memory), (u64)(i0 + 1061737));
  if (i0) {goto B3;}
  i0 = 0u;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 1061737), i1);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061656));
  l2 = i0;
  i1 = 1u;
  i0 = i0 > i1;
  if (i0) {goto B5;}
  i0 = l2;
  switch (i0) {
    case 0: goto B6;
    case 1: goto B4;
    default: goto B6;
  }
  B6:;
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  j1 = 4ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = 0u;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 1061656), i1);
  B5:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l3 = i0;
  i1 = l2;
  i2 = 4u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i0 = i0 == i1;
  if (i0) {goto B7;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  goto B0;
  B7:;
  i0 = l3;
  i1 = 1u;
  i0 += i1;
  l4 = i0;
  i1 = l3;
  i0 = i0 < i1;
  if (i0) {goto B10;}
  i0 = l3;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l4;
  i2 = l5;
  i3 = l4;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l4 = i0;
  i1 = 536870911u;
  i0 &= i1;
  i1 = l4;
  i0 = i0 != i1;
  if (i0) {goto B10;}
  i0 = l4;
  i1 = 3u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B10;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  if (i0) {goto B11;}
  B12:;
  i0 = l5;
  if (i0) {goto B9;}
  i0 = 4u;
  l4 = i0;
  goto B1;
  B11:;
  i0 = l3;
  i1 = 3u;
  i0 <<= (i1 & 31);
  l6 = i0;
  i1 = l5;
  i0 = i0 == i1;
  if (i0) {goto B13;}
  i0 = l6;
  if (i0) {goto B14;}
  i0 = l5;
  if (i0) {goto B15;}
  i0 = 4u;
  l4 = i0;
  goto B1;
  B15:;
  i0 = l5;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  goto B13;
  B14:;
  i0 = l4;
  i1 = l6;
  i2 = 4u;
  i3 = l5;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l4 = i0;
  B13:;
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l3 = i0;
  goto B1;
  B10:;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  B9:;
  i0 = l5;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  if (i0) {goto B1;}
  B8:;
  i0 = l5;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B4:;
  i0 = 0u;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1061737), i1);
  i0 = p0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B16;}
  i0 = p0;
  i1 = l2;
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B16:;
  i0 = 0u;
  goto Bfunc;
  B3:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B2:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  i1 = l5;
  i2 = 3u;
  i1 >>= (i2 & 31);
  i32_store((&memory), (u64)(i0), i1);
  B0:;
  i0 = l4;
  i1 = l3;
  i2 = 3u;
  i1 <<= (i2 & 31);
  i0 += i1;
  l3 = i0;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1061737), i1);
  i0 = 1u;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std2io5stdio5Stdin9read_line17h8f9a7008c4938aaaE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, 
      l11 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1, j2;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l4 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  if (i0) {goto B5;}
  i0 = l4;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = 0u;
  l5 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061728));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B7;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061732));
  l5 = i0;
  goto B6;
  B7:;
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061728), j1);
  B6:;
  i0 = 0u;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 1061732), i1);
  i0 = p2;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i0 = 0u;
  l7 = i0;
  L9: 
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    l4 = i0;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1 + 28));
    l8 = i1;
    i0 = i0 < i1;
    if (i0) {goto B13;}
    i0 = 0u;
    l4 = i0;
    i0 = p1;
    i0 = i32_load8_u((&memory), (u64)(i0 + 32));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B15;}
    i0 = l3;
    i1 = p1;
    j1 = i64_load((&memory), (u64)(i1 + 16));
    i64_store((&memory), (u64)(i0 + 32), j1);
    i0 = l3;
    i1 = 16u;
    i0 += i1;
    i1 = 0u;
    i2 = l3;
    i3 = 32u;
    i2 += i3;
    i3 = 1u;
    _ZN4wasi13lib_generated7fd_read17h0d476bb7732cd2ceE(i0, i1, i2, i3);
    i0 = l3;
    i0 = i32_load16_u((&memory), (u64)(i0 + 16));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B16;}
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 20));
    l8 = i0;
    goto B14;
    B16:;
    i0 = l3;
    i1 = l3;
    i1 = i32_load16_u((&memory), (u64)(i1 + 18));
    i32_store16((&memory), (u64)(i0 + 46), i1);
    i0 = l3;
    i1 = 46u;
    i0 += i1;
    i0 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i0);
    i1 = 65535u;
    i0 &= i1;
    l8 = i0;
    i1 = 8u;
    i0 = i0 != i1;
    if (i0) {goto B12;}
    B15:;
    i0 = 0u;
    l8 = i0;
    B14:;
    i0 = p1;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 24), i1);
    i0 = p1;
    i1 = l8;
    i32_store((&memory), (u64)(i0 + 28), i1);
    B13:;
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0 + 20));
    l9 = i0;
    i1 = l8;
    i0 = i0 < i1;
    if (i0) {goto B4;}
    i0 = l3;
    i1 = 8u;
    i0 += i1;
    i1 = 10u;
    i2 = p1;
    i2 = i32_load((&memory), (u64)(i2 + 16));
    l10 = i2;
    i3 = l4;
    i2 += i3;
    l9 = i2;
    i3 = l8;
    i4 = l4;
    i3 -= i4;
    l4 = i3;
    _ZN4core5slice6memchr6memchr17h4b6f86a8dda0136aE(i0, i1, i2, i3);
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    if (i0) {goto B11;}
    i0 = l10;
    i1 = l8;
    i0 += i1;
    l8 = i0;
    i0 = 0u;
    l10 = i0;
    goto B10;
    B12:;
    i0 = l8;
    i0 = _ZN3std3sys4wasi17decode_error_kind17he23a249a9ada7316E(i0);
    i1 = 255u;
    i0 &= i1;
    i1 = 15u;
    i0 = i0 == i1;
    if (i0) {goto L9;}
    i0 = 1u;
    l9 = i0;
    i0 = 0u;
    l7 = i0;
    goto B8;
    B11:;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 12));
    l8 = i0;
    i1 = 4294967295u;
    i0 = i0 == i1;
    if (i0) {goto B18;}
    i0 = l8;
    i1 = 1u;
    i0 += i1;
    l11 = i0;
    i0 = l8;
    i1 = l4;
    i0 = i0 < i1;
    if (i0) {goto B17;}
    i0 = l11;
    i1 = l4;
    i2 = 1053112u;
    _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
    UNREACHABLE;
    B18:;
    i0 = 1053112u;
    _ZN4core5slice25slice_index_overflow_fail17h96c96832494e835eE(i0);
    UNREACHABLE;
    B17:;
    i0 = l9;
    i1 = l11;
    i0 += i1;
    l8 = i0;
    i0 = 1u;
    l10 = i0;
    i0 = l11;
    l4 = i0;
    B10:;
    i0 = p2;
    i1 = l9;
    i2 = l8;
    _ZN109__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_alloc__vec__SpecExtend_LT__RF_T_C_core__slice__Iter_LT_T_GT__GT__GT_11spec_extend17hce2eec127ad34cc7E(i0, i1, i2);
    i0 = p1;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1 + 28));
    l8 = i1;
    i2 = p1;
    i2 = i32_load((&memory), (u64)(i2 + 24));
    i3 = l4;
    i2 += i3;
    l9 = i2;
    i3 = l9;
    i4 = l8;
    i3 = i3 > i4;
    i1 = i3 ? i1 : i2;
    i32_store((&memory), (u64)(i0 + 24), i1);
    i0 = l4;
    i1 = l7;
    i0 += i1;
    l7 = i0;
    i0 = 0u;
    l9 = i0;
    i0 = l10;
    i0 = !(i0);
    if (i0) {goto B19;}
    goto B8;
    B19:;
    i0 = l4;
    if (i0) {goto L9;}
  B8:;
  i0 = p2;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i1 = l6;
  i0 = i0 < i1;
  if (i0) {goto B3;}
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  i1 = p2;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = l6;
  i1 += i2;
  i2 = l4;
  i3 = l6;
  i2 -= i3;
  _ZN4core3str9from_utf817he6f02ee8cec749d4E(i0, i1, i2);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  if (i0) {goto B21;}
  i0 = p0;
  i1 = l7;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l9;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l8;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  goto B20;
  B21:;
  i0 = l9;
  i0 = !(i0);
  if (i0) {goto B22;}
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l8;
  j1 = (u64)(i1);
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i2 = l7;
  j2 = (u64)(i2);
  j1 |= j2;
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B20;
  B22:;
  i0 = 34u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  i1 = 0u;
  i1 = i32_load16_u((&memory), (u64)(i1 + 1053012));
  i32_store16((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 24u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1053004));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1052996));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l4;
  i1 = 8u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1052988));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l4;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1052980));
  i64_store((&memory), (u64)(i0), j1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l8 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l8;
  j1 = 146028888098ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l8;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l4;
  i1 = 12u;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  i1 = 1052004u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = l8;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l3;
  i1 = i32_load16_u((&memory), (u64)(i1 + 16));
  i32_store16((&memory), (u64)(i0 + 9), i1);
  i0 = l4;
  i1 = 11u;
  i0 += i1;
  i1 = l3;
  i2 = 18u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  j1 = 8589934593ull;
  i64_store((&memory), (u64)(i0), j1);
  B20:;
  i0 = p2;
  i1 = 8u;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  if (i0) {goto B23;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061728));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B24;}
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061728), j1);
  goto B23;
  B24:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061732));
  i0 = !(i0);
  if (i0) {goto B23;}
  i0 = p1;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  B23:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B5:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B4:;
  i0 = l8;
  i1 = l9;
  i2 = 1052152u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B3:;
  i0 = l6;
  i1 = l4;
  i2 = 1052964u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B2:;
  i0 = 34u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN55__LT_std__io__stdio__Stdin_u20_as_u20_std__io__Read_GT_4read17h43ce0ea6cf440e2eE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p1 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  if (i0) {goto B0;}
  i0 = l5;
  i1 = 8u;
  i0 += i1;
  l6 = i0;
  i0 = p1;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = 0u;
  p1 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061728));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B2;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061732));
  p1 = i0;
  goto B1;
  B2:;
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061728), j1);
  B1:;
  i0 = 0u;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 1061732), i1);
  i0 = l4;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  i1 = p1;
  i2 = 0u;
  i1 = i1 != i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i1 = l4;
  i2 = 8u;
  i1 += i2;
  i2 = p2;
  i3 = p3;
  _ZN59__LT_std__io__stdio__StdinLock_u20_as_u20_std__io__Read_GT_4read17hbf4316ecbb809641E(i0, i1, i2, i3);
  i0 = p1;
  if (i0) {goto B3;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061728));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B4;}
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061728), j1);
  goto B3;
  B4:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061732));
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l5;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  B3:;
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B0:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN59__LT_std__io__stdio__StdinLock_u20_as_u20_std__io__Read_GT_4read17hbf4316ecbb809641E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0, l7 = 0;
  u64 l8 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1, j2;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  i1 = p1;
  i2 = 20u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l6 = i1;
  i0 = i0 != i1;
  if (i0) {goto B6;}
  i0 = p1;
  i1 = 12u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p3;
  i0 = i0 <= i1;
  if (i0) {goto B5;}
  B6:;
  i0 = l5;
  i1 = l6;
  i0 = i0 < i1;
  if (i0) {goto B7;}
  i0 = 0u;
  l5 = i0;
  i0 = 0u;
  l6 = i0;
  i0 = p1;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B8;}
  i0 = l4;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = 0u;
  l6 = i0;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = 0u;
  i2 = l4;
  i3 = 8u;
  i2 += i3;
  i3 = 1u;
  _ZN4wasi13lib_generated7fd_read17h0d476bb7732cd2ceE(i0, i1, i2, i3);
  i0 = l4;
  i0 = i32_load16_u((&memory), (u64)(i0 + 16));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B9;}
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  l6 = i0;
  goto B8;
  B9:;
  i0 = l4;
  i1 = l4;
  i1 = i32_load16_u((&memory), (u64)(i1 + 18));
  i32_store16((&memory), (u64)(i0 + 30), i1);
  i0 = l4;
  i1 = 30u;
  i0 += i1;
  i0 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i0);
  l7 = i0;
  i1 = 65535u;
  i0 &= i1;
  i1 = 8u;
  i0 = i0 != i1;
  if (i0) {goto B3;}
  B8:;
  i0 = p1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = p1;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 20), i1);
  B7:;
  i0 = p1;
  i1 = 12u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l7 = i0;
  i1 = l6;
  i0 = i0 >= i1;
  if (i0) {goto B4;}
  i0 = l6;
  i1 = l7;
  i2 = 1052152u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B5:;
  i0 = p1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = p1;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B10;}
  i0 = p0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  goto B0;
  B10:;
  i0 = l4;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l4;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = 0u;
  p1 = i0;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = 0u;
  i2 = l4;
  i3 = 8u;
  i2 += i3;
  i3 = 1u;
  _ZN4wasi13lib_generated7fd_read17h0d476bb7732cd2ceE(i0, i1, i2, i3);
  i0 = l4;
  i0 = i32_load16_u((&memory), (u64)(i0 + 16));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B11;}
  i0 = l4;
  j0 = i64_load32_u((&memory), (u64)(i0 + 20));
  l8 = j0;
  goto B1;
  B11:;
  i0 = l4;
  i1 = l4;
  i1 = i32_load16_u((&memory), (u64)(i1 + 18));
  i32_store16((&memory), (u64)(i0 + 30), i1);
  i0 = l4;
  i1 = 30u;
  i0 += i1;
  i0 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i0);
  p1 = i0;
  i1 = 65535u;
  i0 &= i1;
  i1 = 8u;
  i0 = i0 == i1;
  if (i0) {goto B12;}
  i0 = p1;
  j0 = (u64)(i0);
  j1 = 65535ull;
  j0 &= j1;
  j1 = 32ull;
  j0 <<= (j1 & 63);
  l8 = j0;
  i0 = 1u;
  p1 = i0;
  goto B1;
  B12:;
  i0 = p0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  goto B0;
  B4:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = l5;
  i0 += i1;
  l7 = i0;
  i0 = l6;
  i1 = l5;
  i0 -= i1;
  l6 = i0;
  i1 = p3;
  i2 = l6;
  i3 = p3;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l6 = i0;
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B13;}
  i0 = p2;
  i1 = l7;
  i2 = l6;
  i0 = memcpy_0(i0, i1, i2);
  goto B2;
  B13:;
  i0 = p3;
  i0 = !(i0);
  if (i0) {goto B14;}
  i0 = p2;
  i1 = l7;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  goto B2;
  B14:;
  i0 = 0u;
  i1 = 0u;
  i2 = 1052708u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  B3:;
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l7;
  j1 = (u64)(i1);
  j2 = 65535ull;
  j1 &= j2;
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B0;
  B2:;
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  l5 = i1;
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i3 = l6;
  i2 += i3;
  l6 = i2;
  i3 = l6;
  i4 = l5;
  i3 = i3 > i4;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  goto B0;
  B1:;
  i0 = p0;
  j1 = l8;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  B0:;
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN3std2io5stdio6stdout17h060687408f12e049E(void) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l0 = i0;
  g0 = i0;
  i0 = 0u;
  i0 = i32_load8_u((&memory), (u64)(i0 + 1061652));
  if (i0) {goto B6;}
  i0 = 0u;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 1061652), i1);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061648));
  l1 = i0;
  i1 = 1u;
  i0 = i0 > i1;
  if (i0) {goto B8;}
  i0 = l1;
  switch (i0) {
    case 0: goto B9;
    case 1: goto B10;
    default: goto B9;
  }
  B10:;
  i0 = 0u;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1061652), i1);
  goto B0;
  B9:;
  i0 = 4u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = l1;
  i1 = 1061648u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 1053908u;
  i0 = _ZN3std10sys_common11at_exit_imp4push17h17f1d1a73fe1793aE(i0, i1);
  l2 = i0;
  i0 = 1024u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l0;
  i1 = 10u;
  i0 += i1;
  i1 = 2u;
  i0 += i1;
  l4 = i0;
  i1 = l0;
  i2 = 13u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = l0;
  i1 = i32_load16_u((&memory), (u64)(i1 + 13));
  i32_store16((&memory), (u64)(i0 + 10), i1);
  i0 = 32u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 28), i1);
  i0 = l1;
  i1 = 0u;
  i32_store16((&memory), (u64)(i0 + 24), i1);
  i0 = l1;
  j1 = 1024ull;
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = l1;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l1;
  j1 = 4294967297ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = l0;
  i1 = i32_load16_u((&memory), (u64)(i1 + 10));
  i32_store16((&memory), (u64)(i0 + 29), i1);
  i0 = l1;
  i1 = 31u;
  i0 += i1;
  i1 = l4;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = l1;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  i0 = 4u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = 0u;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 1061648), i1);
  i0 = l2;
  i1 = l1;
  i32_store((&memory), (u64)(i0), i1);
  goto B7;
  B8:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  B7:;
  i0 = 0u;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1061652), i1);
  i0 = l1;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = l1;
  goto Bfunc;
  B6:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B5:;
  i0 = 4u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B4:;
  i0 = 1024u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B3:;
  i0 = 32u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B2:;
  UNREACHABLE;
  B1:;
  i0 = 4u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 1052828u;
  i1 = 36u;
  i2 = 1052864u;
  _ZN4core6option13expect_failed17hdd81bfbb4998aefaE(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN61__LT_std__io__stdio__StdoutLock_u20_as_u20_std__io__Write_GT_5write17h50f86d8404c780efE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0;
  u64 l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1, j2;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  if (i0) {goto B4;}
  i0 = p1;
  i1 = 4294967295u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  l5 = i0;
  i0 = p1;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = l5;
  _ZN3std2io8buffered18BufWriter_LT_W_GT_9flush_buf17hd67ccca3c7d9e3cdE(i0, i1);
  i0 = l4;
  i0 = i32_load8_u((&memory), (u64)(i0 + 16));
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B8;}
  i0 = p1;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B7;}
  i0 = 1051328u;
  i1 = 43u;
  i2 = 1052236u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B8:;
  i0 = l4;
  j0 = i64_load((&memory), (u64)(i0 + 16));
  l6 = j0;
  j1 = 255ull;
  j0 &= j1;
  j1 = 3ull;
  i0 = j0 != j1;
  if (i0) {goto B6;}
  B7:;
  i0 = p1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 20), i1);
  goto B5;
  B6:;
  j0 = l6;
  i0 = (u32)(j0);
  l7 = i0;
  i1 = 255u;
  i0 &= i1;
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B3;}
  i0 = 0u;
  if (i0) {goto B9;}
  i0 = l7;
  i1 = 3u;
  i0 &= i1;
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B5;}
  B9:;
  j0 = l6;
  j1 = 32ull;
  j0 >>= (j1 & 63);
  i0 = (u32)(j0);
  l7 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l7;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l8 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l9 = i0;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l9;
  i2 = l8;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B10:;
  i0 = l7;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B5:;
  i0 = l4;
  i1 = 8u;
  i0 += i1;
  i1 = 10u;
  i2 = p2;
  i3 = p3;
  _ZN4core5slice6memchr7memrchr17heee7616632cba075E(i0, i1, i2, i3);
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  if (i0) {goto B11;}
  i0 = p0;
  i1 = l5;
  i2 = p2;
  i3 = p3;
  _ZN72__LT_std__io__buffered__BufWriter_LT_W_GT__u20_as_u20_std__io__Write_GT_5write17h98b8ed5b902ebbc8E(i0, i1, i2, i3);
  goto B0;
  B11:;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l8 = i0;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B13;}
  i0 = l8;
  i1 = 1u;
  i0 += i1;
  l7 = i0;
  i0 = l8;
  i1 = p3;
  i0 = i0 < i1;
  if (i0) {goto B12;}
  i0 = l7;
  i1 = p3;
  i2 = 1052252u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B13:;
  i0 = 1052252u;
  _ZN4core5slice25slice_index_overflow_fail17h96c96832494e835eE(i0);
  UNREACHABLE;
  B12:;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = l5;
  i2 = p2;
  i3 = l7;
  _ZN72__LT_std__io__buffered__BufWriter_LT_W_GT__u20_as_u20_std__io__Write_GT_5write17h98b8ed5b902ebbc8E(i0, i1, i2, i3);
  i0 = l4;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l9 = i0;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  l8 = i0;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l10 = i0;
  i1 = 1u;
  i0 = i0 > i1;
  if (i0) {goto B15;}
  i0 = l10;
  switch (i0) {
    case 0: goto B14;
    case 1: goto B2;
    default: goto B14;
  }
  B15:;
  i0 = l8;
  i1 = 255u;
  i0 &= i1;
  i1 = 2u;
  i0 = i0 < i1;
  if (i0) {goto B14;}
  i0 = l9;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l9;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l9;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l10 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l11 = i0;
  i0 = !(i0);
  if (i0) {goto B16;}
  i0 = l9;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l11;
  i2 = l10;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B16:;
  i0 = l9;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B14:;
  i0 = p1;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 20), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = l5;
  _ZN3std2io8buffered18BufWriter_LT_W_GT_9flush_buf17hd67ccca3c7d9e3cdE(i0, i1);
  i0 = l4;
  i0 = i32_load8_u((&memory), (u64)(i0 + 16));
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B20;}
  i0 = p1;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B19;}
  i0 = 1051328u;
  i1 = 43u;
  i2 = 1052236u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B20:;
  i0 = l4;
  j0 = i64_load8_u((&memory), (u64)(i0 + 16));
  j1 = 3ull;
  i0 = j0 != j1;
  if (i0) {goto B18;}
  B19:;
  i0 = p1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 20), i1);
  i0 = l8;
  i1 = l7;
  i0 = i0 == i1;
  if (i0) {goto B17;}
  goto B1;
  B18:;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  l9 = i0;
  i0 = l8;
  i1 = l7;
  i0 = i0 != i1;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 16));
  l11 = i1;
  i2 = 255u;
  i1 &= i2;
  i2 = 3u;
  i1 = i1 != i2;
  i0 |= i1;
  l10 = i0;
  i0 = 0u;
  if (i0) {goto B22;}
  i0 = l11;
  i1 = 3u;
  i0 &= i1;
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B21;}
  B22:;
  i0 = l9;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l9;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l9;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l11 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l12 = i0;
  i0 = !(i0);
  if (i0) {goto B23;}
  i0 = l9;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l12;
  i2 = l11;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B23:;
  i0 = l9;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B21:;
  i0 = l10;
  if (i0) {goto B1;}
  B17:;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = l5;
  i2 = p2;
  i3 = l7;
  i2 += i3;
  i3 = p3;
  i4 = l7;
  i3 -= i4;
  _ZN72__LT_std__io__buffered__BufWriter_LT_W_GT__u20_as_u20_std__io__Write_GT_5write17h98b8ed5b902ebbc8E(i0, i1, i2, i3);
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B24;}
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  i2 = l8;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B0;
  B24:;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l8;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i0 = i32_load8_u((&memory), (u64)(i0 + 20));
  i1 = 2u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = l4;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p2 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p3 = i0;
  i0 = !(i0);
  if (i0) {goto B25;}
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p3;
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B25:;
  i0 = l5;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  goto B0;
  B4:;
  i0 = 1051060u;
  i1 = 16u;
  i2 = l4;
  i3 = 16u;
  i2 += i3;
  i3 = 1051372u;
  i4 = 1051144u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B3:;
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  j1 = l6;
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B0;
  B2:;
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l9;
  j1 = (u64)(i1);
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i2 = l8;
  j2 = (u64)(i2);
  j1 |= j2;
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B0;
  B1:;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l8;
  i32_store((&memory), (u64)(i0 + 4), i1);
  B0:;
  i0 = p1;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN57__LT_std__io__stdio__Stdout_u20_as_u20_std__io__Write_GT_5flush17ha8096688cb5c04b4E(u32 p0, u32 p1) {
  u32 l2 = 0;
  u64 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 4294967295u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 += i2;
  _ZN3std2io8buffered18BufWriter_LT_W_GT_9flush_buf17hd67ccca3c7d9e3cdE(i0, i1);
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  i0 = p1;
  i0 = i32_load8_u((&memory), (u64)(i0 + 24));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B3;}
  i0 = 1051328u;
  i1 = 43u;
  i2 = 1052236u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B4:;
  i0 = l2;
  j0 = i64_load((&memory), (u64)(i0));
  l3 = j0;
  j1 = 255ull;
  j0 &= j1;
  j1 = 3ull;
  i0 = j0 != j1;
  if (i0) {goto B2;}
  B3:;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 28), i1);
  goto B1;
  B2:;
  i0 = p0;
  j1 = l3;
  i64_store((&memory), (u64)(i0), j1);
  B1:;
  i0 = p1;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B0:;
  i0 = 1051060u;
  i1 = 16u;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i3 = 1051372u;
  i4 = 1051144u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN57__LT_std__io__stdio__Stdout_u20_as_u20_std__io__Write_GT_9write_fmt17hfcc1c9dfb39740edE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l3;
  i1 = l3;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = 24u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p2;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 24u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = p2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = 1053088u;
  i2 = l3;
  i3 = 24u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0 + 12));
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B5;}
  i0 = 15u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p2;
  i1 = 7u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1053079));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p2;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1053072));
  i64_store((&memory), (u64)(i0), j1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  j1 = 64424509455ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = p1;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p2;
  i1 = 16u;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = p2;
  i1 = 1052004u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p2;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = l3;
  i1 = i32_load16_u((&memory), (u64)(i1 + 24));
  i32_store16((&memory), (u64)(i0 + 9), i1);
  i0 = p2;
  i1 = 11u;
  i0 += i1;
  i1 = l3;
  i2 = 24u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  goto B3;
  B5:;
  i0 = p0;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 12));
  i64_store((&memory), (u64)(i0), j1);
  goto B3;
  B4:;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = 0u;
  if (i0) {goto B6;}
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0 + 12));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B3;}
  B6:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p2 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p2;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B7:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = l3;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B2:;
  i0 = 15u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN3std4sync4once4Once10call_inner17h74e47fc5d3e1aa49E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = l4;
  i1 = 2u;
  i0 |= i1;
  l5 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i0 = p1;
  if (i0) {goto B3;}
  L4: 
    i0 = l6;
    i1 = 3u;
    i0 = i0 > i1;
    if (i0) {goto B5;}
    i0 = l6;
    switch (i0) {
      case 0: goto B6;
      case 1: goto B7;
      case 2: goto B5;
      case 3: goto B1;
      default: goto B6;
    }
    B7:;
    i0 = 1053360u;
    i1 = 42u;
    i2 = 1053404u;
    _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
    UNREACHABLE;
    B6:;
    i0 = p0;
    i1 = p0;
    i1 = i32_load((&memory), (u64)(i1));
    l6 = i1;
    i2 = 2u;
    i3 = l6;
    i1 = i3 ? i1 : i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l6;
    if (i0) {goto L4;}
    i0 = 0u;
    p1 = i0;
    goto B2;
    B5:;
    i0 = l6;
    i1 = 3u;
    i0 &= i1;
    i1 = 2u;
    i0 = i0 != i1;
    if (i0) {goto B0;}
    L10: 
      i0 = l6;
      p1 = i0;
      i0 = 0u;
      i0 = i32_load((&memory), (u64)(i0 + 1061716));
      i1 = 1u;
      i0 = i0 == i1;
      if (i0) {goto B11;}
      i0 = 0u;
      j1 = 1ull;
      i64_store((&memory), (u64)(i0 + 1061716), j1);
      i0 = 0u;
      i1 = 0u;
      i32_store((&memory), (u64)(i0 + 1061724), i1);
      B11:;
      i0 = 1061720u;
      i0 = _ZN3std10sys_common11thread_info10ThreadInfo4with28__u7b__u7b_closure_u7d__u7d_17h4f4afda818addf88E(i0);
      l7 = i0;
      i0 = p0;
      i1 = l5;
      i2 = p0;
      i2 = i32_load((&memory), (u64)(i2));
      l6 = i2;
      i3 = l6;
      i4 = p1;
      i3 = i3 == i4;
      i1 = i3 ? i1 : i2;
      i32_store((&memory), (u64)(i0), i1);
      i0 = l4;
      i1 = 0u;
      i32_store8((&memory), (u64)(i0 + 8), i1);
      i0 = l4;
      i1 = l7;
      i32_store((&memory), (u64)(i0), i1);
      i0 = l4;
      i1 = p1;
      i2 = 4294967292u;
      i1 &= i2;
      i32_store((&memory), (u64)(i0 + 4), i1);
      i0 = l6;
      i1 = p1;
      i0 = i0 != i1;
      if (i0) {goto B13;}
      i0 = l4;
      i0 = i32_load8_u((&memory), (u64)(i0 + 8));
      i0 = !(i0);
      if (i0) {goto B12;}
      goto B9;
      B13:;
      i0 = l4;
      i0 = i32_load((&memory), (u64)(i0));
      p1 = i0;
      i0 = !(i0);
      if (i0) {goto B14;}
      i0 = p1;
      i1 = p1;
      i1 = i32_load((&memory), (u64)(i1));
      l7 = i1;
      i2 = 4294967295u;
      i1 += i2;
      i32_store((&memory), (u64)(i0), i1);
      i0 = l7;
      i1 = 1u;
      i0 = i0 != i1;
      if (i0) {goto B14;}
      i0 = l4;
      _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h54081c59c02bd7eaE(i0);
      B14:;
      i0 = l6;
      i1 = 3u;
      i0 &= i1;
      i1 = 2u;
      i0 = i0 == i1;
      if (i0) {goto L10;}
      goto B8;
      B12:;
    L15: 
      _ZN3std6thread4park17haa34f1fc5521730bE();
      i0 = l4;
      i0 = i32_load8_u((&memory), (u64)(i0 + 8));
      i0 = !(i0);
      if (i0) {goto L15;}
    B9:;
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = !(i0);
    if (i0) {goto B8;}
    i0 = p1;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1));
    l6 = i1;
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l6;
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B8;}
    i0 = l4;
    _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h54081c59c02bd7eaE(i0);
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    goto L4;
    B8:;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    goto L4;
  B3:;
  L16: 
    i0 = l6;
    p1 = i0;
    i1 = 3u;
    i0 = i0 > i1;
    if (i0) {goto B17;}
    i0 = p1;
    switch (i0) {
      case 0: goto B18;
      case 1: goto B18;
      case 2: goto B17;
      case 3: goto B1;
      default: goto B18;
    }
    B18:;
    i0 = p0;
    i1 = 2u;
    i2 = p0;
    i2 = i32_load((&memory), (u64)(i2));
    l6 = i2;
    i3 = l6;
    i4 = p1;
    i3 = i3 == i4;
    l7 = i3;
    i1 = i3 ? i1 : i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l7;
    i0 = !(i0);
    if (i0) {goto L16;}
    goto B2;
    B17:;
    i0 = p1;
    i1 = 3u;
    i0 &= i1;
    i1 = 2u;
    i0 = i0 != i1;
    if (i0) {goto B0;}
    L20: 
      i0 = p1;
      l6 = i0;
      i0 = 0u;
      i0 = i32_load((&memory), (u64)(i0 + 1061716));
      i1 = 1u;
      i0 = i0 == i1;
      if (i0) {goto B21;}
      i0 = 0u;
      j1 = 1ull;
      i64_store((&memory), (u64)(i0 + 1061716), j1);
      i0 = 0u;
      i1 = 0u;
      i32_store((&memory), (u64)(i0 + 1061724), i1);
      B21:;
      i0 = 1061720u;
      i0 = _ZN3std10sys_common11thread_info10ThreadInfo4with28__u7b__u7b_closure_u7d__u7d_17h4f4afda818addf88E(i0);
      l7 = i0;
      i0 = p0;
      i1 = l5;
      i2 = p0;
      i2 = i32_load((&memory), (u64)(i2));
      p1 = i2;
      i3 = p1;
      i4 = l6;
      i3 = i3 == i4;
      l8 = i3;
      i1 = i3 ? i1 : i2;
      i32_store((&memory), (u64)(i0), i1);
      i0 = l4;
      i1 = 0u;
      i32_store8((&memory), (u64)(i0 + 8), i1);
      i0 = l4;
      i1 = l7;
      i32_store((&memory), (u64)(i0), i1);
      i0 = l4;
      i1 = l6;
      i2 = 4294967292u;
      i1 &= i2;
      i32_store((&memory), (u64)(i0 + 4), i1);
      i0 = l8;
      if (i0) {goto B22;}
      i0 = l4;
      i0 = i32_load((&memory), (u64)(i0));
      l6 = i0;
      i0 = !(i0);
      if (i0) {goto B23;}
      i0 = l6;
      i1 = l6;
      i1 = i32_load((&memory), (u64)(i1));
      l7 = i1;
      i2 = 4294967295u;
      i1 += i2;
      i32_store((&memory), (u64)(i0), i1);
      i0 = l7;
      i1 = 1u;
      i0 = i0 != i1;
      if (i0) {goto B23;}
      i0 = l4;
      _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h54081c59c02bd7eaE(i0);
      B23:;
      i0 = p1;
      i1 = 3u;
      i0 &= i1;
      i1 = 2u;
      i0 = i0 == i1;
      if (i0) {goto L20;}
      goto B19;
      B22:;
    i0 = l4;
    i0 = i32_load8_u((&memory), (u64)(i0 + 8));
    if (i0) {goto B24;}
    L25: 
      _ZN3std6thread4park17haa34f1fc5521730bE();
      i0 = l4;
      i0 = i32_load8_u((&memory), (u64)(i0 + 8));
      i0 = !(i0);
      if (i0) {goto L25;}
    B24:;
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = !(i0);
    if (i0) {goto B19;}
    i0 = p1;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1));
    l6 = i1;
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l6;
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B19;}
    i0 = l4;
    _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h54081c59c02bd7eaE(i0);
    B19:;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    goto L16;
  B2:;
  i0 = l4;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = p1;
  i2 = 1u;
  i1 = i1 == i2;
  i2 = p3;
  i2 = i32_load((&memory), (u64)(i2 + 12));
  CALL_INDIRECT(T0, void (*)(u32, u32), 1, i2, i0, i1);
  i0 = l4;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  _ZN70__LT_std__sync__once__WaiterQueue_u20_as_u20_core__ops__drop__Drop_GT_4drop17h18e38d5577964ed0E(i0);
  B1:;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B0:;
  i0 = 1053284u;
  i1 = 57u;
  i2 = 1053344u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN3std2io5stdio9set_panic17h73ed222c0f64725fE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = 0u;
  l4 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061700));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B2;}
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061700), j1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061708), i1);
  goto B1;
  B2:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061704));
  if (i0) {goto B0;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061708));
  l4 = i0;
  B1:;
  i0 = 0u;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 1061708), i1);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061712));
  p1 = i0;
  i0 = 0u;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 1061712), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061704), i1);
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l3;
  i1 = l4;
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 20));
  CALL_INDIRECT(T0, void (*)(u32, u32), 1, i2, i0, i1);
  i0 = 0u;
  if (i0) {goto B4;}
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B3;}
  B4:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p2 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p2;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i2 = l5;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B5:;
  i0 = p2;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B0:;
  i0 = 1051060u;
  i1 = 16u;
  i2 = l3;
  i3 = 8u;
  i2 += i3;
  i3 = 1051372u;
  i4 = 1051144u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN3std2io5stdio6_print17hc41bda27e6084072E(u32 p0) {
  u32 l1 = 0, l2 = 0, l4 = 0, l5 = 0;
  u64 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 96u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = l1;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p0;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = p0;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l1;
  i1 = 6u;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l1;
  i1 = 1052936u;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061684));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B6;}
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061684), j1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061692), i1);
  goto B5;
  B6:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061688));
  if (i0) {goto B2;}
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061688), i1);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061692));
  p0 = i0;
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061692), i1);
  i0 = p0;
  if (i0) {goto B4;}
  B5:;
  i0 = l1;
  i1 = _ZN3std2io5stdio6stdout17h060687408f12e049E();
  p0 = i1;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l1;
  i1 = 72u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = l1;
  i2 = 8u;
  i1 += i2;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = 72u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l1;
  i2 = 8u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = l1;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0 + 72), j1);
  i0 = l1;
  i1 = 64u;
  i0 += i1;
  i1 = l1;
  i2 = 48u;
  i1 += i2;
  i2 = l1;
  i3 = 72u;
  i2 += i3;
  _ZN57__LT_std__io__stdio__Stdout_u20_as_u20_std__io__Write_GT_9write_fmt17hfcc1c9dfb39740edE(i0, i1, i2);
  i0 = p0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B7;}
  i0 = l1;
  i1 = 48u;
  i0 += i1;
  _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h76eb5b162db06de2E(i0);
  B7:;
  i0 = l1;
  j0 = i64_load((&memory), (u64)(i0 + 64));
  l3 = j0;
  goto B3;
  B4:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061696));
  l2 = i0;
  i0 = l1;
  i1 = 72u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = l1;
  i2 = 8u;
  i1 += i2;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = 72u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l1;
  i2 = 8u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = l1;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0 + 72), j1);
  i0 = l1;
  i1 = 48u;
  i0 += i1;
  i1 = p0;
  i2 = l1;
  i3 = 72u;
  i2 += i3;
  i3 = l2;
  i3 = i32_load((&memory), (u64)(i3 + 32));
  CALL_INDIRECT(T0, void (*)(u32, u32, u32), 6, i3, i0, i1, i2);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061688));
  if (i0) {goto B1;}
  i0 = 0u;
  i1 = 4294967295u;
  i32_store((&memory), (u64)(i0 + 1061688), i1);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061692));
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = l4;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061696));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061696));
  l4 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061692));
  i1 = l5;
  i2 = l4;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B8:;
  i0 = 0u;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 1061696), i1);
  i0 = 0u;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 1061692), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061688));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 1061688), i1);
  i0 = l1;
  i1 = l1;
  j1 = i64_load((&memory), (u64)(i1 + 48));
  l3 = j1;
  i64_store((&memory), (u64)(i0 + 64), j1);
  B3:;
  j0 = l3;
  i0 = (u32)(j0);
  p0 = i0;
  i1 = 255u;
  i0 &= i1;
  i1 = 4u;
  i0 = i0 != i1;
  if (i0) {goto B10;}
  i0 = l1;
  i1 = _ZN3std2io5stdio6stdout17h060687408f12e049E();
  p0 = i1;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l1;
  i1 = 72u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = l1;
  i2 = 8u;
  i1 += i2;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = 72u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l1;
  i2 = 8u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = l1;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0 + 72), j1);
  i0 = l1;
  i1 = 40u;
  i0 += i1;
  i1 = l1;
  i2 = 48u;
  i1 += i2;
  i2 = l1;
  i3 = 72u;
  i2 += i3;
  _ZN57__LT_std__io__stdio__Stdout_u20_as_u20_std__io__Write_GT_9write_fmt17hfcc1c9dfb39740edE(i0, i1, i2);
  i0 = p0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B11;}
  i0 = l1;
  i1 = 48u;
  i0 += i1;
  _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h76eb5b162db06de2E(i0);
  B11:;
  i0 = l1;
  i0 = i32_load8_u((&memory), (u64)(i0 + 40));
  l2 = i0;
  p0 = i0;
  goto B9;
  B10:;
  i0 = l1;
  j1 = l3;
  i64_store((&memory), (u64)(i0 + 40), j1);
  j0 = l3;
  i0 = (u32)(j0);
  l2 = i0;
  B9:;
  i0 = p0;
  i1 = 255u;
  i0 &= i1;
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  i0 = 0u;
  if (i0) {goto B13;}
  i0 = l2;
  i1 = 3u;
  i0 &= i1;
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B12;}
  B13:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 44));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B14;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l4;
  i2 = l2;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B14:;
  i0 = p0;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B12:;
  i0 = l1;
  i1 = 96u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B2:;
  i0 = 1051060u;
  i1 = 16u;
  i2 = l1;
  i3 = 72u;
  i2 += i3;
  i3 = 1051372u;
  i4 = 1051144u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B1:;
  i0 = 1051060u;
  i1 = 16u;
  i2 = l1;
  i3 = 72u;
  i2 += i3;
  i3 = 1051372u;
  i4 = 1051144u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B0:;
  i0 = l1;
  i1 = l1;
  j1 = i64_load((&memory), (u64)(i1 + 40));
  i64_store((&memory), (u64)(i0 + 64), j1);
  i0 = l1;
  i1 = 92u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 60u;
  i0 += i1;
  i1 = 31u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 76), j1);
  i0 = l1;
  i1 = 1052904u;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l1;
  i1 = 33u;
  i32_store((&memory), (u64)(i0 + 52), i1);
  i0 = l1;
  i1 = l1;
  i2 = 48u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 88), i1);
  i0 = l1;
  i1 = l1;
  i2 = 64u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l1;
  i1 = l1;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l1;
  i1 = 72u;
  i0 += i1;
  i1 = 1052920u;
  _ZN3std9panicking15begin_panic_fmt17h3bc495be3b042206E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN56__LT_std__io__Guard_u20_as_u20_core__ops__drop__Drop_GT_4drop17h7f4cce983b4a506eE(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i32_store((&memory), (u64)(i0 + 8), i1);
  FUNC_EPILOGUE;
}

static void _ZN3std2io5Write14write_vectored17hcfbf4a1d27a1ae81E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1, j2;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p3;
  i1 = 3u;
  i0 <<= (i1 & 31);
  p3 = i0;
  i0 = p2;
  i1 = 4294967288u;
  i0 += i1;
  l5 = i0;
  L1: 
    i0 = p3;
    if (i0) {goto B2;}
    i0 = 1051284u;
    p2 = i0;
    i0 = 0u;
    l6 = i0;
    goto B0;
    B2:;
    i0 = p3;
    i1 = 4294967288u;
    i0 += i1;
    p3 = i0;
    i0 = l5;
    i1 = 8u;
    i0 += i1;
    l5 = i0;
    i0 = p2;
    i1 = 4u;
    i0 += i1;
    l6 = i0;
    i0 = p2;
    i1 = 8u;
    i0 += i1;
    p2 = i0;
    i0 = l6;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    i0 = !(i0);
    if (i0) {goto L1;}
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0));
  p2 = i0;
  B0:;
  i0 = l4;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l4;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = 1u;
  p2 = i0;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = 2u;
  i2 = l4;
  i3 = 8u;
  i2 += i3;
  i3 = 1u;
  _ZN4wasi13lib_generated8fd_write17hacbf9079620e9958E(i0, i1, i2, i3);
  i0 = l4;
  i0 = i32_load16_u((&memory), (u64)(i0 + 16));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  i0 = l4;
  i1 = l4;
  i1 = i32_load16_u((&memory), (u64)(i1 + 18));
  i32_store16((&memory), (u64)(i0 + 30), i1);
  i0 = p0;
  i1 = l4;
  i2 = 30u;
  i1 += i2;
  i1 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i1);
  j1 = (u64)(i1);
  j2 = 65535ull;
  j1 &= j2;
  j2 = 32ull;
  j1 <<= (j2 & 63);
  i64_store((&memory), (u64)(i0 + 4), j1);
  goto B3;
  B4:;
  i0 = p0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  p2 = i0;
  B3:;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN3std2io5Write18write_all_vectored17h31bcf0c43c76d367E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p3;
  i0 = !(i0);
  if (i0) {goto B1;}
  L2: 
    i0 = p3;
    i1 = 3u;
    i0 <<= (i1 & 31);
    l5 = i0;
    i0 = p2;
    i1 = 4294967288u;
    i0 += i1;
    l6 = i0;
    i0 = p2;
    l7 = i0;
    L4: 
      i0 = l5;
      if (i0) {goto B5;}
      i0 = 1051284u;
      l5 = i0;
      i0 = 0u;
      l8 = i0;
      goto B3;
      B5:;
      i0 = l5;
      i1 = 4294967288u;
      i0 += i1;
      l5 = i0;
      i0 = l6;
      i1 = 8u;
      i0 += i1;
      l6 = i0;
      i0 = l7;
      i1 = 4u;
      i0 += i1;
      l8 = i0;
      i0 = l7;
      i1 = 8u;
      i0 += i1;
      l7 = i0;
      i0 = l8;
      i0 = i32_load((&memory), (u64)(i0));
      l8 = i0;
      i0 = !(i0);
      if (i0) {goto L4;}
    i0 = l6;
    i0 = i32_load((&memory), (u64)(i0));
    l5 = i0;
    B3:;
    i0 = l4;
    i1 = l8;
    i32_store((&memory), (u64)(i0 + 12), i1);
    i0 = l4;
    i1 = l5;
    i32_store((&memory), (u64)(i0 + 8), i1);
    i0 = l4;
    i1 = 16u;
    i0 += i1;
    i1 = 2u;
    i2 = l4;
    i3 = 8u;
    i2 += i3;
    i3 = 1u;
    _ZN4wasi13lib_generated8fd_write17hacbf9079620e9958E(i0, i1, i2, i3);
    i0 = l4;
    i0 = i32_load16_u((&memory), (u64)(i0 + 16));
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B11;}
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 20));
    l9 = i0;
    if (i0) {goto B12;}
    i0 = 28u;
    i1 = 1u;
    i0 = __rust_alloc(i0, i1);
    l5 = i0;
    i0 = !(i0);
    if (i0) {goto B10;}
    i0 = l5;
    i1 = 24u;
    i0 += i1;
    i1 = 0u;
    i1 = i32_load((&memory), (u64)(i1 + 1052748));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l5;
    i1 = 16u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052740));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l5;
    i1 = 8u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052732));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l5;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052724));
    i64_store((&memory), (u64)(i0), j1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    l7 = i0;
    i0 = !(i0);
    if (i0) {goto B9;}
    i0 = l7;
    j1 = 120259084316ull;
    i64_store((&memory), (u64)(i0 + 4), j1);
    i0 = l7;
    i1 = l5;
    i32_store((&memory), (u64)(i0), i1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    l5 = i0;
    i0 = !(i0);
    if (i0) {goto B8;}
    i0 = l5;
    i1 = 14u;
    i32_store8((&memory), (u64)(i0 + 8), i1);
    i0 = l5;
    i1 = 1052004u;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l5;
    i1 = l7;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l5;
    i1 = l4;
    i1 = i32_load16_u((&memory), (u64)(i1 + 16));
    i32_store16((&memory), (u64)(i0 + 9), i1);
    i0 = l5;
    i1 = 11u;
    i0 += i1;
    i1 = l4;
    i2 = 16u;
    i1 += i2;
    i2 = 2u;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4u;
    i0 += i1;
    i1 = l5;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 2u;
    i32_store((&memory), (u64)(i0), i1);
    goto B0;
    B12:;
    i0 = p2;
    i1 = 4u;
    i0 += i1;
    l5 = i0;
    i0 = p3;
    i1 = 3u;
    i0 <<= (i1 & 31);
    i1 = 4294967288u;
    i0 += i1;
    i1 = 3u;
    i0 >>= (i1 & 31);
    i1 = 1u;
    i0 += i1;
    l10 = i0;
    i0 = 0u;
    l7 = i0;
    i0 = 0u;
    l6 = i0;
    L13: 
      i0 = l5;
      i0 = i32_load((&memory), (u64)(i0));
      i1 = l6;
      i0 += i1;
      l8 = i0;
      i1 = l9;
      i0 = i0 > i1;
      if (i0) {goto B7;}
      i0 = l5;
      i1 = 8u;
      i0 += i1;
      l5 = i0;
      i0 = l8;
      l6 = i0;
      i0 = l10;
      i1 = l7;
      i2 = 1u;
      i1 += i2;
      l7 = i1;
      i0 = i0 != i1;
      if (i0) {goto L13;}
    i0 = l8;
    l6 = i0;
    i0 = l10;
    l7 = i0;
    goto B7;
    B11:;
    i0 = l4;
    i1 = l4;
    i1 = i32_load16_u((&memory), (u64)(i1 + 18));
    i32_store16((&memory), (u64)(i0 + 30), i1);
    i0 = l4;
    i1 = 30u;
    i0 += i1;
    i0 = _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(i0);
    i1 = 65535u;
    i0 &= i1;
    l5 = i0;
    i0 = _ZN3std3sys4wasi17decode_error_kind17he23a249a9ada7316E(i0);
    i1 = 255u;
    i0 &= i1;
    i1 = 15u;
    i0 = i0 == i1;
    if (i0) {goto B6;}
    i0 = p0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4u;
    i0 += i1;
    i1 = l5;
    i32_store((&memory), (u64)(i0), i1);
    goto B0;
    B10:;
    i0 = 28u;
    i1 = 1u;
    _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
    UNREACHABLE;
    B9:;
    i0 = 12u;
    i1 = 4u;
    _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
    UNREACHABLE;
    B8:;
    i0 = 12u;
    i1 = 4u;
    _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
    UNREACHABLE;
    B7:;
    i0 = p3;
    i1 = l7;
    i0 = i0 < i1;
    if (i0) {goto B15;}
    i0 = p2;
    i1 = l7;
    i2 = 3u;
    i1 <<= (i2 & 31);
    i0 += i1;
    p2 = i0;
    i0 = p3;
    i1 = l7;
    i0 -= i1;
    p3 = i0;
    i0 = !(i0);
    if (i0) {goto B6;}
    i0 = p2;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l7 = i0;
    i1 = l9;
    i2 = l6;
    i1 -= i2;
    l5 = i1;
    i0 = i0 < i1;
    if (i0) {goto B14;}
    i0 = p2;
    i1 = 4u;
    i0 += i1;
    i1 = l7;
    i2 = l5;
    i1 -= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p2;
    i1 = p2;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = l5;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    goto B6;
    B15:;
    i0 = l7;
    i1 = p3;
    i2 = 1053016u;
    _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
    UNREACHABLE;
    B14:;
    i0 = 1054995u;
    i1 = 35u;
    i2 = 1055056u;
    _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
    UNREACHABLE;
    B6:;
    i0 = p3;
    if (i0) {goto L2;}
  B1:;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  B0:;
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN3std2io5Write18write_all_vectored17hbfa4a88028508b9dE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, l11 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p3;
  i0 = !(i0);
  if (i0) {goto B3;}
  L4: 
    i0 = l4;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = p2;
    i3 = p3;
    i4 = p1;
    i4 = i32_load((&memory), (u64)(i4 + 4));
    i4 = i32_load((&memory), (u64)(i4 + 16));
    CALL_INDIRECT(T0, void (*)(u32, u32, u32, u32), 5, i4, i0, i1, i2, i3);
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    l5 = i0;
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B10;}
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l6 = i0;
    if (i0) {goto B11;}
    i0 = 28u;
    i1 = 1u;
    i0 = __rust_alloc(i0, i1);
    l7 = i0;
    i0 = !(i0);
    if (i0) {goto B9;}
    i0 = l7;
    i1 = 24u;
    i0 += i1;
    i1 = 0u;
    i1 = i32_load((&memory), (u64)(i1 + 1052748));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l7;
    i1 = 16u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052740));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l7;
    i1 = 8u;
    i0 += i1;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052732));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l7;
    i1 = 0u;
    j1 = i64_load((&memory), (u64)(i1 + 1052724));
    i64_store((&memory), (u64)(i0), j1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    l8 = i0;
    i0 = !(i0);
    if (i0) {goto B8;}
    i0 = l8;
    j1 = 120259084316ull;
    i64_store((&memory), (u64)(i0 + 4), j1);
    i0 = l8;
    i1 = l7;
    i32_store((&memory), (u64)(i0), i1);
    i0 = 12u;
    i1 = 4u;
    i0 = __rust_alloc(i0, i1);
    l7 = i0;
    i0 = !(i0);
    if (i0) {goto B7;}
    i0 = l7;
    i1 = 14u;
    i32_store8((&memory), (u64)(i0 + 8), i1);
    i0 = l7;
    i1 = 1052004u;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l7;
    i1 = l8;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l7;
    i1 = l4;
    i1 = i32_load16_u((&memory), (u64)(i1 + 13));
    i32_store16((&memory), (u64)(i0 + 9), i1);
    i0 = l7;
    i1 = 11u;
    i0 += i1;
    i1 = l4;
    i2 = 13u;
    i1 += i2;
    i2 = 2u;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4u;
    i0 += i1;
    i1 = l7;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 2u;
    i32_store((&memory), (u64)(i0), i1);
    goto B0;
    B11:;
    i0 = p2;
    i1 = 4u;
    i0 += i1;
    l7 = i0;
    i0 = p3;
    i1 = 3u;
    i0 <<= (i1 & 31);
    i1 = 4294967288u;
    i0 += i1;
    i1 = 3u;
    i0 >>= (i1 & 31);
    i1 = 1u;
    i0 += i1;
    l9 = i0;
    i0 = 0u;
    l8 = i0;
    i0 = 0u;
    l10 = i0;
    L12: 
      i0 = l7;
      i0 = i32_load((&memory), (u64)(i0));
      i1 = l10;
      i0 += i1;
      l11 = i0;
      i1 = l6;
      i0 = i0 > i1;
      if (i0) {goto B6;}
      i0 = l7;
      i1 = 8u;
      i0 += i1;
      l7 = i0;
      i0 = l11;
      l10 = i0;
      i0 = l9;
      i1 = l8;
      i2 = 1u;
      i1 += i2;
      l8 = i1;
      i0 = i0 != i1;
      if (i0) {goto L12;}
    i0 = l11;
    l10 = i0;
    i0 = l9;
    l8 = i0;
    goto B6;
    B10:;
    i0 = l4;
    i0 = i32_load8_u((&memory), (u64)(i0 + 4));
    l6 = i0;
    switch (i0) {
      case 0: goto B15;
      case 1: goto B16;
      case 2: goto B14;
      default: goto B15;
    }
    B16:;
    i0 = l4;
    i0 = i32_load8_u((&memory), (u64)(i0 + 5));
    l7 = i0;
    goto B13;
    B15:;
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    i0 = _ZN3std3sys4wasi17decode_error_kind17he23a249a9ada7316E(i0);
    i1 = 255u;
    i0 &= i1;
    l7 = i0;
    goto B13;
    B14:;
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    i0 = i32_load8_u((&memory), (u64)(i0 + 8));
    l7 = i0;
    B13:;
    i0 = 1u;
    l5 = i0;
    i0 = l7;
    i1 = 255u;
    i0 &= i1;
    i1 = 15u;
    i0 = i0 == i1;
    if (i0) {goto B5;}
    i0 = p0;
    i1 = l4;
    j1 = i64_load((&memory), (u64)(i1 + 4));
    i64_store((&memory), (u64)(i0), j1);
    goto B0;
    B9:;
    i0 = 28u;
    i1 = 1u;
    _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
    UNREACHABLE;
    B8:;
    i0 = 12u;
    i1 = 4u;
    _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
    UNREACHABLE;
    B7:;
    i0 = 12u;
    i1 = 4u;
    _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
    UNREACHABLE;
    B6:;
    i0 = p3;
    i1 = l8;
    i0 = i0 < i1;
    if (i0) {goto B2;}
    i0 = p2;
    i1 = l8;
    i2 = 3u;
    i1 <<= (i2 & 31);
    i0 += i1;
    p2 = i0;
    i0 = p3;
    i1 = l8;
    i0 -= i1;
    p3 = i0;
    i0 = !(i0);
    if (i0) {goto B5;}
    i0 = p2;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l8 = i0;
    i1 = l6;
    i2 = l10;
    i1 -= i2;
    l7 = i1;
    i0 = i0 < i1;
    if (i0) {goto B1;}
    i0 = p2;
    i1 = 4u;
    i0 += i1;
    i1 = l8;
    i2 = l7;
    i1 -= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p2;
    i1 = p2;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = l7;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l4;
    i0 = i32_load8_u((&memory), (u64)(i0 + 4));
    l6 = i0;
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    l5 = i0;
    B5:;
    i0 = l5;
    i0 = !(i0);
    if (i0) {goto B17;}
    i0 = l6;
    i1 = 255u;
    i0 &= i1;
    i1 = 2u;
    i0 = i0 < i1;
    if (i0) {goto B17;}
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    l7 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l7;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i1 = i32_load((&memory), (u64)(i1));
    CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l8 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l10 = i0;
    i0 = !(i0);
    if (i0) {goto B18;}
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l10;
    i2 = l8;
    i2 = i32_load((&memory), (u64)(i2 + 8));
    __rust_dealloc(i0, i1, i2);
    B18:;
    i0 = l7;
    i1 = 12u;
    i2 = 4u;
    __rust_dealloc(i0, i1, i2);
    B17:;
    i0 = p3;
    if (i0) {goto L4;}
  B3:;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  goto B0;
  B2:;
  i0 = l8;
  i1 = p3;
  i2 = 1053016u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = 1054995u;
  i1 = 35u;
  i2 = 1055056u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN3std2io5Write9write_fmt17h61c08c303399aa39E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = 24u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p2;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 24u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = p2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = 1053048u;
  i2 = l3;
  i3 = 24u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0 + 12));
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B5;}
  i0 = 15u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p2;
  i1 = 7u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1053079));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p2;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1053072));
  i64_store((&memory), (u64)(i0), j1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p1;
  j1 = 64424509455ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = p1;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p2;
  i1 = 16u;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = p2;
  i1 = 1052004u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p2;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = l3;
  i1 = i32_load16_u((&memory), (u64)(i1 + 24));
  i32_store16((&memory), (u64)(i0 + 9), i1);
  i0 = p2;
  i1 = 11u;
  i0 += i1;
  i1 = l3;
  i2 = 24u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  goto B0;
  B5:;
  i0 = p0;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1 + 12));
  i64_store((&memory), (u64)(i0), j1);
  goto B0;
  B4:;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = 0u;
  if (i0) {goto B6;}
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0 + 12));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  B6:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p2 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p2;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B7:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  goto B0;
  B3:;
  i0 = 15u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B2:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = l3;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN80__LT_std__io__Write__write_fmt__Adaptor_LT_T_GT__u20_as_u20_core__fmt__Write_GT_9write_str17habbf305c93d57a52E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l5 = 0;
  u64 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p1;
  i3 = p2;
  _ZN3std2io5Write9write_all17h0ac6a6a37a604fceE(i0, i1, i2, i3);
  i0 = 0u;
  p1 = i0;
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  i1 = 3u;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = l3;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l4 = j0;
  i0 = 0u;
  if (i0) {goto B2;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  B2:;
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p2 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  i0 = p0;
  j1 = l4;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = 1u;
  p1 = i0;
  B0:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN80__LT_std__io__Write__write_fmt__Adaptor_LT_T_GT__u20_as_u20_core__fmt__Write_GT_9write_str17hfba8d08e2a0d6be2E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l5 = 0;
  u64 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p1;
  i3 = p2;
  _ZN3std2io5Write9write_all17h3c6b69cf0d5dfa52E(i0, i1, i2, i3);
  i0 = 0u;
  p1 = i0;
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  i1 = 3u;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = l3;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l4 = j0;
  i0 = 0u;
  if (i0) {goto B2;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  B2:;
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p2 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  i0 = p0;
  j1 = l4;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = 1u;
  p1 = i0;
  B0:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN79__LT_std__path__Path_u20_as_u20_core__convert__AsRef_LT_std__path__Path_GT__GT_6as_ref17h7dc33fb987337414E(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN59__LT_std__process__ChildStdin_u20_as_u20_std__io__Write_GT_5flush17h3236cbe8e09377f1E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN3std7process4exit17h15172f2c8741ba8bE(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  _ZN3std10sys_common7cleanup17h0efc2b08e2a4a6c3E();
  i0 = p0;
  _ZN3std3sys4wasi2os4exit17h7b4910da2192d43dE(i0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN3std10sys_common7cleanup17h0efc2b08e2a4a6c3E(void) {
  u32 l0 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l0 = i0;
  g0 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061664));
  i1 = 3u;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = l0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 11), i1);
  i0 = l0;
  i1 = l0;
  i2 = 11u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = 1061664u;
  i1 = 0u;
  i2 = l0;
  i3 = 12u;
  i2 += i3;
  i3 = 1053224u;
  _ZN3std4sync4once4Once10call_inner17h74e47fc5d3e1aa49E(i0, i1, i2, i3);
  B0:;
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN3std3sys4wasi2os4exit17h7b4910da2192d43dE(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  exit(i0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN3std7process5abort17h5ef35935ef2edf2cE(void) {
  FUNC_PROLOGUE;
  _ZN3std3sys4wasi14abort_internal17h148e8bcb88f086ceE();
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN3std3sys4wasi14abort_internal17h148e8bcb88f086ceE(void) {
  FUNC_PROLOGUE;
  abort();
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN70__LT_std__sync__once__WaiterQueue_u20_as_u20_core__ops__drop__Drop_GT_4drop17h18e38d5577964ed0E(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = l2;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = l3;
  i2 = 3u;
  i1 &= i2;
  p0 = i1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  i0 = l3;
  i1 = 4294967292u;
  i0 &= i1;
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B4;}
  L5: 
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l2 = i0;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0));
    l3 = i0;
    i0 = p0;
    i1 = 0u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i0 = !(i0);
    if (i0) {goto B3;}
    i0 = p0;
    i1 = 1u;
    i32_store8((&memory), (u64)(i0 + 8), i1);
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    p0 = i0;
    i0 = l3;
    i1 = 2u;
    i32_store((&memory), (u64)(i0 + 24), i1);
    i0 = l1;
    i1 = l3;
    i32_store((&memory), (u64)(i0 + 40), i1);
    i0 = p0;
    i1 = 2u;
    i0 = i0 > i1;
    if (i0) {goto B8;}
    i0 = p0;
    switch (i0) {
      case 0: goto B6;
      case 1: goto B7;
      case 2: goto B6;
      default: goto B6;
    }
    B8:;
    i0 = 1051840u;
    i1 = 28u;
    i2 = 1051868u;
    _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
    UNREACHABLE;
    B7:;
    i0 = l1;
    i0 = i32_load((&memory), (u64)(i0 + 40));
    p0 = i0;
    i1 = 28u;
    i0 += i1;
    l3 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l4 = i0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    if (i0) {goto B2;}
    i0 = l4;
    i1 = 1u;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = 0u;
    i0 = i32_load((&memory), (u64)(i0 + 1061728));
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B10;}
    i0 = 0u;
    i0 = i32_load((&memory), (u64)(i0 + 1061732));
    l4 = i0;
    goto B9;
    B10:;
    i0 = 0u;
    l4 = i0;
    i0 = 0u;
    j1 = 1ull;
    i64_store((&memory), (u64)(i0 + 1061728), j1);
    B9:;
    i0 = 0u;
    i1 = l4;
    i32_store((&memory), (u64)(i0 + 1061732), i1);
    i0 = p0;
    i0 = i32_load8_u((&memory), (u64)(i0 + 32));
    if (i0) {goto B1;}
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = 0u;
    i32_store8((&memory), (u64)(i0), i1);
    B6:;
    i0 = l1;
    i0 = i32_load((&memory), (u64)(i0 + 40));
    p0 = i0;
    i1 = p0;
    i1 = i32_load((&memory), (u64)(i1));
    p0 = i1;
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B11;}
    i0 = l1;
    i1 = 40u;
    i0 += i1;
    _ZN5alloc4sync12Arc_LT_T_GT_9drop_slow17h54081c59c02bd7eaE(i0);
    B11:;
    i0 = l2;
    p0 = i0;
    i0 = l2;
    if (i0) {goto L5;}
  B4:;
  i0 = l1;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B3:;
  i0 = 1051328u;
  i1 = 43u;
  i2 = 1053436u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B2:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = l1;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l1;
  i1 = l4;
  i2 = 0u;
  i1 = i1 != i2;
  i32_store8((&memory), (u64)(i0 + 20), i1);
  i0 = 1051420u;
  i1 = 43u;
  i2 = l1;
  i3 = 16u;
  i2 += i3;
  i3 = 1051464u;
  i4 = 1051884u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B0:;
  i0 = l1;
  i1 = 52u;
  i0 += i1;
  i1 = 30u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 36u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  j1 = 3ull;
  i64_store((&memory), (u64)(i0 + 20), j1);
  i0 = l1;
  i1 = 1051260u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l1;
  i1 = 30u;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l1;
  i1 = l1;
  i2 = 12u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l1;
  i1 = 1051628u;
  i32_store((&memory), (u64)(i0 + 60), i1);
  i0 = l1;
  i1 = l1;
  i2 = 40u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l1;
  i1 = l1;
  i2 = 60u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l1;
  i1 = l1;
  i2 = 56u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  i1 = 1053420u;
  _ZN3std9panicking15begin_panic_fmt17h3bc495be3b042206E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 _ZN91__LT_std__sys_common__backtrace___print__DisplayBacktrace_u20_as_u20_core__fmt__Display_GT_3fmt17h25daba2a18d6a743E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l5 = 0, l6 = 0, l7 = 0;
  u64 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  l3 = i0;
  i0 = l2;
  i1 = 40u;
  i0 += i1;
  _ZN3std3sys4wasi11unsupported17hd974f16cf85baeceE(i0);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 40));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  j0 = i64_load((&memory), (u64)(i0));
  l4 = j0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 44));
  p0 = i0;
  goto B0;
  B1:;
  i0 = 0u;
  p0 = i0;
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 44));
  i1 = 2u;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l6 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l7 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l7;
  i2 = l6;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B3:;
  i0 = l5;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B2:;
  B0:;
  i0 = l2;
  j1 = l4;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l3;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 60u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 44), j1);
  i0 = l2;
  i1 = 1053556u;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = p1;
  i1 = l2;
  i2 = 40u;
  i1 += i2;
  i0 = _ZN4core3fmt9Formatter9write_fmt17h5f4a789bf06948b3E(i0, i1);
  if (i0) {goto B5;}
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = l3;
  i3 = l2;
  i4 = 1053564u;
  _ZN9backtrace5print12BacktraceFmt3new17h3ab018832264a723E(i0, i1, i2, i3, i4);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i0 = _ZN9backtrace5print12BacktraceFmt11add_context17hc1ee7fb8cfa6f36aE(i0);
  if (i0) {goto B6;}
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i0 = _ZN9backtrace5print12BacktraceFmt11add_context17hc1ee7fb8cfa6f36aE(i0);
  if (i0) {goto B6;}
  i0 = l3;
  i1 = 255u;
  i0 &= i1;
  if (i0) {goto B7;}
  i0 = l2;
  i1 = 60u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 44), j1);
  i0 = l2;
  i1 = 1053672u;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = p1;
  i1 = l2;
  i2 = 40u;
  i1 += i2;
  i0 = _ZN4core3fmt9Formatter9write_fmt17h5f4a789bf06948b3E(i0, i1);
  if (i0) {goto B6;}
  B7:;
  i0 = 0u;
  l3 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = p0;
  i1 = p1;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  goto B4;
  B6:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  B5:;
  i0 = 1u;
  l3 = i0;
  i0 = p0;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = 1u;
  l3 = i0;
  i0 = p0;
  i1 = p1;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B4:;
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  i0 = l3;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN3std10sys_common9backtrace10_print_fmt28__u7b__u7b_closure_u7d__u7d_17ha62efdc37013783cE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = 1053684u;
  p2 = i0;
  i0 = 9u;
  l4 = i0;
  goto B0;
  B1:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  i1 = p2;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = p2;
  i3 = 8u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  _ZN4core3str9from_utf817he6f02ee8cec749d4E(i0, i1, i2);
  i0 = 1053684u;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  i2 = l3;
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i3 = 1u;
  i2 = i2 == i3;
  l4 = i2;
  i0 = i2 ? i0 : i1;
  p2 = i0;
  i0 = 9u;
  i1 = l3;
  i2 = 16u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = l4;
  i0 = i2 ? i0 : i1;
  l4 = i0;
  B0:;
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  i2 = l4;
  _ZN4core3str5lossy9Utf8Lossy10from_bytes17h1fc730ab18994b0dE(i0, i1, i2);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1 + 12));
  i2 = p1;
  i0 = _ZN66__LT_core__str__lossy__Utf8Lossy_u20_as_u20_core__fmt__Display_GT_3fmt17h9396f0cf1136f103E(i0, i1, i2);
  p2 = i0;
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p2;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17hd2bb8386068f691aE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32), 7, i1, i0);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std3sys4wasi7condvar7Condvar4wait17h08e64e77fb399e8fE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = 1054800u;
  i1 = 29u;
  i2 = 1054868u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN82__LT_std__sys_common__poison__PoisonError_LT_T_GT__u20_as_u20_core__fmt__Debug_GT_3fmt17h16f30397faa9688eE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = 1053736u;
  i1 = 25u;
  i2 = p1;
  i0 = _ZN40__LT_str_u20_as_u20_core__fmt__Debug_GT_3fmt17hc81f6984a0ce9960E(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std10sys_common4util10dumb_print17h200d2c5cffd6deeaE(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p0;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l1;
  i1 = p0;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = l1;
  i1 = 8u;
  i0 += i1;
  i1 = l1;
  i2 = 40u;
  i1 += i2;
  i2 = l1;
  i3 = 16u;
  i2 += i3;
  _ZN3std2io5Write9write_fmt17h61c08c303399aa39E(i0, i1, i2);
  i0 = 0u;
  if (i0) {goto B1;}
  i0 = l1;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  B1:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l3;
  i2 = l2;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B2:;
  i0 = p0;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = l1;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN3std10sys_common4util5abort17hc50d73ca76b1b533E(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = l1;
  i1 = 20u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l1;
  i1 = 1053876u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 27u;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l1;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l1;
  i1 = l1;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l1;
  _ZN3std10sys_common4util10dumb_print17h200d2c5cffd6deeaE(i0);
  _ZN3std3sys4wasi14abort_internal17h148e8bcb88f086ceE();
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN3std5alloc24default_alloc_error_hook17h676e6a95f439f851E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = l2;
  i1 = l2;
  i2 = 20u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 52u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 36), j1);
  i0 = l2;
  i1 = 1053960u;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l2;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l2;
  i1 = 24u;
  i0 += i1;
  i1 = l2;
  i2 = 56u;
  i1 += i2;
  i2 = l2;
  i3 = 32u;
  i2 += i3;
  _ZN3std2io5Write9write_fmt17h61c08c303399aa39E(i0, i1, i2);
  i0 = 0u;
  if (i0) {goto B1;}
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 24));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  B1:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l4;
  i2 = l3;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B2:;
  i0 = p0;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void rust_oom(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i1 = p1;
  i2 = 0u;
  i2 = i32_load((&memory), (u64)(i2 + 1061668));
  l2 = i2;
  i3 = 37u;
  i4 = l2;
  i2 = i4 ? i2 : i3;
  CALL_INDIRECT(T0, void (*)(u32, u32), 1, i2, i0, i1);
  _ZN3std3sys4wasi14abort_internal17h148e8bcb88f086ceE();
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 __rdl_alloc(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p1;
  i1 = 8u;
  i0 = i0 > i1;
  if (i0) {goto B1;}
  i0 = p1;
  i1 = p0;
  i0 = i0 <= i1;
  if (i0) {goto B0;}
  B1:;
  i0 = p1;
  i1 = p0;
  i0 = aligned_alloc(i0, i1);
  goto Bfunc;
  B0:;
  i0 = p0;
  i0 = malloc(i0);
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void __rdl_dealloc(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  free(i0);
  FUNC_EPILOGUE;
}

static u32 __rdl_realloc(u32 p0, u32 p1, u32 p2, u32 p3) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5;
  i0 = p2;
  i1 = 8u;
  i0 = i0 > i1;
  if (i0) {goto B1;}
  i0 = p2;
  i1 = p3;
  i0 = i0 <= i1;
  if (i0) {goto B0;}
  B1:;
  i0 = p2;
  i1 = p3;
  i0 = aligned_alloc(i0, i1);
  p2 = i0;
  if (i0) {goto B2;}
  i0 = 0u;
  goto Bfunc;
  B2:;
  i0 = p2;
  i1 = p0;
  i2 = p3;
  i3 = p1;
  i4 = p1;
  i5 = p3;
  i4 = i4 > i5;
  i2 = i4 ? i2 : i3;
  i0 = memcpy_0(i0, i1, i2);
  p3 = i0;
  i0 = p0;
  free(i0);
  i0 = p3;
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = p3;
  i0 = realloc(i0, i1);
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN3std9panicking12default_hook28__u7b__u7b_closure_u7d__u7d_17h586ab2a6a28d8372E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = 20u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 38u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 44u;
  i0 += i1;
  i1 = 33u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  j1 = 4ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l3;
  i1 = 1054144u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 33u;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l3;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l3;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l3;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l3;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l3;
  i1 = 24u;
  i0 += i1;
  i1 = p1;
  i2 = l3;
  i3 = p2;
  i3 = i32_load((&memory), (u64)(i3 + 32));
  p2 = i3;
  CALL_INDIRECT(T0, void (*)(u32, u32, u32), 6, i3, i0, i1, i2);
  i0 = 0u;
  if (i0) {goto B1;}
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0 + 24));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  B1:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  l4 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i2 = l5;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B2:;
  i0 = l4;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B0:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i0 = i32_load8_u((&memory), (u64)(i0));
  l4 = i0;
  i1 = 4294967293u;
  i0 += i1;
  i1 = 255u;
  i0 &= i1;
  p0 = i0;
  i1 = 1u;
  i0 += i1;
  i1 = 0u;
  i2 = p0;
  i3 = 2u;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  switch (i0) {
    case 0: goto B6;
    case 1: goto B4;
    case 2: goto B5;
    default: goto B6;
  }
  B6:;
  i0 = 0u;
  i0 = i32_load8_u((&memory), (u64)(i0 + 1061738));
  if (i0) {goto B3;}
  i0 = 0u;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 1061738), i1);
  i0 = l3;
  i1 = 52u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 36), j1);
  i0 = l3;
  i1 = 1052640u;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l3;
  i1 = 39u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = l4;
  i32_store8((&memory), (u64)(i0 + 63), i1);
  i0 = l3;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l3;
  i1 = l3;
  i2 = 63u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 24u;
  i0 += i1;
  i1 = p1;
  i2 = l3;
  i3 = 32u;
  i2 += i3;
  i3 = p2;
  CALL_INDIRECT(T0, void (*)(u32, u32, u32), 6, i3, i0, i1, i2);
  i0 = 0u;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1061738), i1);
  i0 = 0u;
  if (i0) {goto B7;}
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0 + 24));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  B7:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p2;
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B8:;
  i0 = p0;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  goto B4;
  B5:;
  i0 = 0u;
  i0 = i32_load8_u((&memory), (u64)(i0 + 1061632));
  p0 = i0;
  i0 = 0u;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1061632), i1);
  i0 = p0;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l3;
  i1 = 52u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l3;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 36), j1);
  i0 = l3;
  i1 = 1054256u;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l3;
  i1 = p1;
  i2 = l3;
  i3 = 32u;
  i2 += i3;
  i3 = p2;
  CALL_INDIRECT(T0, void (*)(u32, u32, u32), 6, i3, i0, i1, i2);
  i0 = 0u;
  if (i0) {goto B9;}
  i0 = l3;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  B9:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i1 = i32_load((&memory), (u64)(i1));
  CALL_INDIRECT(T0, void (*)(u32), 0, i1, i0);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p2;
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  __rust_dealloc(i0, i1, i2);
  B10:;
  i0 = p0;
  i1 = 12u;
  i2 = 4u;
  __rust_dealloc(i0, i1, i2);
  B4:;
  i0 = l3;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B3:;
  i0 = 1055072u;
  i1 = 32u;
  i2 = 1055140u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void rust_begin_unwind(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = p0;
  i0 = _ZN4core5panic9PanicInfo8location17hadae980b9a5e60d2E(i0);
  i1 = 1054264u;
  i0 = _ZN4core6option15Option_LT_T_GT_6unwrap17hcef08ddb8cf9885dE(i0, i1);
  l2 = i0;
  i0 = p0;
  i0 = _ZN4core5panic9PanicInfo7message17h92bd97d427b892e1E(i0);
  i0 = _ZN4core6option15Option_LT_T_GT_6unwrap17hf88ae310ea733521E(i0);
  l3 = i0;
  i0 = l1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = 1054296u;
  i2 = p0;
  i2 = _ZN4core5panic9PanicInfo7message17h92bd97d427b892e1E(i2);
  i3 = l2;
  _ZN3std9panicking20rust_panic_with_hook17hb8132b4308a71007E(i0, i1, i2, i3);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN3std9panicking20rust_panic_with_hook17hb8132b4308a71007E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = 1u;
  l5 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061728));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B3;}
  i0 = 0u;
  j1 = 4294967297ull;
  i64_store((&memory), (u64)(i0 + 1061728), j1);
  goto B2;
  B3:;
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061732));
  i2 = 1u;
  i1 += i2;
  l5 = i1;
  i32_store((&memory), (u64)(i0 + 1061732), i1);
  i0 = l5;
  i1 = 2u;
  i0 = i0 > i1;
  if (i0) {goto B1;}
  B2:;
  i0 = l4;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l4;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l4;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l4;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061672));
  p2 = i0;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B4;}
  i0 = 0u;
  i1 = p2;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 1061672), i1);
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061680));
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B6;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061676));
  p3 = i0;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = p0;
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 16));
  CALL_INDIRECT(T0, void (*)(u32, u32), 1, i2, i0, i1);
  i0 = l4;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1 + 16));
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = p3;
  i1 = l4;
  i2 = 24u;
  i1 += i2;
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 12));
  CALL_INDIRECT(T0, void (*)(u32, u32), 1, i2, i0, i1);
  goto B5;
  B6:;
  i0 = l4;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 16));
  CALL_INDIRECT(T0, void (*)(u32, u32), 1, i2, i0, i1);
  i0 = l4;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l4;
  i1 = 24u;
  i0 += i1;
  _ZN3std9panicking12default_hook17h61085b8eace1a41cE(i0);
  B5:;
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061672));
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 1061672), i1);
  i0 = l5;
  i1 = 1u;
  i0 = i0 <= i1;
  if (i0) {goto B0;}
  i0 = l4;
  i1 = 60u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l4;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 44), j1);
  i0 = l4;
  i1 = 1054472u;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l4;
  i1 = 40u;
  i0 += i1;
  _ZN3std10sys_common4util10dumb_print17h200d2c5cffd6deeaE(i0);
  UNREACHABLE;
  B4:;
  i0 = l4;
  i1 = 60u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l4;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 44), j1);
  i0 = l4;
  i1 = 1055260u;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l4;
  i1 = 40u;
  i0 += i1;
  _ZN3std10sys_common4util5abort17hc50d73ca76b1b533E(i0);
  UNREACHABLE;
  B1:;
  i0 = l4;
  i1 = 60u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 1051284u;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l4;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 44), j1);
  i0 = l4;
  i1 = 1054420u;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l4;
  i1 = 40u;
  i0 += i1;
  _ZN3std10sys_common4util10dumb_print17h200d2c5cffd6deeaE(i0);
  UNREACHABLE;
  B0:;
  i0 = p0;
  i1 = p1;
  rust_panic(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN90__LT_std__panicking__begin_panic_handler__PanicPayload_u20_as_u20_core__panic__BoxMeUp_GT_8take_box17h2d26e4289e9e0f5bE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l2;
  i1 = l2;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l2;
  i1 = 40u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = l4;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 40u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 40), j1);
  i0 = l2;
  i1 = 36u;
  i0 += i1;
  i1 = 1050904u;
  i2 = l2;
  i3 = 40u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  l4 = i0;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 32));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 24));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l5;
  i1 = l6;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  i0 = l3;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  B0:;
  i0 = p1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p1;
  i1 = 12u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  i0 = p1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p1 = i0;
  if (i0) {goto B2;}
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B2:;
  i0 = p1;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p1;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 1054316u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN90__LT_std__panicking__begin_panic_handler__PanicPayload_u20_as_u20_core__panic__BoxMeUp_GT_3get17haebaf56b59d9f0f7E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  if (i0) {goto B0;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l2;
  i1 = l2;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l2;
  i1 = 40u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = l4;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 40u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 40), j1);
  i0 = l2;
  i1 = 36u;
  i0 += i1;
  i1 = 1050904u;
  i2 = l2;
  i3 = 40u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  l4 = i0;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 32));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 24));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l5;
  i1 = p1;
  i2 = 1u;
  __rust_dealloc(i0, i1, i2);
  B1:;
  i0 = l3;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  B0:;
  i0 = p0;
  i1 = 1054316u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN91__LT_std__panicking__begin_panic__PanicPayload_LT_A_GT__u20_as_u20_core__panic__BoxMeUp_GT_8take_box17h00afc1f3240f4984E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i0 = p1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i0 = 8u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 1054352u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B1:;
  _ZN3std7process5abort17h5ef35935ef2edf2cE();
  UNREACHABLE;
  B0:;
  i0 = 8u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN91__LT_std__panicking__begin_panic__PanicPayload_LT_A_GT__u20_as_u20_core__panic__BoxMeUp_GT_3get17hf7b2418ff47c602eE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  if (i0) {goto B0;}
  _ZN3std7process5abort17h5ef35935ef2edf2cE();
  UNREACHABLE;
  B0:;
  i0 = p0;
  i1 = 1054352u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void rust_panic(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l2;
  i1 = __rust_start_panic(i1);
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 36u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 20), j1);
  i0 = l2;
  i1 = 1054512u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l2;
  i1 = l2;
  i2 = 40u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l2;
  i1 = l2;
  i2 = 12u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  _ZN3std10sys_common4util5abort17hc50d73ca76b1b533E(i0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN3std2rt19lang_start_internal17h66de5b0ec01e6d33E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = 4u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l5;
  i1 = 1852399981u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  j1 = 17179869188ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l4;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i0 = _ZN3std6thread6Thread3new17h1d02bb6db813b9d0E(i0);
  l5 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061716));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B5;}
  i0 = 0u;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 1061716), j1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061724), i1);
  goto B4;
  B5:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061720));
  l6 = i0;
  i1 = 1u;
  i0 += i1;
  i1 = 0u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061724));
  if (i0) {goto B1;}
  i0 = l6;
  if (i0) {goto B0;}
  B4:;
  i0 = 0u;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 1061724), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061720), i1);
  i0 = p0;
  i1 = p1;
  i0 = _ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17hd2bb8386068f691aE(i0, i1);
  l5 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061664));
  i1 = 3u;
  i0 = i0 == i1;
  if (i0) {goto B6;}
  i0 = l4;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 15), i1);
  i0 = l4;
  i1 = l4;
  i2 = 15u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 1061664u;
  i1 = 0u;
  i2 = l4;
  i3 = 1053224u;
  _ZN3std4sync4once4Once10call_inner17h74e47fc5d3e1aa49E(i0, i1, i2, i3);
  B6:;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = l5;
  goto Bfunc;
  B3:;
  i0 = 4u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B2:;
  i0 = 1051160u;
  i1 = 24u;
  i2 = l4;
  i3 = 1051404u;
  i4 = 1051184u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B1:;
  i0 = 1053797u;
  i1 = 38u;
  i2 = 1053836u;
  _ZN3std9panicking11begin_panic17h03009c70f59374e1E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = 1051060u;
  i1 = 16u;
  i2 = l4;
  i3 = 1051372u;
  i4 = 1051144u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN62__LT_std__ffi__c_str__NulError_u20_as_u20_core__fmt__Debug_GT_3fmt17h7aebd1ccdb940e5aE(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p1;
  i2 = 1054520u;
  i3 = 8u;
  _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(i0, i1, i2, i3);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = l2;
  i2 = 12u;
  i1 += i2;
  i2 = 1051532u;
  i0 = _ZN4core3fmt8builders10DebugTuple5field17h16202dfa3a9387a4E(i0, i1, i2);
  i0 = l2;
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = l2;
  i2 = 12u;
  i1 += i2;
  i2 = 1054528u;
  i0 = _ZN4core3fmt8builders10DebugTuple5field17h16202dfa3a9387a4E(i0, i1, i2);
  i0 = l2;
  i0 = _ZN4core3fmt8builders10DebugTuple6finish17h540db6bc8e5a3697E(i0);
  p0 = i0;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN68__LT_std__sys__wasi__fd__WasiFd_u20_as_u20_core__ops__drop__Drop_GT_4drop17h4d2e151266c87dc4E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = _ZN4wasi13lib_generated8fd_close17hfa5cf758483496b0E(i0);
  FUNC_EPILOGUE;
}

static void _ZN3std3sys4wasi2fs9osstr2str17h2b93d5c461792507E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = p1;
  i2 = p2;
  _ZN4core3str9from_utf817he6f02ee8cec749d4E(i0, i1, i2);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B5;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p2 = i0;
  if (i0) {goto B4;}
  B5:;
  i0 = 19u;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p1;
  i1 = 15u;
  i0 += i1;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1054991));
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1054984));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1054976));
  i64_store((&memory), (u64)(i0), j1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p2;
  j1 = 81604378643ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = p2;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 12u;
  i1 = 4u;
  i0 = __rust_alloc(i0, i1);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 16u;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = p1;
  i1 = 1052004u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p1;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l3;
  i1 = i32_load16_u((&memory), (u64)(i1 + 13));
  i32_store16((&memory), (u64)(i0 + 9), i1);
  i0 = p1;
  i1 = 11u;
  i0 += i1;
  i1 = l3;
  i2 = 13u;
  i1 += i2;
  i2 = 2u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 2u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 1u;
  p2 = i0;
  goto B3;
  B4:;
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  p2 = i0;
  B3:;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B2:;
  i0 = 19u;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h09718f7e4676ca1fE(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 12u;
  i1 = 4u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN3std3sys4wasi5mutex14ReentrantMutex6unlock17h57b66397f140f523E(u32 p0) {
  FUNC_PROLOGUE;
  FUNC_EPILOGUE;
}

static u32 _ZN3std3sys4wasi7process8ExitCode6as_i3217h363ebb260b4f8711E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN3std3sys4wasi5stdio8is_ebadf17h866f32eebed413cfE(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i0 = !(i0);
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 8u;
  i1 = i1 == i2;
  i0 &= i1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 __rust_start_panic(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  UNREACHABLE;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4wasi5error5Error9raw_error17h8765b01882d84998E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  i0 = i32_load16_u((&memory), (u64)(i0));
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4wasi13lib_generated8fd_close17hfa5cf758483496b0E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  i0 = (*Z_wasi_snapshot_preview1Z_fd_closeZ_ii)(i0);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4wasi13lib_generated7fd_read17h0d476bb7732cd2ceE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p1;
  i1 = p2;
  i2 = p3;
  i3 = l4;
  i4 = 12u;
  i3 += i4;
  i0 = (*Z_wasi_snapshot_preview1Z_fd_readZ_iiiii)(i0, i1, i2, i3);
  p1 = i0;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 12));
  i32_store((&memory), (u64)(i0), i1);
  i0 = 0u;
  p1 = i0;
  goto B0;
  B1:;
  i0 = p0;
  i1 = p1;
  i32_store16((&memory), (u64)(i0 + 2), i1);
  i0 = 1u;
  p1 = i0;
  B0:;
  i0 = p0;
  i1 = p1;
  i32_store16((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN4wasi13lib_generated8fd_write17hacbf9079620e9958E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = p1;
  i1 = p2;
  i2 = p3;
  i3 = l4;
  i4 = 12u;
  i3 += i4;
  i0 = (*Z_wasi_snapshot_preview1Z_fd_writeZ_iiiii)(i0, i1, i2, i3);
  p1 = i0;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 12));
  i32_store((&memory), (u64)(i0), i1);
  i0 = 0u;
  p1 = i0;
  goto B0;
  B1:;
  i0 = p0;
  i1 = p1;
  i32_store16((&memory), (u64)(i0 + 2), i1);
  i0 = 1u;
  p1 = i0;
  B0:;
  i0 = p0;
  i1 = p1;
  i32_store16((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN4wasi13lib_generated9path_open17h60ff9154cd4f4a34E(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4, u32 p5, u64 p6, u64 p7, 
    u32 p8) {
  u32 l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i7, i8, 
      i9;
  u64 j5, j6;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l9 = i0;
  g0 = i0;
  i0 = p1;
  i1 = p2;
  i2 = p3;
  i3 = p4;
  i4 = p5;
  i5 = 65535u;
  i4 &= i5;
  j5 = p6;
  j6 = p7;
  i7 = p8;
  i8 = 65535u;
  i7 &= i8;
  i8 = l9;
  i9 = 12u;
  i8 += i9;
  i0 = (*Z_wasi_snapshot_preview1Z_path_openZ_iiiiiijjii)(i0, i1, i2, i3, i4, j5, j6, i7, i8);
  p1 = i0;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l9;
  i1 = i32_load((&memory), (u64)(i1 + 12));
  i32_store((&memory), (u64)(i0), i1);
  i0 = 0u;
  p1 = i0;
  goto B0;
  B1:;
  i0 = p0;
  i1 = p1;
  i32_store16((&memory), (u64)(i0 + 2), i1);
  i0 = 1u;
  p1 = i0;
  B0:;
  i0 = p0;
  i1 = p1;
  i32_store16((&memory), (u64)(i0), i1);
  i0 = l9;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void _ZN9backtrace5print12BacktraceFmt3new17h3ab018832264a723E(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p2;
  i32_store8((&memory), (u64)(i0 + 16), i1);
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i1 = p4;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static u32 _ZN9backtrace5print12BacktraceFmt11add_context17hc1ee7fb8cfa6f36aE(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = 0u;
  FUNC_EPILOGUE;
  return i0;
}

static void abort(void) {
  FUNC_PROLOGUE;
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 malloc(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  i0 = dlmalloc(i0);
  FUNC_EPILOGUE;
  return i0;
}

static u32 dlmalloc(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, 
      l9 = 0, l10 = 0, l11 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = p0;
  i1 = 236u;
  i0 = i0 > i1;
  if (i0) {goto B11;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061740));
  l2 = i0;
  i1 = 16u;
  i2 = p0;
  i3 = 19u;
  i2 += i3;
  i3 = 4294967280u;
  i2 &= i3;
  i3 = p0;
  i4 = 11u;
  i3 = i3 < i4;
  i1 = i3 ? i1 : i2;
  l3 = i1;
  i2 = 3u;
  i1 >>= (i2 & 31);
  l4 = i1;
  i0 >>= (i1 & 31);
  p0 = i0;
  i1 = 3u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = p0;
  i1 = 1u;
  i0 &= i1;
  i1 = l4;
  i0 |= i1;
  i1 = 1u;
  i0 ^= i1;
  l3 = i0;
  i1 = 3u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = 1061788u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i1 = 8u;
  i0 += i1;
  p0 = i0;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l6 = i0;
  i1 = l5;
  i2 = 1061780u;
  i1 += i2;
  l5 = i1;
  i0 = i0 != i1;
  if (i0) {goto B14;}
  i0 = 0u;
  i1 = l2;
  i2 = 4294967294u;
  i3 = l3;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  goto B13;
  B14:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  i1 = l6;
  i0 = i0 > i1;
  i0 = l5;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l6;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  B13:;
  i0 = l4;
  i1 = l3;
  i2 = 3u;
  i1 <<= (i2 & 31);
  l6 = i1;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = l6;
  i0 += i1;
  l4 = i0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B0;
  B12:;
  i0 = l3;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061748));
  l7 = i1;
  i0 = i0 <= i1;
  if (i0) {goto B10;}
  i0 = p0;
  i0 = !(i0);
  if (i0) {goto B15;}
  i0 = p0;
  i1 = l4;
  i0 <<= (i1 & 31);
  i1 = 2u;
  i2 = l4;
  i1 <<= (i2 & 31);
  p0 = i1;
  i2 = 0u;
  i3 = p0;
  i2 -= i3;
  i1 |= i2;
  i0 &= i1;
  p0 = i0;
  i1 = 0u;
  i2 = p0;
  i1 -= i2;
  i0 &= i1;
  i1 = 4294967295u;
  i0 += i1;
  p0 = i0;
  i1 = p0;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 16u;
  i1 &= i2;
  p0 = i1;
  i0 >>= (i1 & 31);
  l4 = i0;
  i1 = 5u;
  i0 >>= (i1 & 31);
  i1 = 8u;
  i0 &= i1;
  l6 = i0;
  i1 = p0;
  i0 |= i1;
  i1 = l4;
  i2 = l6;
  i1 >>= (i2 & 31);
  p0 = i1;
  i2 = 2u;
  i1 >>= (i2 & 31);
  i2 = 4u;
  i1 &= i2;
  l4 = i1;
  i0 |= i1;
  i1 = p0;
  i2 = l4;
  i1 >>= (i2 & 31);
  p0 = i1;
  i2 = 1u;
  i1 >>= (i2 & 31);
  i2 = 2u;
  i1 &= i2;
  l4 = i1;
  i0 |= i1;
  i1 = p0;
  i2 = l4;
  i1 >>= (i2 & 31);
  p0 = i1;
  i2 = 1u;
  i1 >>= (i2 & 31);
  i2 = 1u;
  i1 &= i2;
  l4 = i1;
  i0 |= i1;
  i1 = p0;
  i2 = l4;
  i1 >>= (i2 & 31);
  i0 += i1;
  l6 = i0;
  i1 = 3u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = 1061788u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p0 = i0;
  i1 = l5;
  i2 = 1061780u;
  i1 += i2;
  l5 = i1;
  i0 = i0 != i1;
  if (i0) {goto B17;}
  i0 = 0u;
  i1 = l2;
  i2 = 4294967294u;
  i3 = l6;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  l2 = i1;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  goto B16;
  B17:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  i1 = p0;
  i0 = i0 > i1;
  i0 = l5;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  B16:;
  i0 = l4;
  i1 = 8u;
  i0 += i1;
  p0 = i0;
  i0 = l4;
  i1 = l3;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = l6;
  i2 = 3u;
  i1 <<= (i2 & 31);
  l6 = i1;
  i0 += i1;
  i1 = l6;
  i2 = l3;
  i1 -= i2;
  l6 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l3;
  i0 += i1;
  l5 = i0;
  i1 = l6;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B18;}
  i0 = l7;
  i1 = 3u;
  i0 >>= (i1 & 31);
  l8 = i0;
  i1 = 3u;
  i0 <<= (i1 & 31);
  i1 = 1061780u;
  i0 += i1;
  l3 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061760));
  l4 = i0;
  i0 = l2;
  i1 = 1u;
  i2 = l8;
  i1 <<= (i2 & 31);
  l8 = i1;
  i0 &= i1;
  if (i0) {goto B20;}
  i0 = 0u;
  i1 = l2;
  i2 = l8;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  i0 = l3;
  l8 = i0;
  goto B19;
  B20:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l8 = i0;
  B19:;
  i0 = l8;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l3;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l4;
  i1 = l8;
  i32_store((&memory), (u64)(i0 + 8), i1);
  B18:;
  i0 = 0u;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 1061760), i1);
  i0 = 0u;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  goto B0;
  B15:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061744));
  l9 = i0;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = l9;
  i1 = 0u;
  i2 = l9;
  i1 -= i2;
  i0 &= i1;
  i1 = 4294967295u;
  i0 += i1;
  p0 = i0;
  i1 = p0;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 16u;
  i1 &= i2;
  p0 = i1;
  i0 >>= (i1 & 31);
  l4 = i0;
  i1 = 5u;
  i0 >>= (i1 & 31);
  i1 = 8u;
  i0 &= i1;
  l6 = i0;
  i1 = p0;
  i0 |= i1;
  i1 = l4;
  i2 = l6;
  i1 >>= (i2 & 31);
  p0 = i1;
  i2 = 2u;
  i1 >>= (i2 & 31);
  i2 = 4u;
  i1 &= i2;
  l4 = i1;
  i0 |= i1;
  i1 = p0;
  i2 = l4;
  i1 >>= (i2 & 31);
  p0 = i1;
  i2 = 1u;
  i1 >>= (i2 & 31);
  i2 = 2u;
  i1 &= i2;
  l4 = i1;
  i0 |= i1;
  i1 = p0;
  i2 = l4;
  i1 >>= (i2 & 31);
  p0 = i1;
  i2 = 1u;
  i1 >>= (i2 & 31);
  i2 = 1u;
  i1 &= i2;
  l4 = i1;
  i0 |= i1;
  i1 = p0;
  i2 = l4;
  i1 >>= (i2 & 31);
  i0 += i1;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  i1 = 4294967288u;
  i0 &= i1;
  i1 = l3;
  i0 -= i1;
  l4 = i0;
  i0 = l5;
  l6 = i0;
  L22: 
    i0 = l6;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    p0 = i0;
    if (i0) {goto B23;}
    i0 = l6;
    i1 = 20u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    p0 = i0;
    i0 = !(i0);
    if (i0) {goto B21;}
    B23:;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i1 = 4294967288u;
    i0 &= i1;
    i1 = l3;
    i0 -= i1;
    l6 = i0;
    i1 = l4;
    i2 = l6;
    i3 = l4;
    i2 = i2 < i3;
    l6 = i2;
    i0 = i2 ? i0 : i1;
    l4 = i0;
    i0 = p0;
    i1 = l5;
    i2 = l6;
    i0 = i2 ? i0 : i1;
    l5 = i0;
    i0 = p0;
    l6 = i0;
    goto L22;
  B21:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l10 = i0;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l8 = i0;
  i1 = l5;
  i0 = i0 == i1;
  if (i0) {goto B24;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  p0 = i1;
  i0 = i0 > i1;
  if (i0) {goto B25;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i1 = l5;
  i0 = i0 != i1;
  B25:;
  i0 = l8;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l8;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B1;
  B24:;
  i0 = l5;
  i1 = 20u;
  i0 += i1;
  l6 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  if (i0) {goto B26;}
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = l5;
  i1 = 16u;
  i0 += i1;
  l6 = i0;
  B26:;
  L27: 
    i0 = l6;
    l11 = i0;
    i0 = p0;
    l8 = i0;
    i1 = 20u;
    i0 += i1;
    l6 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    p0 = i0;
    if (i0) {goto L27;}
    i0 = l8;
    i1 = 16u;
    i0 += i1;
    l6 = i0;
    i0 = l8;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    p0 = i0;
    if (i0) {goto L27;}
  i0 = l11;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  goto B1;
  B11:;
  i0 = 4294967295u;
  l3 = i0;
  i0 = p0;
  i1 = 4294967231u;
  i0 = i0 > i1;
  if (i0) {goto B10;}
  i0 = p0;
  i1 = 19u;
  i0 += i1;
  p0 = i0;
  i1 = 4294967280u;
  i0 &= i1;
  l3 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061744));
  l7 = i0;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = 0u;
  l11 = i0;
  i0 = p0;
  i1 = 8u;
  i0 >>= (i1 & 31);
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B28;}
  i0 = 31u;
  l11 = i0;
  i0 = l3;
  i1 = 16777215u;
  i0 = i0 > i1;
  if (i0) {goto B28;}
  i0 = p0;
  i1 = p0;
  i2 = 1048320u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 8u;
  i1 &= i2;
  l4 = i1;
  i0 <<= (i1 & 31);
  p0 = i0;
  i1 = p0;
  i2 = 520192u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 4u;
  i1 &= i2;
  p0 = i1;
  i0 <<= (i1 & 31);
  l6 = i0;
  i1 = l6;
  i2 = 245760u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 2u;
  i1 &= i2;
  l6 = i1;
  i0 <<= (i1 & 31);
  i1 = 15u;
  i0 >>= (i1 & 31);
  i1 = p0;
  i2 = l4;
  i1 |= i2;
  i2 = l6;
  i1 |= i2;
  i0 -= i1;
  p0 = i0;
  i1 = 1u;
  i0 <<= (i1 & 31);
  i1 = l3;
  i2 = p0;
  i3 = 21u;
  i2 += i3;
  i1 >>= (i2 & 31);
  i2 = 1u;
  i1 &= i2;
  i0 |= i1;
  i1 = 28u;
  i0 += i1;
  l11 = i0;
  B28:;
  i0 = 0u;
  i1 = l3;
  i0 -= i1;
  l6 = i0;
  i0 = l11;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  if (i0) {goto B32;}
  i0 = 0u;
  p0 = i0;
  i0 = 0u;
  l8 = i0;
  goto B31;
  B32:;
  i0 = l3;
  i1 = 0u;
  i2 = 25u;
  i3 = l11;
  i4 = 1u;
  i3 >>= (i4 & 31);
  i2 -= i3;
  i3 = l11;
  i4 = 31u;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 <<= (i1 & 31);
  l5 = i0;
  i0 = 0u;
  p0 = i0;
  i0 = 0u;
  l8 = i0;
  L33: 
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i1 = 4294967288u;
    i0 &= i1;
    i1 = l3;
    i0 -= i1;
    l2 = i0;
    i1 = l6;
    i0 = i0 >= i1;
    if (i0) {goto B34;}
    i0 = l2;
    l6 = i0;
    i0 = l4;
    l8 = i0;
    i0 = l2;
    if (i0) {goto B34;}
    i0 = 0u;
    l6 = i0;
    i0 = l4;
    l8 = i0;
    i0 = l4;
    p0 = i0;
    goto B30;
    B34:;
    i0 = p0;
    i1 = l4;
    i2 = 20u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l2 = i1;
    i2 = l2;
    i3 = l4;
    i4 = l5;
    i5 = 29u;
    i4 >>= (i5 & 31);
    i5 = 4u;
    i4 &= i5;
    i3 += i4;
    i4 = 16u;
    i3 += i4;
    i3 = i32_load((&memory), (u64)(i3));
    l4 = i3;
    i2 = i2 == i3;
    i0 = i2 ? i0 : i1;
    i1 = p0;
    i2 = l2;
    i0 = i2 ? i0 : i1;
    p0 = i0;
    i0 = l5;
    i1 = l4;
    i2 = 0u;
    i1 = i1 != i2;
    i0 <<= (i1 & 31);
    l5 = i0;
    i0 = l4;
    if (i0) {goto L33;}
  B31:;
  i0 = p0;
  i1 = l8;
  i0 |= i1;
  if (i0) {goto B35;}
  i0 = 2u;
  i1 = l11;
  i0 <<= (i1 & 31);
  p0 = i0;
  i1 = 0u;
  i2 = p0;
  i1 -= i2;
  i0 |= i1;
  i1 = l7;
  i0 &= i1;
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = p0;
  i1 = 0u;
  i2 = p0;
  i1 -= i2;
  i0 &= i1;
  i1 = 4294967295u;
  i0 += i1;
  p0 = i0;
  i1 = p0;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 16u;
  i1 &= i2;
  p0 = i1;
  i0 >>= (i1 & 31);
  l4 = i0;
  i1 = 5u;
  i0 >>= (i1 & 31);
  i1 = 8u;
  i0 &= i1;
  l5 = i0;
  i1 = p0;
  i0 |= i1;
  i1 = l4;
  i2 = l5;
  i1 >>= (i2 & 31);
  p0 = i1;
  i2 = 2u;
  i1 >>= (i2 & 31);
  i2 = 4u;
  i1 &= i2;
  l4 = i1;
  i0 |= i1;
  i1 = p0;
  i2 = l4;
  i1 >>= (i2 & 31);
  p0 = i1;
  i2 = 1u;
  i1 >>= (i2 & 31);
  i2 = 2u;
  i1 &= i2;
  l4 = i1;
  i0 |= i1;
  i1 = p0;
  i2 = l4;
  i1 >>= (i2 & 31);
  p0 = i1;
  i2 = 1u;
  i1 >>= (i2 & 31);
  i2 = 1u;
  i1 &= i2;
  l4 = i1;
  i0 |= i1;
  i1 = p0;
  i2 = l4;
  i1 >>= (i2 & 31);
  i0 += i1;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  B35:;
  i0 = p0;
  i0 = !(i0);
  if (i0) {goto B29;}
  B30:;
  L36: 
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i1 = 4294967288u;
    i0 &= i1;
    i1 = l3;
    i0 -= i1;
    l2 = i0;
    i1 = l6;
    i0 = i0 < i1;
    l5 = i0;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    l4 = i0;
    if (i0) {goto B37;}
    i0 = p0;
    i1 = 20u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    l4 = i0;
    B37:;
    i0 = l2;
    i1 = l6;
    i2 = l5;
    i0 = i2 ? i0 : i1;
    l6 = i0;
    i0 = p0;
    i1 = l8;
    i2 = l5;
    i0 = i2 ? i0 : i1;
    l8 = i0;
    i0 = l4;
    p0 = i0;
    i0 = l4;
    if (i0) {goto L36;}
  B29:;
  i0 = l8;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = l6;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061748));
  i2 = l3;
  i1 -= i2;
  i0 = i0 >= i1;
  if (i0) {goto B10;}
  i0 = l8;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l11 = i0;
  i0 = l8;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l5 = i0;
  i1 = l8;
  i0 = i0 == i1;
  if (i0) {goto B38;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  i1 = l8;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  p0 = i1;
  i0 = i0 > i1;
  if (i0) {goto B39;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i1 = l8;
  i0 = i0 != i1;
  B39:;
  i0 = l5;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B2;
  B38:;
  i0 = l8;
  i1 = 20u;
  i0 += i1;
  l4 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  if (i0) {goto B40;}
  i0 = l8;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = l8;
  i1 = 16u;
  i0 += i1;
  l4 = i0;
  B40:;
  L41: 
    i0 = l4;
    l2 = i0;
    i0 = p0;
    l5 = i0;
    i1 = 20u;
    i0 += i1;
    l4 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    p0 = i0;
    if (i0) {goto L41;}
    i0 = l5;
    i1 = 16u;
    i0 += i1;
    l4 = i0;
    i0 = l5;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    p0 = i0;
    if (i0) {goto L41;}
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  goto B2;
  B10:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061748));
  p0 = i0;
  i1 = l3;
  i0 = i0 < i1;
  if (i0) {goto B42;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061760));
  l4 = i0;
  i0 = p0;
  i1 = l3;
  i0 -= i1;
  l6 = i0;
  i1 = 16u;
  i0 = i0 < i1;
  if (i0) {goto B44;}
  i0 = l4;
  i1 = l3;
  i0 += i1;
  l5 = i0;
  i1 = l6;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  i0 = 0u;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 1061760), i1);
  i0 = l4;
  i1 = p0;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l3;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B43;
  B44:;
  i0 = l4;
  i1 = p0;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = p0;
  i0 += i1;
  p0 = i0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061760), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  B43:;
  i0 = l4;
  i1 = 8u;
  i0 += i1;
  p0 = i0;
  goto B0;
  B42:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061752));
  l5 = i0;
  i1 = l3;
  i0 = i0 <= i1;
  if (i0) {goto B45;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061764));
  p0 = i0;
  i1 = l3;
  i0 += i1;
  l4 = i0;
  i1 = l5;
  i2 = l3;
  i1 -= i2;
  l6 = i1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 1061752), i1);
  i0 = 0u;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 1061764), i1);
  i0 = p0;
  i1 = l3;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  p0 = i0;
  goto B0;
  B45:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062212));
  i0 = !(i0);
  if (i0) {goto B47;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062220));
  l4 = i0;
  goto B46;
  B47:;
  i0 = 0u;
  j1 = 18446744073709551615ull;
  i64_store((&memory), (u64)(i0 + 1062224), j1);
  i0 = 0u;
  j1 = 281474976776192ull;
  i64_store((&memory), (u64)(i0 + 1062216), j1);
  i0 = 0u;
  i1 = l1;
  i2 = 12u;
  i1 += i2;
  i2 = 4294967280u;
  i1 &= i2;
  i2 = 1431655768u;
  i1 ^= i2;
  i32_store((&memory), (u64)(i0 + 1062212), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1062232), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1062184), i1);
  i0 = 65536u;
  l4 = i0;
  B46:;
  i0 = 0u;
  p0 = i0;
  i0 = l4;
  i1 = l3;
  i2 = 71u;
  i1 += i2;
  l7 = i1;
  i0 += i1;
  l2 = i0;
  i1 = 0u;
  i2 = l4;
  i1 -= i2;
  l11 = i1;
  i0 &= i1;
  l8 = i0;
  i1 = l3;
  i0 = i0 > i1;
  if (i0) {goto B48;}
  i0 = 0u;
  i1 = 48u;
  i32_store((&memory), (u64)(i0 + 1062236), i1);
  goto B0;
  B48:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062180));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B49;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062172));
  l4 = i0;
  i1 = l8;
  i0 += i1;
  l6 = i0;
  i1 = l4;
  i0 = i0 <= i1;
  if (i0) {goto B50;}
  i0 = l6;
  i1 = p0;
  i0 = i0 <= i1;
  if (i0) {goto B49;}
  B50:;
  i0 = 0u;
  p0 = i0;
  i0 = 0u;
  i1 = 48u;
  i32_store((&memory), (u64)(i0 + 1062236), i1);
  goto B0;
  B49:;
  i0 = 0u;
  i0 = i32_load8_u((&memory), (u64)(i0 + 1062184));
  i1 = 4u;
  i0 &= i1;
  if (i0) {goto B5;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061764));
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B53;}
  i0 = 1062188u;
  p0 = i0;
  L54: 
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    i1 = l4;
    i0 = i0 > i1;
    if (i0) {goto B55;}
    i0 = l6;
    i1 = p0;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i0 += i1;
    i1 = l4;
    i0 = i0 > i1;
    if (i0) {goto B52;}
    B55:;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    p0 = i0;
    if (i0) {goto L54;}
  B53:;
  i0 = 0u;
  i0 = sbrk(i0);
  l5 = i0;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B6;}
  i0 = l8;
  l2 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062216));
  p0 = i0;
  i1 = 4294967295u;
  i0 += i1;
  l4 = i0;
  i1 = l5;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B56;}
  i0 = l8;
  i1 = l5;
  i0 -= i1;
  i1 = l4;
  i2 = l5;
  i1 += i2;
  i2 = 0u;
  i3 = p0;
  i2 -= i3;
  i1 &= i2;
  i0 += i1;
  l2 = i0;
  B56:;
  i0 = l2;
  i1 = l3;
  i0 = i0 <= i1;
  if (i0) {goto B6;}
  i0 = l2;
  i1 = 2147483646u;
  i0 = i0 > i1;
  if (i0) {goto B6;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062180));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B57;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062172));
  l4 = i0;
  i1 = l2;
  i0 += i1;
  l6 = i0;
  i1 = l4;
  i0 = i0 <= i1;
  if (i0) {goto B6;}
  i0 = l6;
  i1 = p0;
  i0 = i0 > i1;
  if (i0) {goto B6;}
  B57:;
  i0 = l2;
  i0 = sbrk(i0);
  p0 = i0;
  i1 = l5;
  i0 = i0 != i1;
  if (i0) {goto B51;}
  goto B4;
  B52:;
  i0 = l2;
  i1 = l5;
  i0 -= i1;
  i1 = l11;
  i0 &= i1;
  l2 = i0;
  i1 = 2147483646u;
  i0 = i0 > i1;
  if (i0) {goto B6;}
  i0 = l2;
  i0 = sbrk(i0);
  l5 = i0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i1 += i2;
  i0 = i0 == i1;
  if (i0) {goto B7;}
  i0 = l5;
  p0 = i0;
  B51:;
  i0 = p0;
  l5 = i0;
  i0 = l3;
  i1 = 72u;
  i0 += i1;
  i1 = l2;
  i0 = i0 <= i1;
  if (i0) {goto B58;}
  i0 = l2;
  i1 = 2147483646u;
  i0 = i0 > i1;
  if (i0) {goto B58;}
  i0 = l5;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B58;}
  i0 = l7;
  i1 = l2;
  i0 -= i1;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1062220));
  p0 = i1;
  i0 += i1;
  i1 = 0u;
  i2 = p0;
  i1 -= i2;
  i0 &= i1;
  p0 = i0;
  i1 = 2147483646u;
  i0 = i0 > i1;
  if (i0) {goto B4;}
  i0 = p0;
  i0 = sbrk(i0);
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B59;}
  i0 = p0;
  i1 = l2;
  i0 += i1;
  l2 = i0;
  goto B4;
  B59:;
  i0 = 0u;
  i1 = l2;
  i0 -= i1;
  i0 = sbrk(i0);
  goto B6;
  B58:;
  i0 = l5;
  i1 = 4294967295u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  goto B6;
  B9:;
  i0 = 0u;
  l8 = i0;
  goto B1;
  B8:;
  i0 = 0u;
  l5 = i0;
  goto B2;
  B7:;
  i0 = l5;
  i1 = 4294967295u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  B6:;
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1062184));
  i2 = 4u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1062184), i1);
  B5:;
  i0 = l8;
  i1 = 2147483646u;
  i0 = i0 > i1;
  if (i0) {goto B3;}
  i0 = l8;
  i0 = sbrk(i0);
  l5 = i0;
  i1 = 0u;
  i1 = sbrk(i1);
  p0 = i1;
  i0 = i0 >= i1;
  if (i0) {goto B3;}
  i0 = l5;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B3;}
  i0 = p0;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B3;}
  i0 = p0;
  i1 = l5;
  i0 -= i1;
  l2 = i0;
  i1 = l3;
  i2 = 56u;
  i1 += i2;
  i0 = i0 <= i1;
  if (i0) {goto B3;}
  B4:;
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1062172));
  i2 = l2;
  i1 += i2;
  p0 = i1;
  i32_store((&memory), (u64)(i0 + 1062172), i1);
  i0 = p0;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1062176));
  i0 = i0 <= i1;
  if (i0) {goto B60;}
  i0 = 0u;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 1062176), i1);
  B60:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061764));
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B64;}
  i0 = 1062188u;
  p0 = i0;
  L65: 
    i0 = l5;
    i1 = p0;
    i1 = i32_load((&memory), (u64)(i1));
    l6 = i1;
    i2 = p0;
    i2 = i32_load((&memory), (u64)(i2 + 4));
    l8 = i2;
    i1 += i2;
    i0 = i0 == i1;
    if (i0) {goto B63;}
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    p0 = i0;
    if (i0) {goto L65;}
    goto B62;
  B64:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B67;}
  i0 = l5;
  i1 = p0;
  i0 = i0 >= i1;
  if (i0) {goto B66;}
  B67:;
  i0 = 0u;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 1061756), i1);
  B66:;
  i0 = 0u;
  p0 = i0;
  i0 = 0u;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 1062192), i1);
  i0 = 0u;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 1062188), i1);
  i0 = 0u;
  i1 = 4294967295u;
  i32_store((&memory), (u64)(i0 + 1061772), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1062212));
  i32_store((&memory), (u64)(i0 + 1061776), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1062200), i1);
  L68: 
    i0 = p0;
    i1 = 1061788u;
    i0 += i1;
    i1 = p0;
    i2 = 1061780u;
    i1 += i2;
    l4 = i1;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 1061792u;
    i0 += i1;
    i1 = l4;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 8u;
    i0 += i1;
    p0 = i0;
    i1 = 256u;
    i0 = i0 != i1;
    if (i0) {goto L68;}
  i0 = l5;
  i1 = 4294967288u;
  i2 = l5;
  i1 -= i2;
  i2 = 15u;
  i1 &= i2;
  i2 = 0u;
  i3 = l5;
  i4 = 8u;
  i3 += i4;
  i4 = 15u;
  i3 &= i4;
  i1 = i3 ? i1 : i2;
  p0 = i1;
  i0 += i1;
  l4 = i0;
  i1 = l2;
  i2 = 4294967240u;
  i1 += i2;
  l6 = i1;
  i2 = p0;
  i1 -= i2;
  p0 = i1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1062228));
  i32_store((&memory), (u64)(i0 + 1061768), i1);
  i0 = 0u;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 1061752), i1);
  i0 = 0u;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 1061764), i1);
  i0 = l5;
  i1 = l6;
  i0 += i1;
  i1 = 56u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B61;
  B63:;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 12));
  i1 = 8u;
  i0 &= i1;
  if (i0) {goto B62;}
  i0 = l5;
  i1 = l4;
  i0 = i0 <= i1;
  if (i0) {goto B62;}
  i0 = l6;
  i1 = l4;
  i0 = i0 > i1;
  if (i0) {goto B62;}
  i0 = l4;
  i1 = 4294967288u;
  i2 = l4;
  i1 -= i2;
  i2 = 15u;
  i1 &= i2;
  i2 = 0u;
  i3 = l4;
  i4 = 8u;
  i3 += i4;
  i4 = 15u;
  i3 &= i4;
  i1 = i3 ? i1 : i2;
  l6 = i1;
  i0 += i1;
  l5 = i0;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061752));
  i2 = l2;
  i1 += i2;
  l11 = i1;
  i2 = l6;
  i1 -= i2;
  l6 = i1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l8;
  i2 = l2;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1062228));
  i32_store((&memory), (u64)(i0 + 1061768), i1);
  i0 = 0u;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 1061752), i1);
  i0 = 0u;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 1061764), i1);
  i0 = l4;
  i1 = l11;
  i0 += i1;
  i1 = 56u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B61;
  B62:;
  i0 = l5;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061756));
  l8 = i1;
  i0 = i0 >= i1;
  if (i0) {goto B69;}
  i0 = 0u;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 1061756), i1);
  i0 = l5;
  l8 = i0;
  B69:;
  i0 = l5;
  i1 = l2;
  i0 += i1;
  l6 = i0;
  i0 = 1062188u;
  p0 = i0;
  L77: 
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l6;
    i0 = i0 == i1;
    if (i0) {goto B76;}
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    p0 = i0;
    if (i0) {goto L77;}
    goto B75;
  B76:;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 12));
  i1 = 8u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B74;}
  B75:;
  i0 = 1062188u;
  p0 = i0;
  L78: 
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    i1 = l4;
    i0 = i0 > i1;
    if (i0) {goto B79;}
    i0 = l6;
    i1 = p0;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i0 += i1;
    l6 = i0;
    i1 = l4;
    i0 = i0 > i1;
    if (i0) {goto B73;}
    B79:;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    p0 = i0;
    goto L78;
  B74:;
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = l2;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l5;
  i1 = 4294967288u;
  i2 = l5;
  i1 -= i2;
  i2 = 15u;
  i1 &= i2;
  i2 = 0u;
  i3 = l5;
  i4 = 8u;
  i3 += i4;
  i4 = 15u;
  i3 &= i4;
  i1 = i3 ? i1 : i2;
  i0 += i1;
  l11 = i0;
  i1 = l3;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l6;
  i1 = 4294967288u;
  i2 = l6;
  i1 -= i2;
  i2 = 15u;
  i1 &= i2;
  i2 = 0u;
  i3 = l6;
  i4 = 8u;
  i3 += i4;
  i4 = 15u;
  i3 &= i4;
  i1 = i3 ? i1 : i2;
  i0 += i1;
  l5 = i0;
  i1 = l11;
  i0 -= i1;
  i1 = l3;
  i0 -= i1;
  p0 = i0;
  i0 = l11;
  i1 = l3;
  i0 += i1;
  l6 = i0;
  i0 = l4;
  i1 = l5;
  i0 = i0 != i1;
  if (i0) {goto B80;}
  i0 = 0u;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 1061764), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061752));
  i2 = p0;
  i1 += i2;
  p0 = i1;
  i32_store((&memory), (u64)(i0 + 1061752), i1);
  i0 = l6;
  i1 = p0;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B71;
  B80:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061760));
  i1 = l5;
  i0 = i0 != i1;
  if (i0) {goto B81;}
  i0 = 0u;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 1061760), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061748));
  i2 = p0;
  i1 += i2;
  p0 = i1;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  i0 = l6;
  i1 = p0;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l6;
  i1 = p0;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  goto B71;
  B81:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l4 = i0;
  i1 = 3u;
  i0 &= i1;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B82;}
  i0 = l4;
  i1 = 4294967288u;
  i0 &= i1;
  l7 = i0;
  i0 = l4;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B84;}
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l3 = i0;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l2 = i0;
  i1 = l4;
  i2 = 3u;
  i1 >>= (i2 & 31);
  l9 = i1;
  i2 = 3u;
  i1 <<= (i2 & 31);
  i2 = 1061780u;
  i1 += i2;
  l4 = i1;
  i0 = i0 == i1;
  if (i0) {goto B85;}
  i0 = l8;
  i1 = l2;
  i0 = i0 > i1;
  B85:;
  i0 = l3;
  i1 = l2;
  i0 = i0 != i1;
  if (i0) {goto B86;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061740));
  i2 = 4294967294u;
  i3 = l9;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  goto B83;
  B86:;
  i0 = l3;
  i1 = l4;
  i0 = i0 == i1;
  if (i0) {goto B87;}
  i0 = l8;
  i1 = l3;
  i0 = i0 > i1;
  B87:;
  i0 = l3;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B83;
  B84:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l9 = i0;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l2 = i0;
  i1 = l5;
  i0 = i0 == i1;
  if (i0) {goto B89;}
  i0 = l8;
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  l4 = i1;
  i0 = i0 > i1;
  if (i0) {goto B90;}
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i1 = l5;
  i0 = i0 != i1;
  B90:;
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B88;
  B89:;
  i0 = l5;
  i1 = 20u;
  i0 += i1;
  l4 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  if (i0) {goto B91;}
  i0 = l5;
  i1 = 16u;
  i0 += i1;
  l4 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  if (i0) {goto B91;}
  i0 = 0u;
  l2 = i0;
  goto B88;
  B91:;
  L92: 
    i0 = l4;
    l8 = i0;
    i0 = l3;
    l2 = i0;
    i1 = 20u;
    i0 += i1;
    l4 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l3 = i0;
    if (i0) {goto L92;}
    i0 = l2;
    i1 = 16u;
    i0 += i1;
    l4 = i0;
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    l3 = i0;
    if (i0) {goto L92;}
  i0 = l8;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  B88:;
  i0 = l9;
  i0 = !(i0);
  if (i0) {goto B83;}
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  l3 = i0;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  l4 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i0 = i0 != i1;
  if (i0) {goto B94;}
  i0 = l4;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  if (i0) {goto B93;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061744));
  i2 = 4294967294u;
  i3 = l3;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  goto B83;
  B94:;
  i0 = l9;
  i1 = 16u;
  i2 = 20u;
  i3 = l9;
  i3 = i32_load((&memory), (u64)(i3 + 16));
  i4 = l5;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 += i1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B83;}
  B93:;
  i0 = l2;
  i1 = l9;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B95;}
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l4;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B95:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B83;}
  i0 = l2;
  i1 = 20u;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B83:;
  i0 = l7;
  i1 = p0;
  i0 += i1;
  p0 = i0;
  i0 = l5;
  i1 = l7;
  i0 += i1;
  l5 = i0;
  B82:;
  i0 = l5;
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 4294967294u;
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l6;
  i1 = p0;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = p0;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B96;}
  i0 = p0;
  i1 = 3u;
  i0 >>= (i1 & 31);
  l4 = i0;
  i1 = 3u;
  i0 <<= (i1 & 31);
  i1 = 1061780u;
  i0 += i1;
  p0 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061740));
  l3 = i0;
  i1 = 1u;
  i2 = l4;
  i1 <<= (i2 & 31);
  l4 = i1;
  i0 &= i1;
  if (i0) {goto B98;}
  i0 = 0u;
  i1 = l3;
  i2 = l4;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  i0 = p0;
  l4 = i0;
  goto B97;
  B98:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l4 = i0;
  B97:;
  i0 = l4;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l6;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l6;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto B71;
  B96:;
  i0 = 0u;
  l4 = i0;
  i0 = p0;
  i1 = 8u;
  i0 >>= (i1 & 31);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B99;}
  i0 = 31u;
  l4 = i0;
  i0 = p0;
  i1 = 16777215u;
  i0 = i0 > i1;
  if (i0) {goto B99;}
  i0 = l3;
  i1 = l3;
  i2 = 1048320u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 8u;
  i1 &= i2;
  l4 = i1;
  i0 <<= (i1 & 31);
  l3 = i0;
  i1 = l3;
  i2 = 520192u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 4u;
  i1 &= i2;
  l3 = i1;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l5;
  i2 = 245760u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 2u;
  i1 &= i2;
  l5 = i1;
  i0 <<= (i1 & 31);
  i1 = 15u;
  i0 >>= (i1 & 31);
  i1 = l3;
  i2 = l4;
  i1 |= i2;
  i2 = l5;
  i1 |= i2;
  i0 -= i1;
  l4 = i0;
  i1 = 1u;
  i0 <<= (i1 & 31);
  i1 = p0;
  i2 = l4;
  i3 = 21u;
  i2 += i3;
  i1 >>= (i2 & 31);
  i2 = 1u;
  i1 &= i2;
  i0 |= i1;
  i1 = 28u;
  i0 += i1;
  l4 = i0;
  B99:;
  i0 = l6;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l6;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = l4;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  l3 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061744));
  l5 = i0;
  i1 = 1u;
  i2 = l4;
  i1 <<= (i2 & 31);
  l8 = i1;
  i0 &= i1;
  if (i0) {goto B100;}
  i0 = l3;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 0u;
  i1 = l5;
  i2 = l8;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  i0 = l6;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l6;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l6;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B71;
  B100:;
  i0 = p0;
  i1 = 0u;
  i2 = 25u;
  i3 = l4;
  i4 = 1u;
  i3 >>= (i4 & 31);
  i2 -= i3;
  i3 = l4;
  i4 = 31u;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 <<= (i1 & 31);
  l4 = i0;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  L101: 
    i0 = l5;
    l3 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i1 = 4294967288u;
    i0 &= i1;
    i1 = p0;
    i0 = i0 == i1;
    if (i0) {goto B72;}
    i0 = l4;
    i1 = 29u;
    i0 >>= (i1 & 31);
    l5 = i0;
    i0 = l4;
    i1 = 1u;
    i0 <<= (i1 & 31);
    l4 = i0;
    i0 = l3;
    i1 = l5;
    i2 = 4u;
    i1 &= i2;
    i0 += i1;
    i1 = 16u;
    i0 += i1;
    l8 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l5 = i0;
    if (i0) {goto L101;}
  i0 = l8;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l6;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l6;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto B71;
  B73:;
  i0 = l5;
  i1 = 4294967288u;
  i2 = l5;
  i1 -= i2;
  i2 = 15u;
  i1 &= i2;
  i2 = 0u;
  i3 = l5;
  i4 = 8u;
  i3 += i4;
  i4 = 15u;
  i3 &= i4;
  i1 = i3 ? i1 : i2;
  p0 = i1;
  i0 += i1;
  l11 = i0;
  i1 = l2;
  i2 = 4294967240u;
  i1 += i2;
  l8 = i1;
  i2 = p0;
  i1 -= i2;
  p0 = i1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l5;
  i1 = l8;
  i0 += i1;
  i1 = 56u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = l6;
  i2 = 55u;
  i3 = l6;
  i2 -= i3;
  i3 = 15u;
  i2 &= i3;
  i3 = 0u;
  i4 = l6;
  i5 = 4294967241u;
  i4 += i5;
  i5 = 15u;
  i4 &= i5;
  i2 = i4 ? i2 : i3;
  i1 += i2;
  i2 = 4294967233u;
  i1 += i2;
  l8 = i1;
  i2 = l8;
  i3 = l4;
  i4 = 16u;
  i3 += i4;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l8 = i0;
  i1 = 35u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1062228));
  i32_store((&memory), (u64)(i0 + 1061768), i1);
  i0 = 0u;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 1061752), i1);
  i0 = 0u;
  i1 = l11;
  i32_store((&memory), (u64)(i0 + 1061764), i1);
  i0 = l8;
  i1 = 16u;
  i0 += i1;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1062196));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l8;
  i1 = 0u;
  j1 = i64_load((&memory), (u64)(i1 + 1062188));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = 0u;
  i1 = l8;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 1062196), i1);
  i0 = 0u;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 1062192), i1);
  i0 = 0u;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 1062188), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1062200), i1);
  i0 = l8;
  i1 = 36u;
  i0 += i1;
  p0 = i0;
  L102: 
    i0 = p0;
    i1 = 7u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4u;
    i0 += i1;
    p0 = i0;
    i1 = l6;
    i0 = i0 < i1;
    if (i0) {goto L102;}
  i0 = l8;
  i1 = l4;
  i0 = i0 == i1;
  if (i0) {goto B61;}
  i0 = l8;
  i1 = l8;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 4294967294u;
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l8;
  i1 = l8;
  i2 = l4;
  i1 -= i2;
  l2 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l2;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B103;}
  i0 = l2;
  i1 = 3u;
  i0 >>= (i1 & 31);
  l6 = i0;
  i1 = 3u;
  i0 <<= (i1 & 31);
  i1 = 1061780u;
  i0 += i1;
  p0 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061740));
  l5 = i0;
  i1 = 1u;
  i2 = l6;
  i1 <<= (i2 & 31);
  l6 = i1;
  i0 &= i1;
  if (i0) {goto B105;}
  i0 = 0u;
  i1 = l5;
  i2 = l6;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  i0 = p0;
  l6 = i0;
  goto B104;
  B105:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l6 = i0;
  B104:;
  i0 = l6;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l4;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto B61;
  B103:;
  i0 = 0u;
  p0 = i0;
  i0 = l2;
  i1 = 8u;
  i0 >>= (i1 & 31);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B106;}
  i0 = 31u;
  p0 = i0;
  i0 = l2;
  i1 = 16777215u;
  i0 = i0 > i1;
  if (i0) {goto B106;}
  i0 = l6;
  i1 = l6;
  i2 = 1048320u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 8u;
  i1 &= i2;
  p0 = i1;
  i0 <<= (i1 & 31);
  l6 = i0;
  i1 = l6;
  i2 = 520192u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 4u;
  i1 &= i2;
  l6 = i1;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l5;
  i2 = 245760u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 2u;
  i1 &= i2;
  l5 = i1;
  i0 <<= (i1 & 31);
  i1 = 15u;
  i0 >>= (i1 & 31);
  i1 = l6;
  i2 = p0;
  i1 |= i2;
  i2 = l5;
  i1 |= i2;
  i0 -= i1;
  p0 = i0;
  i1 = 1u;
  i0 <<= (i1 & 31);
  i1 = l2;
  i2 = p0;
  i3 = 21u;
  i2 += i3;
  i1 >>= (i2 & 31);
  i2 = 1u;
  i1 &= i2;
  i0 |= i1;
  i1 = 28u;
  i0 += i1;
  p0 = i0;
  B106:;
  i0 = l4;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = l4;
  i1 = 28u;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  l6 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061744));
  l5 = i0;
  i1 = 1u;
  i2 = p0;
  i1 <<= (i2 & 31);
  l8 = i1;
  i0 &= i1;
  if (i0) {goto B107;}
  i0 = l6;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 0u;
  i1 = l5;
  i2 = l8;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  i0 = l4;
  i1 = 24u;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B61;
  B107:;
  i0 = l2;
  i1 = 0u;
  i2 = 25u;
  i3 = p0;
  i4 = 1u;
  i3 >>= (i4 & 31);
  i2 -= i3;
  i3 = p0;
  i4 = 31u;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 <<= (i1 & 31);
  p0 = i0;
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  L108: 
    i0 = l5;
    l6 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i1 = 4294967288u;
    i0 &= i1;
    i1 = l2;
    i0 = i0 == i1;
    if (i0) {goto B70;}
    i0 = p0;
    i1 = 29u;
    i0 >>= (i1 & 31);
    l5 = i0;
    i0 = p0;
    i1 = 1u;
    i0 <<= (i1 & 31);
    p0 = i0;
    i0 = l6;
    i1 = l5;
    i2 = 4u;
    i1 &= i2;
    i0 += i1;
    i1 = 16u;
    i0 += i1;
    l8 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l5 = i0;
    if (i0) {goto L108;}
  i0 = l8;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 24u;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l4;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto B61;
  B72:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p0 = i0;
  i0 = l3;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l6;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l6;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l6;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  B71:;
  i0 = l11;
  i1 = 8u;
  i0 += i1;
  p0 = i0;
  goto B0;
  B70:;
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p0 = i0;
  i0 = l6;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l4;
  i1 = 24u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 12), i1);
  B61:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061752));
  p0 = i0;
  i1 = l3;
  i0 = i0 <= i1;
  if (i0) {goto B3;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061764));
  l4 = i0;
  i1 = l3;
  i0 += i1;
  l6 = i0;
  i1 = p0;
  i2 = l3;
  i1 -= i2;
  p0 = i1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 1061752), i1);
  i0 = 0u;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 1061764), i1);
  i0 = l4;
  i1 = l3;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = 8u;
  i0 += i1;
  p0 = i0;
  goto B0;
  B3:;
  i0 = 0u;
  p0 = i0;
  i0 = 0u;
  i1 = 48u;
  i32_store((&memory), (u64)(i0 + 1062236), i1);
  goto B0;
  B2:;
  i0 = l11;
  i0 = !(i0);
  if (i0) {goto B109;}
  i0 = l8;
  i1 = l8;
  i1 = i32_load((&memory), (u64)(i1 + 28));
  l4 = i1;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = 1062044u;
  i1 += i2;
  p0 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  i0 = i0 != i1;
  if (i0) {goto B111;}
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  if (i0) {goto B110;}
  i0 = 0u;
  i1 = l7;
  i2 = 4294967294u;
  i3 = l4;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  l7 = i1;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  goto B109;
  B111:;
  i0 = l11;
  i1 = 16u;
  i2 = 20u;
  i3 = l11;
  i3 = i32_load((&memory), (u64)(i3 + 16));
  i4 = l8;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B109;}
  B110:;
  i0 = l5;
  i1 = l11;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l8;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B112;}
  i0 = l5;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B112:;
  i0 = l8;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B109;}
  i0 = l5;
  i1 = 20u;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B109:;
  i0 = l6;
  i1 = 15u;
  i0 = i0 > i1;
  if (i0) {goto B114;}
  i0 = l8;
  i1 = l6;
  i2 = l3;
  i1 += i2;
  p0 = i1;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l8;
  i1 = p0;
  i0 += i1;
  p0 = i0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B113;
  B114:;
  i0 = l8;
  i1 = l3;
  i0 += i1;
  l5 = i0;
  i1 = l6;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l8;
  i1 = l3;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l5;
  i1 = l6;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B115;}
  i0 = l6;
  i1 = 3u;
  i0 >>= (i1 & 31);
  l4 = i0;
  i1 = 3u;
  i0 <<= (i1 & 31);
  i1 = 1061780u;
  i0 += i1;
  p0 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061740));
  l6 = i0;
  i1 = 1u;
  i2 = l4;
  i1 <<= (i2 & 31);
  l4 = i1;
  i0 &= i1;
  if (i0) {goto B117;}
  i0 = 0u;
  i1 = l6;
  i2 = l4;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  i0 = p0;
  l4 = i0;
  goto B116;
  B117:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l4 = i0;
  B116:;
  i0 = l4;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l5;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l5;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto B113;
  B115:;
  i0 = l6;
  i1 = 8u;
  i0 >>= (i1 & 31);
  l4 = i0;
  if (i0) {goto B119;}
  i0 = 0u;
  p0 = i0;
  goto B118;
  B119:;
  i0 = 31u;
  p0 = i0;
  i0 = l6;
  i1 = 16777215u;
  i0 = i0 > i1;
  if (i0) {goto B118;}
  i0 = l4;
  i1 = l4;
  i2 = 1048320u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 8u;
  i1 &= i2;
  p0 = i1;
  i0 <<= (i1 & 31);
  l4 = i0;
  i1 = l4;
  i2 = 520192u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 4u;
  i1 &= i2;
  l4 = i1;
  i0 <<= (i1 & 31);
  l3 = i0;
  i1 = l3;
  i2 = 245760u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 2u;
  i1 &= i2;
  l3 = i1;
  i0 <<= (i1 & 31);
  i1 = 15u;
  i0 >>= (i1 & 31);
  i1 = l4;
  i2 = p0;
  i1 |= i2;
  i2 = l3;
  i1 |= i2;
  i0 -= i1;
  p0 = i0;
  i1 = 1u;
  i0 <<= (i1 & 31);
  i1 = l6;
  i2 = p0;
  i3 = 21u;
  i2 += i3;
  i1 >>= (i2 & 31);
  i2 = 1u;
  i1 &= i2;
  i0 |= i1;
  i1 = 28u;
  i0 += i1;
  p0 = i0;
  B118:;
  i0 = l5;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l5;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = p0;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  l4 = i0;
  i0 = l7;
  i1 = 1u;
  i2 = p0;
  i1 <<= (i2 & 31);
  l3 = i1;
  i0 &= i1;
  if (i0) {goto B120;}
  i0 = l4;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 0u;
  i1 = l7;
  i2 = l3;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  i0 = l5;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l5;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l5;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B113;
  B120:;
  i0 = l6;
  i1 = 0u;
  i2 = 25u;
  i3 = p0;
  i4 = 1u;
  i3 >>= (i4 & 31);
  i2 -= i3;
  i3 = p0;
  i4 = 31u;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 <<= (i1 & 31);
  p0 = i0;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  L122: 
    i0 = l3;
    l4 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i1 = 4294967288u;
    i0 &= i1;
    i1 = l6;
    i0 = i0 == i1;
    if (i0) {goto B121;}
    i0 = p0;
    i1 = 29u;
    i0 >>= (i1 & 31);
    l3 = i0;
    i0 = p0;
    i1 = 1u;
    i0 <<= (i1 & 31);
    p0 = i0;
    i0 = l4;
    i1 = l3;
    i2 = 4u;
    i1 &= i2;
    i0 += i1;
    i1 = 16u;
    i0 += i1;
    l2 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l3 = i0;
    if (i0) {goto L122;}
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l5;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l5;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto B113;
  B121:;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p0 = i0;
  i0 = l4;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l5;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l5;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l5;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 12), i1);
  B113:;
  i0 = l8;
  i1 = 8u;
  i0 += i1;
  p0 = i0;
  goto B0;
  B1:;
  i0 = l10;
  i0 = !(i0);
  if (i0) {goto B123;}
  i0 = l5;
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1 + 28));
  l6 = i1;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = 1062044u;
  i1 += i2;
  p0 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  i0 = i0 != i1;
  if (i0) {goto B125;}
  i0 = p0;
  i1 = l8;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l8;
  if (i0) {goto B124;}
  i0 = 0u;
  i1 = l9;
  i2 = 4294967294u;
  i3 = l6;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  goto B123;
  B125:;
  i0 = l10;
  i1 = 16u;
  i2 = 20u;
  i3 = l10;
  i3 = i32_load((&memory), (u64)(i3 + 16));
  i4 = l5;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 += i1;
  i1 = l8;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l8;
  i0 = !(i0);
  if (i0) {goto B123;}
  B124:;
  i0 = l8;
  i1 = l10;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B126;}
  i0 = l8;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = p0;
  i1 = l8;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B126:;
  i0 = l5;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B123;}
  i0 = l8;
  i1 = 20u;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l8;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B123:;
  i0 = l4;
  i1 = 15u;
  i0 = i0 > i1;
  if (i0) {goto B128;}
  i0 = l5;
  i1 = l4;
  i2 = l3;
  i1 += i2;
  p0 = i1;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l5;
  i1 = p0;
  i0 += i1;
  p0 = i0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B127;
  B128:;
  i0 = l5;
  i1 = l3;
  i0 += i1;
  l6 = i0;
  i1 = l4;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l5;
  i1 = l3;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l6;
  i1 = l4;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B129;}
  i0 = l7;
  i1 = 3u;
  i0 >>= (i1 & 31);
  l8 = i0;
  i1 = 3u;
  i0 <<= (i1 & 31);
  i1 = 1061780u;
  i0 += i1;
  l3 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061760));
  p0 = i0;
  i0 = 1u;
  i1 = l8;
  i0 <<= (i1 & 31);
  l8 = i0;
  i1 = l2;
  i0 &= i1;
  if (i0) {goto B131;}
  i0 = 0u;
  i1 = l8;
  i2 = l2;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  i0 = l3;
  l8 = i0;
  goto B130;
  B131:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l8 = i0;
  B130:;
  i0 = l8;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i1 = l8;
  i32_store((&memory), (u64)(i0 + 8), i1);
  B129:;
  i0 = 0u;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 1061760), i1);
  i0 = 0u;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  B127:;
  i0 = l5;
  i1 = 8u;
  i0 += i1;
  p0 = i0;
  B0:;
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static void free(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  dlfree(i0);
  FUNC_EPILOGUE;
}

static void dlfree(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = p0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 4294967288u;
  i0 += i1;
  l1 = i0;
  i1 = p0;
  i2 = 4294967292u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i2 = 4294967288u;
  i1 &= i2;
  p0 = i1;
  i0 += i1;
  l3 = i0;
  i0 = l2;
  i1 = 1u;
  i0 &= i1;
  if (i0) {goto B1;}
  i0 = l2;
  i1 = 3u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i0 -= i1;
  l1 = i0;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061756));
  l4 = i1;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = l2;
  i1 = p0;
  i0 += i1;
  p0 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061760));
  i1 = l1;
  i0 = i0 == i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B3;}
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l5 = i0;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l6 = i0;
  i1 = l2;
  i2 = 3u;
  i1 >>= (i2 & 31);
  l7 = i1;
  i2 = 3u;
  i1 <<= (i2 & 31);
  i2 = 1061780u;
  i1 += i2;
  l2 = i1;
  i0 = i0 == i1;
  if (i0) {goto B4;}
  i0 = l4;
  i1 = l6;
  i0 = i0 > i1;
  B4:;
  i0 = l5;
  i1 = l6;
  i0 = i0 != i1;
  if (i0) {goto B5;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061740));
  i2 = 4294967294u;
  i3 = l7;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  goto B1;
  B5:;
  i0 = l5;
  i1 = l2;
  i0 = i0 == i1;
  if (i0) {goto B6;}
  i0 = l4;
  i1 = l5;
  i0 = i0 > i1;
  B6:;
  i0 = l5;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l6;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B1;
  B3:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l7 = i0;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l5 = i0;
  i1 = l1;
  i0 = i0 == i1;
  if (i0) {goto B8;}
  i0 = l4;
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  l2 = i1;
  i0 = i0 > i1;
  if (i0) {goto B9;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i1 = l1;
  i0 = i0 != i1;
  B9:;
  i0 = l5;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B7;
  B8:;
  i0 = l1;
  i1 = 20u;
  i0 += i1;
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  if (i0) {goto B10;}
  i0 = l1;
  i1 = 16u;
  i0 += i1;
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  if (i0) {goto B10;}
  i0 = 0u;
  l5 = i0;
  goto B7;
  B10:;
  L11: 
    i0 = l2;
    l6 = i0;
    i0 = l4;
    l5 = i0;
    i1 = 20u;
    i0 += i1;
    l2 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l4 = i0;
    if (i0) {goto L11;}
    i0 = l5;
    i1 = 16u;
    i0 += i1;
    l2 = i0;
    i0 = l5;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    l4 = i0;
    if (i0) {goto L11;}
  i0 = l6;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  B7:;
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  l4 = i0;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l1;
  i0 = i0 != i1;
  if (i0) {goto B13;}
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  if (i0) {goto B12;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061744));
  i2 = 4294967294u;
  i3 = l4;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  goto B1;
  B13:;
  i0 = l7;
  i1 = 16u;
  i2 = 20u;
  i3 = l7;
  i3 = i32_load((&memory), (u64)(i3 + 16));
  i4 = l1;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B1;}
  B12:;
  i0 = l5;
  i1 = l7;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B14;}
  i0 = l5;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B14:;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l5;
  i1 = 20u;
  i0 += i1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 24), i1);
  goto B1;
  B2:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i1 = 3u;
  i0 &= i1;
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = l3;
  i1 = l2;
  i2 = 4294967294u;
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  i0 = l1;
  i1 = p0;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = p0;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto Bfunc;
  B1:;
  i0 = l3;
  i1 = l1;
  i0 = i0 <= i1;
  if (i0) {goto B0;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i1 = 1u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l2;
  i1 = 2u;
  i0 &= i1;
  if (i0) {goto B16;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061764));
  i1 = l3;
  i0 = i0 != i1;
  if (i0) {goto B17;}
  i0 = 0u;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 1061764), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061752));
  i2 = p0;
  i1 += i2;
  p0 = i1;
  i32_store((&memory), (u64)(i0 + 1061752), i1);
  i0 = l1;
  i1 = p0;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l1;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061760));
  i0 = i0 != i1;
  if (i0) {goto B0;}
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061760), i1);
  goto Bfunc;
  B17:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061760));
  i1 = l3;
  i0 = i0 != i1;
  if (i0) {goto B18;}
  i0 = 0u;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 1061760), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061748));
  i2 = p0;
  i1 += i2;
  p0 = i1;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  i0 = l1;
  i1 = p0;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l1;
  i1 = p0;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B18:;
  i0 = l2;
  i1 = 4294967288u;
  i0 &= i1;
  i1 = p0;
  i0 += i1;
  p0 = i0;
  i0 = l2;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B20;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l4 = i0;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l5 = i0;
  i1 = l2;
  i2 = 3u;
  i1 >>= (i2 & 31);
  l3 = i1;
  i2 = 3u;
  i1 <<= (i2 & 31);
  i2 = 1061780u;
  i1 += i2;
  l2 = i1;
  i0 = i0 == i1;
  if (i0) {goto B21;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  i1 = l5;
  i0 = i0 > i1;
  B21:;
  i0 = l4;
  i1 = l5;
  i0 = i0 != i1;
  if (i0) {goto B22;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061740));
  i2 = 4294967294u;
  i3 = l3;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  goto B19;
  B22:;
  i0 = l4;
  i1 = l2;
  i0 = i0 == i1;
  if (i0) {goto B23;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  i1 = l4;
  i0 = i0 > i1;
  B23:;
  i0 = l4;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l5;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B19;
  B20:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l7 = i0;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l5 = i0;
  i1 = l3;
  i0 = i0 == i1;
  if (i0) {goto B25;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  l2 = i1;
  i0 = i0 > i1;
  if (i0) {goto B26;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i1 = l3;
  i0 = i0 != i1;
  B26:;
  i0 = l5;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B24;
  B25:;
  i0 = l3;
  i1 = 20u;
  i0 += i1;
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  if (i0) {goto B27;}
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  if (i0) {goto B27;}
  i0 = 0u;
  l5 = i0;
  goto B24;
  B27:;
  L28: 
    i0 = l2;
    l6 = i0;
    i0 = l4;
    l5 = i0;
    i1 = 20u;
    i0 += i1;
    l2 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l4 = i0;
    if (i0) {goto L28;}
    i0 = l5;
    i1 = 16u;
    i0 += i1;
    l2 = i0;
    i0 = l5;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    l4 = i0;
    if (i0) {goto L28;}
  i0 = l6;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  B24:;
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B19;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  l4 = i0;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  l2 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l3;
  i0 = i0 != i1;
  if (i0) {goto B30;}
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  if (i0) {goto B29;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061744));
  i2 = 4294967294u;
  i3 = l4;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  goto B19;
  B30:;
  i0 = l7;
  i1 = 16u;
  i2 = 20u;
  i3 = l7;
  i3 = i32_load((&memory), (u64)(i3 + 16));
  i4 = l3;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B19;}
  B29:;
  i0 = l5;
  i1 = l7;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B31;}
  i0 = l5;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B31:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B19;}
  i0 = l5;
  i1 = 20u;
  i0 += i1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B19:;
  i0 = l1;
  i1 = p0;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = p0;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l1;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061760));
  i0 = i0 != i1;
  if (i0) {goto B15;}
  i0 = 0u;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  goto Bfunc;
  B16:;
  i0 = l3;
  i1 = l2;
  i2 = 4294967294u;
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l1;
  i1 = p0;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = p0;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  B15:;
  i0 = p0;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B32;}
  i0 = p0;
  i1 = 3u;
  i0 >>= (i1 & 31);
  l2 = i0;
  i1 = 3u;
  i0 <<= (i1 & 31);
  i1 = 1061780u;
  i0 += i1;
  p0 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061740));
  l4 = i0;
  i1 = 1u;
  i2 = l2;
  i1 <<= (i2 & 31);
  l2 = i1;
  i0 &= i1;
  if (i0) {goto B34;}
  i0 = 0u;
  i1 = l4;
  i2 = l2;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  i0 = p0;
  l2 = i0;
  goto B33;
  B34:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l2 = i0;
  B33:;
  i0 = l2;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l1;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l1;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto Bfunc;
  B32:;
  i0 = 0u;
  l2 = i0;
  i0 = p0;
  i1 = 8u;
  i0 >>= (i1 & 31);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B35;}
  i0 = 31u;
  l2 = i0;
  i0 = p0;
  i1 = 16777215u;
  i0 = i0 > i1;
  if (i0) {goto B35;}
  i0 = l4;
  i1 = l4;
  i2 = 1048320u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 8u;
  i1 &= i2;
  l2 = i1;
  i0 <<= (i1 & 31);
  l4 = i0;
  i1 = l4;
  i2 = 520192u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 4u;
  i1 &= i2;
  l4 = i1;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l5;
  i2 = 245760u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 2u;
  i1 &= i2;
  l5 = i1;
  i0 <<= (i1 & 31);
  i1 = 15u;
  i0 >>= (i1 & 31);
  i1 = l4;
  i2 = l2;
  i1 |= i2;
  i2 = l5;
  i1 |= i2;
  i0 -= i1;
  l2 = i0;
  i1 = 1u;
  i0 <<= (i1 & 31);
  i1 = p0;
  i2 = l2;
  i3 = 21u;
  i2 += i3;
  i1 >>= (i2 & 31);
  i2 = 1u;
  i1 &= i2;
  i0 |= i1;
  i1 = 28u;
  i0 += i1;
  l2 = i0;
  B35:;
  i0 = l1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = l1;
  i1 = 28u;
  i0 += i1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  l4 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061744));
  l5 = i0;
  i1 = 1u;
  i2 = l2;
  i1 <<= (i2 & 31);
  l3 = i1;
  i0 &= i1;
  if (i0) {goto B37;}
  i0 = l4;
  i1 = l1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 0u;
  i1 = l5;
  i2 = l3;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  i0 = l1;
  i1 = 24u;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l1;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B36;
  B37:;
  i0 = p0;
  i1 = 0u;
  i2 = 25u;
  i3 = l2;
  i4 = 1u;
  i3 >>= (i4 & 31);
  i2 -= i3;
  i3 = l2;
  i4 = 31u;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 <<= (i1 & 31);
  l2 = i0;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  L39: 
    i0 = l5;
    l4 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i1 = 4294967288u;
    i0 &= i1;
    i1 = p0;
    i0 = i0 == i1;
    if (i0) {goto B38;}
    i0 = l2;
    i1 = 29u;
    i0 >>= (i1 & 31);
    l5 = i0;
    i0 = l2;
    i1 = 1u;
    i0 <<= (i1 & 31);
    l2 = i0;
    i0 = l4;
    i1 = l5;
    i2 = 4u;
    i1 &= i2;
    i0 += i1;
    i1 = 16u;
    i0 += i1;
    l3 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l5 = i0;
    if (i0) {goto L39;}
  i0 = l3;
  i1 = l1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l1;
  i1 = 24u;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto B36;
  B38:;
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p0 = i0;
  i0 = l4;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l1;
  i1 = 24u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l1;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 12), i1);
  B36:;
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061772));
  i2 = 4294967295u;
  i1 += i2;
  l1 = i1;
  i32_store((&memory), (u64)(i0 + 1061772), i1);
  i0 = l1;
  if (i0) {goto B0;}
  i0 = 1062196u;
  l1 = i0;
  L40: 
    i0 = l1;
    i0 = i32_load((&memory), (u64)(i0));
    p0 = i0;
    i1 = 8u;
    i0 += i1;
    l1 = i0;
    i0 = p0;
    if (i0) {goto L40;}
  i0 = 0u;
  i1 = 4294967295u;
  i32_store((&memory), (u64)(i0 + 1061772), i1);
  B0:;
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 calloc(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  if (i0) {goto B1;}
  i0 = 0u;
  l2 = i0;
  goto B0;
  B1:;
  i0 = p1;
  i1 = p0;
  i0 *= i1;
  l2 = i0;
  i0 = p1;
  i1 = p0;
  i0 |= i1;
  i1 = 65536u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = l2;
  i1 = 4294967295u;
  i2 = l2;
  i3 = p0;
  i2 = DIV_U(i2, i3);
  i3 = p1;
  i2 = i2 == i3;
  i0 = i2 ? i0 : i1;
  l2 = i0;
  B0:;
  i0 = l2;
  i0 = dlmalloc(i0);
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p0;
  i1 = 4294967292u;
  i0 += i1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 3u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p0;
  i1 = 0u;
  i2 = l2;
  i0 = memset_0(i0, i1, i2);
  B2:;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 realloc(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, 
      l10 = 0, l11 = 0, l12 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  i0 = p0;
  if (i0) {goto B0;}
  i0 = p1;
  i0 = dlmalloc(i0);
  goto Bfunc;
  B0:;
  i0 = p1;
  i1 = 4294967232u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = 0u;
  i1 = 48u;
  i32_store((&memory), (u64)(i0 + 1062236), i1);
  i0 = 0u;
  goto Bfunc;
  B1:;
  i0 = p1;
  i1 = 11u;
  i0 = i0 < i1;
  l2 = i0;
  i0 = p1;
  i1 = 19u;
  i0 += i1;
  i1 = 4294967280u;
  i0 &= i1;
  l3 = i0;
  i0 = p0;
  i1 = 4294967288u;
  i0 += i1;
  l4 = i0;
  i0 = p0;
  i1 = 4294967292u;
  i0 += i1;
  l5 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i1 = 3u;
  i0 &= i1;
  l7 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  l8 = i0;
  i0 = l6;
  i1 = 4294967288u;
  i0 &= i1;
  l9 = i0;
  i1 = 1u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l7;
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B2;}
  i0 = l8;
  i1 = l4;
  i0 = i0 > i1;
  B2:;
  i0 = 16u;
  i1 = l3;
  i2 = l2;
  i0 = i2 ? i0 : i1;
  l2 = i0;
  i0 = l7;
  if (i0) {goto B5;}
  i0 = l2;
  i1 = 256u;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l9;
  i1 = l2;
  i2 = 4u;
  i1 |= i2;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l9;
  i1 = l2;
  i0 -= i1;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1062220));
  i2 = 1u;
  i1 <<= (i2 & 31);
  i0 = i0 <= i1;
  if (i0) {goto B3;}
  goto B4;
  B5:;
  i0 = l4;
  i1 = l9;
  i0 += i1;
  l7 = i0;
  i0 = l9;
  i1 = l2;
  i0 = i0 < i1;
  if (i0) {goto B6;}
  i0 = l9;
  i1 = l2;
  i0 -= i1;
  p1 = i0;
  i1 = 16u;
  i0 = i0 < i1;
  if (i0) {goto B3;}
  i0 = l5;
  i1 = l2;
  i2 = l6;
  i3 = 1u;
  i2 &= i3;
  i1 |= i2;
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l2;
  i0 += i1;
  l2 = i0;
  i1 = p1;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l7;
  i1 = l7;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p1;
  dispose_chunk(i0, i1);
  i0 = p0;
  goto Bfunc;
  B6:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061764));
  i1 = l7;
  i0 = i0 != i1;
  if (i0) {goto B7;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061752));
  i1 = l9;
  i0 += i1;
  l9 = i0;
  i1 = l2;
  i0 = i0 <= i1;
  if (i0) {goto B4;}
  i0 = l5;
  i1 = l2;
  i2 = l6;
  i3 = 1u;
  i2 &= i3;
  i1 |= i2;
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 0u;
  i1 = l4;
  i2 = l2;
  i1 += i2;
  p1 = i1;
  i32_store((&memory), (u64)(i0 + 1061764), i1);
  i0 = 0u;
  i1 = l9;
  i2 = l2;
  i1 -= i2;
  l2 = i1;
  i32_store((&memory), (u64)(i0 + 1061752), i1);
  i0 = p1;
  i1 = l2;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  goto Bfunc;
  B7:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061760));
  i1 = l7;
  i0 = i0 != i1;
  if (i0) {goto B8;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061748));
  i1 = l9;
  i0 += i1;
  l9 = i0;
  i1 = l2;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l9;
  i1 = l2;
  i0 -= i1;
  p1 = i0;
  i1 = 16u;
  i0 = i0 < i1;
  if (i0) {goto B10;}
  i0 = l5;
  i1 = l2;
  i2 = l6;
  i3 = 1u;
  i2 &= i3;
  i1 |= i2;
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l2;
  i0 += i1;
  l2 = i0;
  i1 = p1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = l9;
  i0 += i1;
  l9 = i0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l9;
  i1 = l9;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 4294967294u;
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto B9;
  B10:;
  i0 = l5;
  i1 = l6;
  i2 = 1u;
  i1 &= i2;
  i2 = l9;
  i1 |= i2;
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l9;
  i0 += i1;
  p1 = i0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  p1 = i0;
  i0 = 0u;
  l2 = i0;
  B9:;
  i0 = 0u;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 1061760), i1);
  i0 = 0u;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  i0 = p0;
  goto Bfunc;
  B8:;
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i1 = 2u;
  i0 &= i1;
  if (i0) {goto B4;}
  i0 = l3;
  i1 = 4294967288u;
  i0 &= i1;
  i1 = l9;
  i0 += i1;
  l10 = i0;
  i1 = l2;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l10;
  i1 = l2;
  i0 -= i1;
  l11 = i0;
  i0 = l3;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B12;}
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  p1 = i0;
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l9 = i0;
  i1 = l3;
  i2 = 3u;
  i1 >>= (i2 & 31);
  l3 = i1;
  i2 = 3u;
  i1 <<= (i2 & 31);
  i2 = 1061780u;
  i1 += i2;
  l7 = i1;
  i0 = i0 == i1;
  if (i0) {goto B13;}
  i0 = l8;
  i1 = l9;
  i0 = i0 > i1;
  B13:;
  i0 = p1;
  i1 = l9;
  i0 = i0 != i1;
  if (i0) {goto B14;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061740));
  i2 = 4294967294u;
  i3 = l3;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  goto B11;
  B14:;
  i0 = p1;
  i1 = l7;
  i0 = i0 == i1;
  if (i0) {goto B15;}
  i0 = l8;
  i1 = p1;
  i0 = i0 > i1;
  B15:;
  i0 = p1;
  i1 = l9;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l9;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B11;
  B12:;
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l12 = i0;
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l3 = i0;
  i1 = l7;
  i0 = i0 == i1;
  if (i0) {goto B17;}
  i0 = l8;
  i1 = l7;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  p1 = i1;
  i0 = i0 > i1;
  if (i0) {goto B18;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i1 = l7;
  i0 = i0 != i1;
  B18:;
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p1;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B16;
  B17:;
  i0 = l7;
  i1 = 20u;
  i0 += i1;
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l9 = i0;
  if (i0) {goto B19;}
  i0 = l7;
  i1 = 16u;
  i0 += i1;
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l9 = i0;
  if (i0) {goto B19;}
  i0 = 0u;
  l3 = i0;
  goto B16;
  B19:;
  L20: 
    i0 = p1;
    l8 = i0;
    i0 = l9;
    l3 = i0;
    i1 = 20u;
    i0 += i1;
    p1 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l9 = i0;
    if (i0) {goto L20;}
    i0 = l3;
    i1 = 16u;
    i0 += i1;
    p1 = i0;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    l9 = i0;
    if (i0) {goto L20;}
  i0 = l8;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  B16:;
  i0 = l12;
  i0 = !(i0);
  if (i0) {goto B11;}
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  l9 = i0;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l7;
  i0 = i0 != i1;
  if (i0) {goto B22;}
  i0 = p1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  if (i0) {goto B21;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061744));
  i2 = 4294967294u;
  i3 = l9;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  goto B11;
  B22:;
  i0 = l12;
  i1 = 16u;
  i2 = 20u;
  i3 = l12;
  i3 = i32_load((&memory), (u64)(i3 + 16));
  i4 = l7;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 += i1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B11;}
  B21:;
  i0 = l3;
  i1 = l12;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B23;}
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = p1;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B23:;
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B11;}
  i0 = l3;
  i1 = 20u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B11:;
  i0 = l11;
  i1 = 15u;
  i0 = i0 > i1;
  if (i0) {goto B24;}
  i0 = l5;
  i1 = l6;
  i2 = 1u;
  i1 &= i2;
  i2 = l10;
  i1 |= i2;
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l10;
  i0 += i1;
  p1 = i0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  goto Bfunc;
  B24:;
  i0 = l5;
  i1 = l2;
  i2 = l6;
  i3 = 1u;
  i2 &= i3;
  i1 |= i2;
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l2;
  i0 += i1;
  p1 = i0;
  i1 = l11;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = l10;
  i0 += i1;
  l2 = i0;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p1;
  i1 = l11;
  dispose_chunk(i0, i1);
  i0 = p0;
  goto Bfunc;
  B4:;
  i0 = p1;
  i0 = dlmalloc(i0);
  l2 = i0;
  if (i0) {goto B25;}
  i0 = 0u;
  goto Bfunc;
  B25:;
  i0 = l2;
  i1 = p0;
  i2 = l5;
  i2 = i32_load((&memory), (u64)(i2));
  l9 = i2;
  i3 = 4294967288u;
  i2 &= i3;
  i3 = 4u;
  i4 = 8u;
  i5 = l9;
  i6 = 3u;
  i5 &= i6;
  i3 = i5 ? i3 : i4;
  i2 -= i3;
  l9 = i2;
  i3 = p1;
  i4 = l9;
  i5 = p1;
  i4 = i4 < i5;
  i2 = i4 ? i2 : i3;
  i0 = memcpy_0(i0, i1, i2);
  p1 = i0;
  i0 = p0;
  dlfree(i0);
  i0 = p1;
  p0 = i0;
  B3:;
  i0 = p0;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void dispose_chunk(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = p0;
  i1 = p1;
  i0 += i1;
  l2 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i1 = 1u;
  i0 &= i1;
  if (i0) {goto B1;}
  i0 = l3;
  i1 = 3u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i1 = p1;
  i0 += i1;
  p1 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061760));
  i1 = p0;
  i2 = l3;
  i1 -= i2;
  p0 = i1;
  i0 = i0 == i1;
  if (i0) {goto B2;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  l4 = i0;
  i0 = l3;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B3;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l5 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l6 = i0;
  i1 = l3;
  i2 = 3u;
  i1 >>= (i2 & 31);
  l7 = i1;
  i2 = 3u;
  i1 <<= (i2 & 31);
  i2 = 1061780u;
  i1 += i2;
  l3 = i1;
  i0 = i0 == i1;
  if (i0) {goto B4;}
  i0 = l4;
  i1 = l6;
  i0 = i0 > i1;
  B4:;
  i0 = l5;
  i1 = l6;
  i0 = i0 != i1;
  if (i0) {goto B5;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061740));
  i2 = 4294967294u;
  i3 = l7;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  goto B1;
  B5:;
  i0 = l5;
  i1 = l3;
  i0 = i0 == i1;
  if (i0) {goto B6;}
  i0 = l4;
  i1 = l5;
  i0 = i0 > i1;
  B6:;
  i0 = l5;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l6;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B1;
  B3:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l7 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l6 = i0;
  i1 = p0;
  i0 = i0 == i1;
  if (i0) {goto B8;}
  i0 = l4;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  l3 = i1;
  i0 = i0 > i1;
  if (i0) {goto B9;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i1 = p0;
  i0 = i0 != i1;
  B9:;
  i0 = l6;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B7;
  B8:;
  i0 = p0;
  i1 = 20u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  if (i0) {goto B10;}
  i0 = p0;
  i1 = 16u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  if (i0) {goto B10;}
  i0 = 0u;
  l6 = i0;
  goto B7;
  B10:;
  L11: 
    i0 = l3;
    l4 = i0;
    i0 = l5;
    l6 = i0;
    i1 = 20u;
    i0 += i1;
    l3 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l5 = i0;
    if (i0) {goto L11;}
    i0 = l6;
    i1 = 16u;
    i0 += i1;
    l3 = i0;
    i0 = l6;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    l5 = i0;
    if (i0) {goto L11;}
  i0 = l4;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  B7:;
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  l5 = i0;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i0 = i0 != i1;
  if (i0) {goto B13;}
  i0 = l3;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  if (i0) {goto B12;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061744));
  i2 = 4294967294u;
  i3 = l5;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  goto B1;
  B13:;
  i0 = l7;
  i1 = 16u;
  i2 = 20u;
  i3 = l7;
  i3 = i32_load((&memory), (u64)(i3 + 16));
  i4 = p0;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B1;}
  B12:;
  i0 = l6;
  i1 = l7;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B14;}
  i0 = l6;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l3;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B14:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l6;
  i1 = 20u;
  i0 += i1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 24), i1);
  goto B1;
  B2:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i1 = 3u;
  i0 &= i1;
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = l2;
  i1 = l3;
  i2 = 4294967294u;
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  i0 = l2;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  goto Bfunc;
  B1:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i1 = 2u;
  i0 &= i1;
  if (i0) {goto B16;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061764));
  i1 = l2;
  i0 = i0 != i1;
  if (i0) {goto B17;}
  i0 = 0u;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 1061764), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061752));
  i2 = p1;
  i1 += i2;
  p1 = i1;
  i32_store((&memory), (u64)(i0 + 1061752), i1);
  i0 = p0;
  i1 = p1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061760));
  i0 = i0 != i1;
  if (i0) {goto B0;}
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  i0 = 0u;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 1061760), i1);
  goto Bfunc;
  B17:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061760));
  i1 = l2;
  i0 = i0 != i1;
  if (i0) {goto B18;}
  i0 = 0u;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 1061760), i1);
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061748));
  i2 = p1;
  i1 += i2;
  p1 = i1;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  i0 = p0;
  i1 = p1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B18:;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061756));
  l4 = i0;
  i0 = l3;
  i1 = 4294967288u;
  i0 &= i1;
  i1 = p1;
  i0 += i1;
  p1 = i0;
  i0 = l3;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B20;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l5 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l6 = i0;
  i1 = l3;
  i2 = 3u;
  i1 >>= (i2 & 31);
  l2 = i1;
  i2 = 3u;
  i1 <<= (i2 & 31);
  i2 = 1061780u;
  i1 += i2;
  l3 = i1;
  i0 = i0 == i1;
  if (i0) {goto B21;}
  i0 = l4;
  i1 = l6;
  i0 = i0 > i1;
  B21:;
  i0 = l5;
  i1 = l6;
  i0 = i0 != i1;
  if (i0) {goto B22;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061740));
  i2 = 4294967294u;
  i3 = l2;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  goto B19;
  B22:;
  i0 = l5;
  i1 = l3;
  i0 = i0 == i1;
  if (i0) {goto B23;}
  i0 = l4;
  i1 = l5;
  i0 = i0 > i1;
  B23:;
  i0 = l5;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l6;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B19;
  B20:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l7 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l6 = i0;
  i1 = l2;
  i0 = i0 == i1;
  if (i0) {goto B25;}
  i0 = l4;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  l3 = i1;
  i0 = i0 > i1;
  if (i0) {goto B26;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i1 = l2;
  i0 = i0 != i1;
  B26:;
  i0 = l6;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto B24;
  B25:;
  i0 = l2;
  i1 = 20u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  if (i0) {goto B27;}
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  if (i0) {goto B27;}
  i0 = 0u;
  l6 = i0;
  goto B24;
  B27:;
  L28: 
    i0 = l3;
    l4 = i0;
    i0 = l5;
    l6 = i0;
    i1 = 20u;
    i0 += i1;
    l3 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l5 = i0;
    if (i0) {goto L28;}
    i0 = l6;
    i1 = 16u;
    i0 += i1;
    l3 = i0;
    i0 = l6;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    l5 = i0;
    if (i0) {goto L28;}
  i0 = l4;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  B24:;
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B19;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  l5 = i0;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i0 = i0 != i1;
  if (i0) {goto B30;}
  i0 = l3;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  if (i0) {goto B29;}
  i0 = 0u;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061744));
  i2 = 4294967294u;
  i3 = l5;
  i2 = I32_ROTL(i2, i3);
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  goto B19;
  B30:;
  i0 = l7;
  i1 = 16u;
  i2 = 20u;
  i3 = l7;
  i3 = i32_load((&memory), (u64)(i3 + 16));
  i4 = l2;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B19;}
  B29:;
  i0 = l6;
  i1 = l7;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B31;}
  i0 = l6;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l3;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B31:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B19;}
  i0 = l6;
  i1 = 20u;
  i0 += i1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 24), i1);
  B19:;
  i0 = p0;
  i1 = p1;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1061760));
  i0 = i0 != i1;
  if (i0) {goto B15;}
  i0 = 0u;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 1061748), i1);
  goto Bfunc;
  B16:;
  i0 = l2;
  i1 = l3;
  i2 = 4294967294u;
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p1;
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  B15:;
  i0 = p1;
  i1 = 255u;
  i0 = i0 > i1;
  if (i0) {goto B32;}
  i0 = p1;
  i1 = 3u;
  i0 >>= (i1 & 31);
  l3 = i0;
  i1 = 3u;
  i0 <<= (i1 & 31);
  i1 = 1061780u;
  i0 += i1;
  p1 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061740));
  l5 = i0;
  i1 = 1u;
  i2 = l3;
  i1 <<= (i2 & 31);
  l3 = i1;
  i0 &= i1;
  if (i0) {goto B34;}
  i0 = 0u;
  i1 = l5;
  i2 = l3;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061740), i1);
  i0 = p1;
  l3 = i0;
  goto B33;
  B34:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l3 = i0;
  B33:;
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p1;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto Bfunc;
  B32:;
  i0 = 0u;
  l3 = i0;
  i0 = p1;
  i1 = 8u;
  i0 >>= (i1 & 31);
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B35;}
  i0 = 31u;
  l3 = i0;
  i0 = p1;
  i1 = 16777215u;
  i0 = i0 > i1;
  if (i0) {goto B35;}
  i0 = l5;
  i1 = l5;
  i2 = 1048320u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 8u;
  i1 &= i2;
  l3 = i1;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l5;
  i2 = 520192u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 4u;
  i1 &= i2;
  l5 = i1;
  i0 <<= (i1 & 31);
  l6 = i0;
  i1 = l6;
  i2 = 245760u;
  i1 += i2;
  i2 = 16u;
  i1 >>= (i2 & 31);
  i2 = 2u;
  i1 &= i2;
  l6 = i1;
  i0 <<= (i1 & 31);
  i1 = 15u;
  i0 >>= (i1 & 31);
  i1 = l5;
  i2 = l3;
  i1 |= i2;
  i2 = l6;
  i1 |= i2;
  i0 -= i1;
  l3 = i0;
  i1 = 1u;
  i0 <<= (i1 & 31);
  i1 = p1;
  i2 = l3;
  i3 = 21u;
  i2 += i3;
  i1 >>= (i2 & 31);
  i2 = 1u;
  i1 &= i2;
  i0 |= i1;
  i1 = 28u;
  i0 += i1;
  l3 = i0;
  B35:;
  i0 = p0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = p0;
  i1 = 28u;
  i0 += i1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1062044u;
  i0 += i1;
  l5 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1061744));
  l6 = i0;
  i1 = 1u;
  i2 = l3;
  i1 <<= (i2 & 31);
  l2 = i1;
  i0 &= i1;
  if (i0) {goto B36;}
  i0 = l5;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 0u;
  i1 = l6;
  i2 = l2;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 1061744), i1);
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  goto Bfunc;
  B36:;
  i0 = p1;
  i1 = 0u;
  i2 = 25u;
  i3 = l3;
  i4 = 1u;
  i3 >>= (i4 & 31);
  i2 -= i3;
  i3 = l3;
  i4 = 31u;
  i3 = i3 == i4;
  i1 = i3 ? i1 : i2;
  i0 <<= (i1 & 31);
  l3 = i0;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  L38: 
    i0 = l6;
    l5 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i1 = 4294967288u;
    i0 &= i1;
    i1 = p1;
    i0 = i0 == i1;
    if (i0) {goto B37;}
    i0 = l3;
    i1 = 29u;
    i0 >>= (i1 & 31);
    l6 = i0;
    i0 = l3;
    i1 = 1u;
    i0 <<= (i1 & 31);
    l3 = i0;
    i0 = l5;
    i1 = l6;
    i2 = 4u;
    i1 &= i2;
    i0 += i1;
    i1 = 16u;
    i0 += i1;
    l2 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    if (i0) {goto L38;}
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto Bfunc;
  B37:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p1 = i0;
  i0 = l5;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p1;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 12), i1);
  B0:;
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 internal_memalign(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i1 = 16u;
  i2 = p0;
  i3 = 16u;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l2 = i0;
  i1 = l2;
  i2 = 4294967295u;
  i1 += i2;
  i0 &= i1;
  if (i0) {goto B1;}
  i0 = l2;
  p0 = i0;
  goto B0;
  B1:;
  i0 = 32u;
  l3 = i0;
  L2: 
    i0 = l3;
    p0 = i0;
    i1 = 1u;
    i0 <<= (i1 & 31);
    l3 = i0;
    i0 = p0;
    i1 = l2;
    i0 = i0 < i1;
    if (i0) {goto L2;}
  B0:;
  i0 = 4294967232u;
  i1 = p0;
  i0 -= i1;
  i1 = p1;
  i0 = i0 > i1;
  if (i0) {goto B3;}
  i0 = 0u;
  i1 = 48u;
  i32_store((&memory), (u64)(i0 + 1062236), i1);
  i0 = 0u;
  goto Bfunc;
  B3:;
  i0 = 16u;
  i1 = p1;
  i2 = 19u;
  i1 += i2;
  i2 = 4294967280u;
  i1 &= i2;
  i2 = p1;
  i3 = 11u;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  p1 = i0;
  i1 = 12u;
  i0 |= i1;
  i1 = p0;
  i0 += i1;
  i0 = dlmalloc(i0);
  l3 = i0;
  if (i0) {goto B4;}
  i0 = 0u;
  goto Bfunc;
  B4:;
  i0 = l3;
  i1 = 4294967288u;
  i0 += i1;
  l2 = i0;
  i0 = p0;
  i1 = 4294967295u;
  i0 += i1;
  i1 = l3;
  i0 &= i1;
  if (i0) {goto B6;}
  i0 = l2;
  p0 = i0;
  goto B5;
  B6:;
  i0 = l3;
  i1 = 4294967292u;
  i0 += i1;
  l4 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  i1 = 4294967288u;
  i0 &= i1;
  i1 = l3;
  i2 = p0;
  i1 += i2;
  i2 = 4294967295u;
  i1 += i2;
  i2 = 0u;
  i3 = p0;
  i2 -= i3;
  i1 &= i2;
  i2 = 4294967288u;
  i1 += i2;
  l3 = i1;
  i2 = l3;
  i3 = p0;
  i2 += i3;
  i3 = l3;
  i4 = l2;
  i3 -= i4;
  i4 = 15u;
  i3 = i3 > i4;
  i1 = i3 ? i1 : i2;
  p0 = i1;
  i2 = l2;
  i1 -= i2;
  l3 = i1;
  i0 -= i1;
  l6 = i0;
  i0 = l5;
  i1 = 3u;
  i0 &= i1;
  if (i0) {goto B7;}
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = l3;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  goto B5;
  B7:;
  i0 = p0;
  i1 = l6;
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i3 = 1u;
  i2 &= i3;
  i1 |= i2;
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l6;
  i0 += i1;
  l6 = i0;
  i1 = l6;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = l3;
  i2 = l4;
  i2 = i32_load((&memory), (u64)(i2));
  i3 = 1u;
  i2 &= i3;
  i1 |= i2;
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = l3;
  dispose_chunk(i0, i1);
  B5:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i1 = 3u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = l3;
  i1 = 4294967288u;
  i0 &= i1;
  l2 = i0;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  i0 = i0 <= i1;
  if (i0) {goto B8;}
  i0 = p0;
  i1 = p1;
  i2 = l3;
  i3 = 1u;
  i2 &= i3;
  i1 |= i2;
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i0 += i1;
  l3 = i0;
  i1 = l2;
  i2 = p1;
  i1 -= i2;
  p1 = i1;
  i2 = 3u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l2;
  i0 += i1;
  l2 = i0;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = p1;
  dispose_chunk(i0, i1);
  B8:;
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 aligned_alloc(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = 16u;
  i0 = i0 > i1;
  if (i0) {goto B0;}
  i0 = p1;
  i0 = dlmalloc(i0);
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = p1;
  i0 = internal_memalign(i0, i1);
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _Exit(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  (*Z_wasi_snapshot_preview1Z_proc_exitZ_vi)(i0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 __wasilibc_find_relpath(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, 
      l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, l16 = 0, l17 = 0, 
      l18 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = 0u;
  l2 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062248));
  l3 = i0;
  if (i0) {goto B2;}
  i0 = 4294967295u;
  l4 = i0;
  goto B0;
  B2:;
  i0 = p0;
  i1 = 1u;
  i0 += i1;
  l5 = i0;
  i0 = 0u;
  l2 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062240));
  l6 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  l7 = i0;
  i1 = 4294967250u;
  i0 += i1;
  l8 = i0;
  i0 = 0u;
  l9 = i0;
  i0 = 0u;
  l10 = i0;
  i0 = 4294967295u;
  l4 = i0;
  L3: 
    i0 = l6;
    i1 = l9;
    i2 = 3u;
    i1 <<= (i2 & 31);
    i0 += i1;
    l11 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l12 = i0;
    i0 = strlen_0(i0);
    l13 = i0;
    i0 = l8;
    i1 = 1u;
    i0 = i0 > i1;
    if (i0) {goto B5;}
    i0 = l8;
    switch (i0) {
      case 0: goto B6;
      case 1: goto B4;
      default: goto B6;
    }
    B6:;
    i0 = p0;
    i0 = i32_load8_u((&memory), (u64)(i0 + 1));
    l14 = i0;
    i0 = !(i0);
    if (i0) {goto B4;}
    i0 = l14;
    i1 = 47u;
    i0 = i0 == i1;
    if (i0) {goto B4;}
    B5:;
    i0 = l13;
    i1 = 2u;
    i0 = i0 < i1;
    if (i0) {goto B7;}
    i0 = l12;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 46u;
    i0 = i0 != i1;
    if (i0) {goto B4;}
    i0 = l12;
    i0 = i32_load8_u((&memory), (u64)(i0 + 1));
    i1 = 47u;
    i0 = i0 != i1;
    if (i0) {goto B4;}
    i0 = l13;
    i1 = 4294967294u;
    i0 += i1;
    l13 = i0;
    i0 = l12;
    i1 = 2u;
    i0 += i1;
    l12 = i0;
    goto B4;
    B7:;
    i0 = l13;
    i1 = 1u;
    i0 = i0 != i1;
    l14 = i0;
    i0 = 0u;
    l13 = i0;
    i0 = l14;
    if (i0) {goto B4;}
    i0 = l12;
    i1 = 1u;
    i0 += i1;
    i1 = l12;
    i2 = l12;
    i2 = i32_load8_u((&memory), (u64)(i2));
    l14 = i2;
    i3 = 46u;
    i2 = i2 == i3;
    i0 = i2 ? i0 : i1;
    l12 = i0;
    i0 = l14;
    i1 = 46u;
    i0 = i0 != i1;
    l13 = i0;
    B4:;
    i0 = l13;
    i1 = l2;
    i0 = i0 > i1;
    if (i0) {goto B9;}
    i0 = l10;
    i1 = 1u;
    i0 ^= i1;
    i1 = 1u;
    i0 &= i1;
    i0 = !(i0);
    if (i0) {goto B8;}
    B9:;
    i0 = l12;
    i0 = !(i0);
    if (i0) {goto B1;}
    i0 = l7;
    i1 = 47u;
    i0 = i0 == i1;
    if (i0) {goto B11;}
    i0 = l13;
    i0 = !(i0);
    if (i0) {goto B10;}
    B11:;
    i0 = l13;
    i0 = !(i0);
    if (i0) {goto B12;}
    i0 = l7;
    i1 = l12;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i0 = i0 != i1;
    if (i0) {goto B8;}
    i0 = l13;
    i1 = 4294967295u;
    i0 += i1;
    l14 = i0;
    i0 = l12;
    i1 = 1u;
    i0 += i1;
    l15 = i0;
    i0 = l5;
    l16 = i0;
    L13: 
      i0 = l14;
      i0 = !(i0);
      if (i0) {goto B12;}
      i0 = l14;
      i1 = 4294967295u;
      i0 += i1;
      l14 = i0;
      i0 = l15;
      i0 = i32_load8_u((&memory), (u64)(i0));
      l17 = i0;
      i0 = l16;
      i0 = i32_load8_u((&memory), (u64)(i0));
      l18 = i0;
      i0 = l16;
      i1 = 1u;
      i0 += i1;
      l16 = i0;
      i0 = l15;
      i1 = 1u;
      i0 += i1;
      l15 = i0;
      i0 = l18;
      i1 = l17;
      i0 = i0 == i1;
      if (i0) {goto L13;}
      goto B8;
    B12:;
    i0 = l12;
    i1 = 4294967295u;
    i0 += i1;
    l16 = i0;
    i0 = l13;
    l15 = i0;
    L15: 
      i0 = l15;
      l14 = i0;
      i0 = !(i0);
      if (i0) {goto B14;}
      i0 = l14;
      i1 = 4294967295u;
      i0 += i1;
      l15 = i0;
      i0 = l16;
      i1 = l14;
      i0 += i1;
      i0 = i32_load8_u((&memory), (u64)(i0));
      i1 = 47u;
      i0 = i0 == i1;
      if (i0) {goto L15;}
    B14:;
    i0 = p0;
    i1 = l14;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l14 = i0;
    i1 = 47u;
    i0 = i0 == i1;
    if (i0) {goto B10;}
    i0 = l14;
    if (i0) {goto B8;}
    B10:;
    i0 = l11;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l4 = i0;
    i0 = 1u;
    l10 = i0;
    i0 = l13;
    l2 = i0;
    B8:;
    i0 = l9;
    i1 = 1u;
    i0 += i1;
    l9 = i0;
    i1 = l3;
    i0 = i0 >= i1;
    if (i0) {goto B0;}
    goto L3;
  B1:;
  abort();
  UNREACHABLE;
  B0:;
  i0 = p0;
  i1 = l2;
  i0 += i1;
  l14 = i0;
  L17: 
    i0 = l14;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l15 = i0;
    i1 = 47u;
    i0 = i0 != i1;
    if (i0) {goto B16;}
    i0 = l14;
    i1 = 1u;
    i0 += i1;
    l14 = i0;
    goto L17;
  B16:;
  i0 = l15;
  if (i0) {goto B18;}
  i0 = 1055303u;
  l14 = i0;
  B18:;
  i0 = p1;
  i1 = l14;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  FUNC_EPILOGUE;
  return i0;
}

static void __wasilibc_populate_libpreopen(void) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l0 = i0;
  g0 = i0;
  i0 = 3u;
  l1 = i0;
  L3: 
    i0 = l1;
    i1 = l0;
    i2 = 8u;
    i1 += i2;
    i0 = (*Z_wasi_snapshot_preview1Z_fd_prestat_getZ_iii)(i0, i1);
    l2 = i0;
    i1 = 8u;
    i0 = i0 > i1;
    if (i0) {goto B2;}
    i0 = l2;
    switch (i0) {
      case 0: goto B5;
      case 1: goto B2;
      case 2: goto B2;
      case 3: goto B2;
      case 4: goto B2;
      case 5: goto B2;
      case 6: goto B2;
      case 7: goto B2;
      case 8: goto B4;
      default: goto B5;
    }
    B5:;
    i0 = l0;
    i0 = i32_load8_u((&memory), (u64)(i0 + 8));
    if (i0) {goto B6;}
    i0 = l0;
    i0 = i32_load((&memory), (u64)(i0 + 12));
    l2 = i0;
    i1 = 1u;
    i0 += i1;
    i0 = malloc(i0);
    l3 = i0;
    i0 = !(i0);
    if (i0) {goto B1;}
    i0 = l1;
    i1 = l3;
    i2 = l2;
    i0 = (*Z_wasi_snapshot_preview1Z_fd_prestat_dir_nameZ_iiii)(i0, i1, i2);
    if (i0) {goto B2;}
    i0 = l3;
    i1 = l0;
    i1 = i32_load((&memory), (u64)(i1 + 12));
    i0 += i1;
    i1 = 0u;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = l1;
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B0;}
    i0 = 0u;
    i0 = i32_load((&memory), (u64)(i0 + 1062248));
    l2 = i0;
    i1 = 0u;
    i1 = i32_load((&memory), (u64)(i1 + 1062244));
    i0 = i0 == i1;
    if (i0) {goto B8;}
    i0 = 0u;
    i0 = i32_load((&memory), (u64)(i0 + 1062240));
    l4 = i0;
    goto B7;
    B8:;
    i0 = 8u;
    i1 = l2;
    i2 = 1u;
    i1 <<= (i2 & 31);
    i2 = 4u;
    i3 = l2;
    i1 = i3 ? i1 : i2;
    l5 = i1;
    i0 = calloc(i0, i1);
    l4 = i0;
    i0 = !(i0);
    if (i0) {goto B1;}
    i0 = l4;
    i1 = 0u;
    i1 = i32_load((&memory), (u64)(i1 + 1062240));
    l6 = i1;
    i2 = l2;
    i3 = 3u;
    i2 <<= (i3 & 31);
    i0 = memcpy_0(i0, i1, i2);
    l2 = i0;
    i0 = l6;
    free(i0);
    i0 = 0u;
    i1 = l5;
    i32_store((&memory), (u64)(i0 + 1062244), i1);
    i0 = 0u;
    i1 = l2;
    i32_store((&memory), (u64)(i0 + 1062240), i1);
    i0 = 0u;
    i0 = i32_load((&memory), (u64)(i0 + 1062248));
    l2 = i0;
    B7:;
    i0 = 0u;
    i1 = l2;
    i2 = 1u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 1062248), i1);
    i0 = l4;
    i1 = l2;
    i2 = 3u;
    i1 <<= (i2 & 31);
    i0 += i1;
    l2 = i0;
    i1 = l1;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l2;
    i1 = l3;
    i32_store((&memory), (u64)(i0), i1);
    B6:;
    i0 = l1;
    i1 = 1u;
    i0 += i1;
    l2 = i0;
    i1 = l1;
    i0 = i0 >= i1;
    l3 = i0;
    i0 = l2;
    l1 = i0;
    i0 = l3;
    if (i0) {goto L3;}
    B4:;
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B2:;
  i0 = 71u;
  _Exit(i0);
  UNREACHABLE;
  B1:;
  i0 = 70u;
  _Exit(i0);
  UNREACHABLE;
  B0:;
  abort();
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void __wasilibc_initialize_environ_eagerly(void) {
  FUNC_PROLOGUE;
  __wasilibc_initialize_environ();
  FUNC_EPILOGUE;
}

static u32 sbrk(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  if (i0) {goto B0;}
  i0 = memory.pages;
  i1 = 16u;
  i0 <<= (i1 & 31);
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = 65535u;
  i0 &= i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 16u;
  i0 >>= (i1 & 31);
  i0 = wasm_rt_grow_memory((&memory), i0);
  p0 = i0;
  i1 = 4294967295u;
  i0 = i0 != i1;
  if (i0) {goto B2;}
  i0 = 0u;
  i1 = 48u;
  i32_store((&memory), (u64)(i0 + 1062236), i1);
  i0 = 4294967295u;
  goto Bfunc;
  B2:;
  i0 = p0;
  i1 = 16u;
  i0 <<= (i1 & 31);
  goto Bfunc;
  B1:;
  abort();
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void __wasilibc_ensure_environ(void) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062252));
  i1 = 4294967295u;
  i0 = i0 != i1;
  if (i0) {goto B0;}
  __wasilibc_initialize_environ();
  B0:;
  FUNC_EPILOGUE;
}

static void __wasilibc_initialize_environ(void) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l0 = i0;
  g0 = i0;
  i0 = l0;
  i1 = 12u;
  i0 += i1;
  i1 = l0;
  i2 = 8u;
  i1 += i2;
  i0 = (*Z_wasi_snapshot_preview1Z_environ_sizes_getZ_iii)(i0, i1);
  if (i0) {goto B2;}
  i0 = l0;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l1 = i0;
  if (i0) {goto B3;}
  i0 = 0u;
  i1 = 1062256u;
  i32_store((&memory), (u64)(i0 + 1062252), i1);
  goto B0;
  B3:;
  i0 = l1;
  i1 = 1u;
  i0 += i1;
  l2 = i0;
  i1 = l1;
  i0 = i0 < i1;
  if (i0) {goto B5;}
  i0 = l0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i0 = malloc(i0);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = l2;
  i1 = 4u;
  i0 = calloc(i0, i1);
  l1 = i0;
  if (i0) {goto B4;}
  i0 = l3;
  free(i0);
  B5:;
  i0 = 70u;
  _Exit(i0);
  UNREACHABLE;
  B4:;
  i0 = l1;
  i1 = l3;
  i0 = (*Z_wasi_snapshot_preview1Z_environ_getZ_iii)(i0, i1);
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l3;
  free(i0);
  i0 = l1;
  free(i0);
  B2:;
  i0 = 71u;
  _Exit(i0);
  UNREACHABLE;
  B1:;
  i0 = 0u;
  i1 = l1;
  i32_store((&memory), (u64)(i0 + 1062252), i1);
  B0:;
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static void dummy(void) {
  FUNC_PROLOGUE;
  FUNC_EPILOGUE;
}

static void __prepare_for_exit(void) {
  FUNC_PROLOGUE;
  dummy();
  dummy();
  FUNC_EPILOGUE;
}

static void exit(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  dummy();
  dummy();
  i0 = p0;
  _Exit(i0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 getenv(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  __wasilibc_ensure_environ();
  i0 = 0u;
  l1 = i0;
  i0 = p0;
  i1 = 61u;
  i0 = __strchrnul(i0, i1);
  l2 = i0;
  i1 = p0;
  i0 -= i1;
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0));
  if (i0) {goto B0;}
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062252));
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l4;
  i1 = 4u;
  i0 += i1;
  l4 = i0;
  L2: 
    i0 = p0;
    i1 = l2;
    i2 = l3;
    i0 = strncmp_0(i0, i1, i2);
    if (i0) {goto B3;}
    i0 = l2;
    i1 = l3;
    i0 += i1;
    l2 = i0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 61u;
    i0 = i0 == i1;
    if (i0) {goto B1;}
    B3:;
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    l2 = i0;
    i0 = l4;
    i1 = 4u;
    i0 += i1;
    l4 = i0;
    i0 = l2;
    if (i0) {goto L2;}
    goto B0;
  B1:;
  i0 = l2;
  i1 = 1u;
  i0 += i1;
  l1 = i0;
  B0:;
  i0 = l1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 strlen_0(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  l1 = i0;
  i0 = p0;
  i1 = 3u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  if (i0) {goto B3;}
  i0 = p0;
  i1 = p0;
  i0 -= i1;
  goto Bfunc;
  B3:;
  i0 = p0;
  i1 = 1u;
  i0 += i1;
  l1 = i0;
  L4: 
    i0 = l1;
    i1 = 3u;
    i0 &= i1;
    i0 = !(i0);
    if (i0) {goto B2;}
    i0 = l1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l2 = i0;
    i0 = l1;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    l1 = i0;
    i0 = l2;
    i0 = !(i0);
    if (i0) {goto B1;}
    goto L4;
  B2:;
  i0 = l1;
  i1 = 4294967292u;
  i0 += i1;
  l1 = i0;
  L5: 
    i0 = l1;
    i1 = 4u;
    i0 += i1;
    l1 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    l2 = i0;
    i1 = 4294967295u;
    i0 ^= i1;
    i1 = l2;
    i2 = 4278124287u;
    i1 += i2;
    i0 &= i1;
    i1 = 2155905152u;
    i0 &= i1;
    i0 = !(i0);
    if (i0) {goto L5;}
  i0 = l2;
  i1 = 255u;
  i0 &= i1;
  if (i0) {goto B6;}
  i0 = l1;
  i1 = p0;
  i0 -= i1;
  goto Bfunc;
  B6:;
  L7: 
    i0 = l1;
    i0 = i32_load8_u((&memory), (u64)(i0 + 1));
    l2 = i0;
    i0 = l1;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    l1 = i0;
    i0 = l2;
    if (i0) {goto L7;}
    goto B0;
  B1:;
  i0 = l3;
  i1 = 4294967295u;
  i0 += i1;
  l3 = i0;
  B0:;
  i0 = l3;
  i1 = p0;
  i0 -= i1;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 __strchrnul(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 3u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B2;}
  L3: 
    i0 = p0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l3 = i0;
    i0 = !(i0);
    if (i0) {goto B1;}
    i0 = l3;
    i1 = p1;
    i2 = 255u;
    i1 &= i2;
    i0 = i0 == i1;
    if (i0) {goto B1;}
    i0 = p0;
    i1 = 1u;
    i0 += i1;
    p0 = i0;
    i1 = 3u;
    i0 &= i1;
    if (i0) {goto L3;}
  B2:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i1 = 4294967295u;
  i0 ^= i1;
  i1 = l3;
  i2 = 4278124287u;
  i1 += i2;
  i0 &= i1;
  i1 = 2155905152u;
  i0 &= i1;
  if (i0) {goto B4;}
  i0 = l2;
  i1 = 16843009u;
  i0 *= i1;
  l2 = i0;
  L5: 
    i0 = l3;
    i1 = l2;
    i0 ^= i1;
    l3 = i0;
    i1 = 4294967295u;
    i0 ^= i1;
    i1 = l3;
    i2 = 4278124287u;
    i1 += i2;
    i0 &= i1;
    i1 = 2155905152u;
    i0 &= i1;
    if (i0) {goto B4;}
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l3 = i0;
    i0 = p0;
    i1 = 4u;
    i0 += i1;
    p0 = i0;
    i0 = l3;
    i1 = 4294967295u;
    i0 ^= i1;
    i1 = l3;
    i2 = 4278124287u;
    i1 += i2;
    i0 &= i1;
    i1 = 2155905152u;
    i0 &= i1;
    i0 = !(i0);
    if (i0) {goto L5;}
  B4:;
  i0 = p0;
  i1 = 4294967295u;
  i0 += i1;
  p0 = i0;
  L6: 
    i0 = p0;
    i1 = 1u;
    i0 += i1;
    p0 = i0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l3 = i0;
    i0 = !(i0);
    if (i0) {goto B1;}
    i0 = l3;
    i1 = p1;
    i2 = 255u;
    i1 &= i2;
    i0 = i0 != i1;
    if (i0) {goto L6;}
  B1:;
  i0 = p0;
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = p0;
  i1 = strlen_0(i1);
  i0 += i1;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 memcpy_0(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  i1 = 3u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p0;
  l3 = i0;
  L2: 
    i0 = l3;
    i1 = p1;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p2;
    i1 = 4294967295u;
    i0 += i1;
    l4 = i0;
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    p1 = i0;
    i0 = p2;
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B0;}
    i0 = l4;
    p2 = i0;
    i0 = p1;
    i1 = 3u;
    i0 &= i1;
    if (i0) {goto L2;}
    goto B0;
  B1:;
  i0 = p2;
  l4 = i0;
  i0 = p0;
  l3 = i0;
  B0:;
  i0 = l3;
  i1 = 3u;
  i0 &= i1;
  p2 = i0;
  if (i0) {goto B4;}
  i0 = l4;
  i1 = 16u;
  i0 = i0 >= i1;
  if (i0) {goto B6;}
  i0 = l4;
  p2 = i0;
  goto B5;
  B6:;
  i0 = l4;
  i1 = 4294967280u;
  i0 += i1;
  p2 = i0;
  L7: 
    i0 = l3;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 4u;
    i0 += i1;
    i1 = p1;
    i2 = 4u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 8u;
    i0 += i1;
    i1 = p1;
    i2 = 8u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 12u;
    i0 += i1;
    i1 = p1;
    i2 = 12u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 16u;
    i0 += i1;
    l3 = i0;
    i0 = p1;
    i1 = 16u;
    i0 += i1;
    p1 = i0;
    i0 = l4;
    i1 = 4294967280u;
    i0 += i1;
    l4 = i0;
    i1 = 15u;
    i0 = i0 > i1;
    if (i0) {goto L7;}
  B5:;
  i0 = p2;
  i1 = 8u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = l3;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  p1 = i0;
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  l3 = i0;
  B8:;
  i0 = p2;
  i1 = 4u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = l3;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  p1 = i0;
  i0 = l3;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  B9:;
  i0 = p2;
  i1 = 2u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 1));
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = l3;
  i1 = 2u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 2u;
  i0 += i1;
  p1 = i0;
  B10:;
  i0 = p2;
  i1 = 1u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  goto Bfunc;
  B4:;
  i0 = l4;
  i1 = 32u;
  i0 = i0 < i1;
  if (i0) {goto B11;}
  i0 = p2;
  i1 = 4294967295u;
  i0 += i1;
  p2 = i0;
  i1 = 2u;
  i0 = i0 > i1;
  if (i0) {goto B11;}
  i0 = p2;
  switch (i0) {
    case 0: goto B14;
    case 1: goto B13;
    case 2: goto B12;
    default: goto B14;
  }
  B14:;
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 1));
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 2));
  i32_store8((&memory), (u64)(i0 + 2), i1);
  i0 = l4;
  i1 = 4294967293u;
  i0 += i1;
  l6 = i0;
  i0 = l3;
  i1 = 3u;
  i0 += i1;
  l7 = i0;
  i0 = l4;
  i1 = 4294967276u;
  i0 += i1;
  i1 = 4294967280u;
  i0 &= i1;
  l8 = i0;
  i0 = 0u;
  p2 = i0;
  L15: 
    i0 = l7;
    i1 = p2;
    i0 += i1;
    l3 = i0;
    i1 = p1;
    i2 = p2;
    i1 += i2;
    l9 = i1;
    i2 = 4u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l10 = i1;
    i2 = 8u;
    i1 <<= (i2 & 31);
    i2 = l5;
    i3 = 24u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 4u;
    i0 += i1;
    i1 = l9;
    i2 = 8u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l5 = i1;
    i2 = 8u;
    i1 <<= (i2 & 31);
    i2 = l10;
    i3 = 24u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 8u;
    i0 += i1;
    i1 = l9;
    i2 = 12u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l10 = i1;
    i2 = 8u;
    i1 <<= (i2 & 31);
    i2 = l5;
    i3 = 24u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 12u;
    i0 += i1;
    i1 = l9;
    i2 = 16u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l5 = i1;
    i2 = 8u;
    i1 <<= (i2 & 31);
    i2 = l10;
    i3 = 24u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p2;
    i1 = 16u;
    i0 += i1;
    p2 = i0;
    i0 = l6;
    i1 = 4294967280u;
    i0 += i1;
    l6 = i0;
    i1 = 16u;
    i0 = i0 > i1;
    if (i0) {goto L15;}
  i0 = l7;
  i1 = p2;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = p2;
  i0 += i1;
  i1 = 3u;
  i0 += i1;
  p1 = i0;
  i0 = l4;
  i1 = l8;
  i0 -= i1;
  i1 = 4294967277u;
  i0 += i1;
  l4 = i0;
  goto B11;
  B13:;
  i0 = l3;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 1));
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = l4;
  i1 = 4294967294u;
  i0 += i1;
  l6 = i0;
  i0 = l3;
  i1 = 2u;
  i0 += i1;
  l7 = i0;
  i0 = l4;
  i1 = 4294967276u;
  i0 += i1;
  i1 = 4294967280u;
  i0 &= i1;
  l8 = i0;
  i0 = 0u;
  p2 = i0;
  L16: 
    i0 = l7;
    i1 = p2;
    i0 += i1;
    l3 = i0;
    i1 = p1;
    i2 = p2;
    i1 += i2;
    l9 = i1;
    i2 = 4u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l10 = i1;
    i2 = 16u;
    i1 <<= (i2 & 31);
    i2 = l5;
    i3 = 16u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 4u;
    i0 += i1;
    i1 = l9;
    i2 = 8u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l5 = i1;
    i2 = 16u;
    i1 <<= (i2 & 31);
    i2 = l10;
    i3 = 16u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 8u;
    i0 += i1;
    i1 = l9;
    i2 = 12u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l10 = i1;
    i2 = 16u;
    i1 <<= (i2 & 31);
    i2 = l5;
    i3 = 16u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 12u;
    i0 += i1;
    i1 = l9;
    i2 = 16u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l5 = i1;
    i2 = 16u;
    i1 <<= (i2 & 31);
    i2 = l10;
    i3 = 16u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p2;
    i1 = 16u;
    i0 += i1;
    p2 = i0;
    i0 = l6;
    i1 = 4294967280u;
    i0 += i1;
    l6 = i0;
    i1 = 17u;
    i0 = i0 > i1;
    if (i0) {goto L16;}
  i0 = l7;
  i1 = p2;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = p2;
  i0 += i1;
  i1 = 2u;
  i0 += i1;
  p1 = i0;
  i0 = l4;
  i1 = l8;
  i0 -= i1;
  i1 = 4294967278u;
  i0 += i1;
  l4 = i0;
  goto B11;
  B12:;
  i0 = l3;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 4294967295u;
  i0 += i1;
  l6 = i0;
  i0 = l3;
  i1 = 1u;
  i0 += i1;
  l7 = i0;
  i0 = l4;
  i1 = 4294967276u;
  i0 += i1;
  i1 = 4294967280u;
  i0 &= i1;
  l8 = i0;
  i0 = 0u;
  p2 = i0;
  L17: 
    i0 = l7;
    i1 = p2;
    i0 += i1;
    l3 = i0;
    i1 = p1;
    i2 = p2;
    i1 += i2;
    l9 = i1;
    i2 = 4u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l10 = i1;
    i2 = 24u;
    i1 <<= (i2 & 31);
    i2 = l5;
    i3 = 8u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 4u;
    i0 += i1;
    i1 = l9;
    i2 = 8u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l5 = i1;
    i2 = 24u;
    i1 <<= (i2 & 31);
    i2 = l10;
    i3 = 8u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 8u;
    i0 += i1;
    i1 = l9;
    i2 = 12u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l10 = i1;
    i2 = 24u;
    i1 <<= (i2 & 31);
    i2 = l5;
    i3 = 8u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 12u;
    i0 += i1;
    i1 = l9;
    i2 = 16u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    l5 = i1;
    i2 = 24u;
    i1 <<= (i2 & 31);
    i2 = l10;
    i3 = 8u;
    i2 >>= (i3 & 31);
    i1 |= i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p2;
    i1 = 16u;
    i0 += i1;
    p2 = i0;
    i0 = l6;
    i1 = 4294967280u;
    i0 += i1;
    l6 = i0;
    i1 = 18u;
    i0 = i0 > i1;
    if (i0) {goto L17;}
  i0 = l7;
  i1 = p2;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = p2;
  i0 += i1;
  i1 = 1u;
  i0 += i1;
  p1 = i0;
  i0 = l4;
  i1 = l8;
  i0 -= i1;
  i1 = 4294967279u;
  i0 += i1;
  l4 = i0;
  B11:;
  i0 = l4;
  i1 = 16u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B18;}
  i0 = l3;
  i1 = p1;
  i1 = i32_load16_u((&memory), (u64)(i1));
  i32_store16((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 2));
  i32_store8((&memory), (u64)(i0 + 2), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 3));
  i32_store8((&memory), (u64)(i0 + 3), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 4));
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 5));
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 6));
  i32_store8((&memory), (u64)(i0 + 6), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 7));
  i32_store8((&memory), (u64)(i0 + 7), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 8));
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 9));
  i32_store8((&memory), (u64)(i0 + 9), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 10));
  i32_store8((&memory), (u64)(i0 + 10), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 11));
  i32_store8((&memory), (u64)(i0 + 11), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 12));
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 13));
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 14));
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 15));
  i32_store8((&memory), (u64)(i0 + 15), i1);
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 16u;
  i0 += i1;
  p1 = i0;
  B18:;
  i0 = l4;
  i1 = 8u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B19;}
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 1));
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 2));
  i32_store8((&memory), (u64)(i0 + 2), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 3));
  i32_store8((&memory), (u64)(i0 + 3), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 4));
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 5));
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 6));
  i32_store8((&memory), (u64)(i0 + 6), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 7));
  i32_store8((&memory), (u64)(i0 + 7), i1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  p1 = i0;
  B19:;
  i0 = l4;
  i1 = 4u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B20;}
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 1));
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 2));
  i32_store8((&memory), (u64)(i0 + 2), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 3));
  i32_store8((&memory), (u64)(i0 + 3), i1);
  i0 = l3;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  p1 = i0;
  B20:;
  i0 = l4;
  i1 = 2u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B21;}
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1 + 1));
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = l3;
  i1 = 2u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 2u;
  i0 += i1;
  p1 = i0;
  B21:;
  i0 = l4;
  i1 = 1u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l3;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i32_store8((&memory), (u64)(i0), i1);
  B3:;
  i0 = p0;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 memset_0(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0;
  u64 l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j0, j1;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = p1;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = p0;
  i0 += i1;
  l3 = i0;
  i1 = 4294967295u;
  i0 += i1;
  i1 = p1;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = 3u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 2), i1);
  i0 = p0;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = l3;
  i1 = 4294967293u;
  i0 += i1;
  i1 = p1;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 4294967294u;
  i0 += i1;
  i1 = p1;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = 7u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 3), i1);
  i0 = l3;
  i1 = 4294967292u;
  i0 += i1;
  i1 = p1;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = 9u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 0u;
  i2 = p0;
  i1 -= i2;
  i2 = 3u;
  i1 &= i2;
  l4 = i1;
  i0 += i1;
  l3 = i0;
  i1 = p1;
  i2 = 255u;
  i1 &= i2;
  i2 = 16843009u;
  i1 *= i2;
  p1 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = p2;
  i2 = l4;
  i1 -= i2;
  i2 = 4294967292u;
  i1 &= i2;
  l4 = i1;
  i0 += i1;
  p2 = i0;
  i1 = 4294967292u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 9u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p2;
  i1 = 4294967288u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = 4294967284u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 25u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p2;
  i1 = 4294967280u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = 4294967276u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = 4294967272u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = 4294967268u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l3;
  i2 = 4u;
  i1 &= i2;
  i2 = 24u;
  i1 |= i2;
  l5 = i1;
  i0 -= i1;
  p2 = i0;
  i1 = 32u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = p1;
  j0 = (u64)(i0);
  l6 = j0;
  j1 = 32ull;
  j0 <<= (j1 & 63);
  j1 = l6;
  j0 |= j1;
  l6 = j0;
  i0 = l3;
  i1 = l5;
  i0 += i1;
  p1 = i0;
  L1: 
    i0 = p1;
    j1 = l6;
    i64_store((&memory), (u64)(i0), j1);
    i0 = p1;
    i1 = 24u;
    i0 += i1;
    j1 = l6;
    i64_store((&memory), (u64)(i0), j1);
    i0 = p1;
    i1 = 16u;
    i0 += i1;
    j1 = l6;
    i64_store((&memory), (u64)(i0), j1);
    i0 = p1;
    i1 = 8u;
    i0 += i1;
    j1 = l6;
    i64_store((&memory), (u64)(i0), j1);
    i0 = p1;
    i1 = 32u;
    i0 += i1;
    p1 = i0;
    i0 = p2;
    i1 = 4294967264u;
    i0 += i1;
    p2 = i0;
    i1 = 31u;
    i0 = i0 > i1;
    if (i0) {goto L1;}
  B0:;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 memcmp_0(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = 0u;
  l3 = i0;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B0;}
  L2: 
    i0 = p0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l4 = i0;
    i1 = p1;
    i1 = i32_load8_u((&memory), (u64)(i1));
    l5 = i1;
    i0 = i0 != i1;
    if (i0) {goto B1;}
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    p1 = i0;
    i0 = p0;
    i1 = 1u;
    i0 += i1;
    p0 = i0;
    i0 = p2;
    i1 = 4294967295u;
    i0 += i1;
    p2 = i0;
    if (i0) {goto L2;}
    goto B0;
  B1:;
  i0 = l4;
  i1 = l5;
  i0 -= i1;
  l3 = i0;
  B0:;
  i0 = l3;
  FUNC_EPILOGUE;
  return i0;
}

static u32 strncmp_0(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p2;
  if (i0) {goto B0;}
  i0 = 0u;
  goto Bfunc;
  B0:;
  i0 = 0u;
  l3 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 1u;
  i0 += i1;
  p0 = i0;
  i0 = p2;
  i1 = 4294967295u;
  i0 += i1;
  p2 = i0;
  L2: 
    i0 = l4;
    i1 = 255u;
    i0 &= i1;
    i1 = p1;
    i1 = i32_load8_u((&memory), (u64)(i1));
    l5 = i1;
    i0 = i0 == i1;
    if (i0) {goto B3;}
    i0 = l4;
    l3 = i0;
    goto B1;
    B3:;
    i0 = p2;
    if (i0) {goto B4;}
    i0 = l4;
    l3 = i0;
    goto B1;
    B4:;
    i0 = l5;
    if (i0) {goto B5;}
    i0 = l4;
    l3 = i0;
    goto B1;
    B5:;
    i0 = p2;
    i1 = 4294967295u;
    i0 += i1;
    p2 = i0;
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    p1 = i0;
    i0 = p0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l4 = i0;
    i0 = p0;
    i1 = 1u;
    i0 += i1;
    p0 = i0;
    i0 = l4;
    if (i0) {goto L2;}
  B1:;
  i0 = l3;
  i1 = 255u;
  i0 &= i1;
  i1 = p1;
  i1 = i32_load8_u((&memory), (u64)(i1));
  i0 -= i1;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 strerror_0(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = 0u;
  l1 = i0;
  i0 = 0u;
  i0 = i32_load((&memory), (u64)(i0 + 1062284));
  l2 = i0;
  if (i0) {goto B0;}
  i0 = 1062260u;
  l2 = i0;
  i0 = 0u;
  i1 = 1062260u;
  i32_store((&memory), (u64)(i0 + 1062284), i1);
  B0:;
  L4: 
    i0 = l1;
    i1 = 1055312u;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = p0;
    i0 = i0 == i1;
    if (i0) {goto B3;}
    i0 = 77u;
    l3 = i0;
    i0 = l1;
    i1 = 1u;
    i0 += i1;
    l1 = i0;
    i1 = 77u;
    i0 = i0 != i1;
    if (i0) {goto L4;}
    goto B2;
  B3:;
  i0 = l1;
  l3 = i0;
  i0 = l1;
  if (i0) {goto B2;}
  i0 = 1055392u;
  l4 = i0;
  goto B1;
  B2:;
  i0 = 1055392u;
  l1 = i0;
  L5: 
    i0 = l1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    p0 = i0;
    i0 = l1;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    l1 = i0;
    i0 = p0;
    if (i0) {goto L5;}
    i0 = l4;
    l1 = i0;
    i0 = l3;
    i1 = 4294967295u;
    i0 += i1;
    l3 = i0;
    if (i0) {goto L5;}
  B1:;
  i0 = l4;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 20));
  i0 = __lctrans(i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 strerror_r(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i0 = strerror_0(i0);
  p0 = i0;
  i0 = strlen_0(i0);
  l3 = i0;
  i1 = p2;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = 68u;
  l3 = i0;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = p0;
  i2 = p2;
  i3 = 4294967295u;
  i2 += i3;
  p2 = i2;
  i0 = memcpy_0(i0, i1, i2);
  i1 = p2;
  i0 += i1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = 68u;
  goto Bfunc;
  B1:;
  i0 = p1;
  i1 = p0;
  i2 = l3;
  i3 = 1u;
  i2 += i3;
  i0 = memcpy_0(i0, i1, i2);
  i0 = 0u;
  l3 = i0;
  B0:;
  i0 = l3;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 memmove_0(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i1 = p1;
  i0 = i0 == i1;
  if (i0) {goto B0;}
  i0 = p1;
  i1 = p0;
  i0 -= i1;
  i1 = p2;
  i0 -= i1;
  i1 = 0u;
  i2 = p2;
  i3 = 1u;
  i2 <<= (i3 & 31);
  i1 -= i2;
  i0 = i0 > i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = p1;
  i2 = p2;
  i0 = memcpy_0(i0, i1, i2);
  goto B0;
  B1:;
  i0 = p1;
  i1 = p0;
  i0 ^= i1;
  i1 = 3u;
  i0 &= i1;
  l3 = i0;
  i0 = p0;
  i1 = p1;
  i0 = i0 >= i1;
  if (i0) {goto B4;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = p0;
  l3 = i0;
  goto B2;
  B5:;
  i0 = p0;
  i1 = 3u;
  i0 &= i1;
  if (i0) {goto B6;}
  i0 = p0;
  l3 = i0;
  goto B3;
  B6:;
  i0 = p0;
  l3 = i0;
  L7: 
    i0 = p2;
    i0 = !(i0);
    if (i0) {goto B0;}
    i0 = l3;
    i1 = p1;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    p1 = i0;
    i0 = p2;
    i1 = 4294967295u;
    i0 += i1;
    p2 = i0;
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    i1 = 3u;
    i0 &= i1;
    i0 = !(i0);
    if (i0) {goto B3;}
    goto L7;
  B4:;
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = p2;
  l3 = i0;
  goto B8;
  B9:;
  i0 = p0;
  i1 = p2;
  i0 += i1;
  i1 = 3u;
  i0 &= i1;
  if (i0) {goto B11;}
  i0 = p2;
  l3 = i0;
  goto B10;
  B11:;
  i0 = p1;
  i1 = 4294967295u;
  i0 += i1;
  l4 = i0;
  i0 = p0;
  i1 = 4294967295u;
  i0 += i1;
  l5 = i0;
  L12: 
    i0 = p2;
    i0 = !(i0);
    if (i0) {goto B0;}
    i0 = l5;
    i1 = p2;
    i0 += i1;
    l6 = i0;
    i1 = l4;
    i2 = p2;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p2;
    i1 = 4294967295u;
    i0 += i1;
    l3 = i0;
    p2 = i0;
    i0 = l6;
    i1 = 3u;
    i0 &= i1;
    if (i0) {goto L12;}
  B10:;
  i0 = l3;
  i1 = 4u;
  i0 = i0 < i1;
  if (i0) {goto B8;}
  i0 = p0;
  i1 = 4294967292u;
  i0 += i1;
  p2 = i0;
  i0 = p1;
  i1 = 4294967292u;
  i0 += i1;
  l6 = i0;
  L13: 
    i0 = p2;
    i1 = l3;
    i0 += i1;
    i1 = l6;
    i2 = l3;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 4294967292u;
    i0 += i1;
    l3 = i0;
    i1 = 3u;
    i0 = i0 > i1;
    if (i0) {goto L13;}
  B8:;
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 4294967295u;
  i0 += i1;
  p1 = i0;
  i0 = p0;
  i1 = 4294967295u;
  i0 += i1;
  p2 = i0;
  L14: 
    i0 = p2;
    i1 = l3;
    i0 += i1;
    i1 = p1;
    i2 = l3;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 4294967295u;
    i0 += i1;
    l3 = i0;
    if (i0) {goto L14;}
    goto B0;
  B3:;
  i0 = p2;
  i1 = 4u;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = p2;
  l6 = i0;
  L15: 
    i0 = l3;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = p1;
    i1 = 4u;
    i0 += i1;
    p1 = i0;
    i0 = l3;
    i1 = 4u;
    i0 += i1;
    l3 = i0;
    i0 = l6;
    i1 = 4294967292u;
    i0 += i1;
    l6 = i0;
    i1 = 3u;
    i0 = i0 > i1;
    if (i0) {goto L15;}
  i0 = p2;
  i1 = 3u;
  i0 &= i1;
  p2 = i0;
  B2:;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B0;}
  L16: 
    i0 = l3;
    i1 = p1;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    p1 = i0;
    i0 = p2;
    i1 = 4294967295u;
    i0 += i1;
    p2 = i0;
    if (i0) {goto L16;}
  B0:;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 dummy_1(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 __lctrans(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p1;
  i0 = dummy_1(i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3ptr13drop_in_place17h402ec9c621dc0a64E(u32 p0) {
  FUNC_PROLOGUE;
  FUNC_EPILOGUE;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17he835ee2740080451E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  _ZN5alloc6string6String4push17h49cb764b5cad3b99E(i0, i1);
  i0 = 0u;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN5alloc6string6String4push17h49cb764b5cad3b99E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  i1 = 128u;
  i0 = i0 < i1;
  if (i0) {goto B5;}
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p1;
  i1 = 2048u;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l2;
  i1 = 12u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 65536u;
  i0 = i0 >= i1;
  if (i0) {goto B6;}
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 15u;
  i1 &= i2;
  i2 = 224u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 3u;
  p1 = i0;
  goto B1;
  B6:;
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 15), i1);
  i0 = l2;
  i1 = p1;
  i2 = 18u;
  i1 >>= (i2 & 31);
  i2 = 240u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = 4u;
  p1 = i0;
  goto B1;
  B5:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l3 = i0;
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i0 = i0 == i1;
  if (i0) {goto B7;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  goto B2;
  B7:;
  i0 = l3;
  i1 = 1u;
  i0 += i1;
  l4 = i0;
  i1 = l3;
  i0 = i0 < i1;
  if (i0) {goto B10;}
  i0 = l3;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l4;
  i2 = l5;
  i3 = l4;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B10;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  if (i0) {goto B11;}
  B12:;
  i0 = l5;
  if (i0) {goto B9;}
  i0 = 1u;
  l4 = i0;
  goto B3;
  B11:;
  i0 = l3;
  i1 = l5;
  i0 = i0 == i1;
  if (i0) {goto B13;}
  i0 = l4;
  i1 = l3;
  i2 = 1u;
  i3 = l5;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l4 = i0;
  B13:;
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l3 = i0;
  goto B3;
  B10:;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  B9:;
  i0 = l5;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  if (i0) {goto B3;}
  B8:;
  i0 = l5;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B4:;
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 31u;
  i1 &= i2;
  i2 = 192u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 12u;
  i0 += i1;
  l3 = i0;
  i0 = 2u;
  p1 = i0;
  goto B1;
  B3:;
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  B2:;
  i0 = l4;
  i1 = l3;
  i0 += i1;
  i1 = p1;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  goto B0;
  B1:;
  i0 = p0;
  i1 = l3;
  i2 = l3;
  i3 = p1;
  i2 += i3;
  _ZN109__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_alloc__vec__SpecExtend_LT__RF_T_C_core__slice__Iter_LT_T_GT__GT__GT_11spec_extend17h45c47c004d042e17E(i0, i1, i2);
  B0:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17hd12a4d5c4ea306b5E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  i1 = 1056968u;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p1 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h0d968c1939c85c57E(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p1;
  i3 = p2;
  i2 += i3;
  _ZN109__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_alloc__vec__SpecExtend_LT__RF_T_C_core__slice__Iter_LT_T_GT__GT__GT_11spec_extend17h45c47c004d042e17E(i0, i1, i2);
  i0 = 0u;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN109__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_alloc__vec__SpecExtend_LT__RF_T_C_core__slice__Iter_LT_T_GT__GT__GT_11spec_extend17h45c47c004d042e17E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l4 = i1;
  i0 -= i1;
  i1 = p2;
  i2 = p1;
  i1 -= i2;
  p2 = i1;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  goto B0;
  B1:;
  i0 = l4;
  i1 = p2;
  i0 += i1;
  l5 = i0;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B5;}
  i0 = l3;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l6 = i0;
  i1 = l5;
  i2 = l6;
  i3 = l5;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l6 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B5;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  if (i0) {goto B6;}
  B7:;
  i0 = l6;
  if (i0) {goto B4;}
  i0 = 1u;
  l5 = i0;
  goto B2;
  B6:;
  i0 = l3;
  i1 = l6;
  i0 = i0 == i1;
  if (i0) {goto B8;}
  i0 = l5;
  i1 = l3;
  i2 = 1u;
  i3 = l6;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l5 = i0;
  B8:;
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  goto B2;
  B5:;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  B4:;
  i0 = l6;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l5 = i0;
  if (i0) {goto B2;}
  B3:;
  i0 = l6;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  B2:;
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  B0:;
  i0 = l5;
  i1 = l4;
  i0 += i1;
  i1 = p1;
  i2 = p2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i2 = p2;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p1;
  rust_oom(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h08088d9b25d6a95aE(void) {
  FUNC_PROLOGUE;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17ha9e5510550e81555E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p1;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E(void) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = 1057207u;
  i1 = 17u;
  i2 = 1057224u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN5alloc3fmt6format17h791816ebd75606e6E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l4 = i0;
  i1 = 3u;
  i0 <<= (i1 & 31);
  l5 = i0;
  if (i0) {goto B1;}
  i0 = 0u;
  l6 = i0;
  goto B0;
  B1:;
  i0 = l3;
  i1 = 4u;
  i0 += i1;
  l7 = i0;
  i0 = 0u;
  l6 = i0;
  L2: 
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l6;
    i0 += i1;
    l6 = i0;
    i0 = l7;
    i1 = 8u;
    i0 += i1;
    l7 = i0;
    i0 = l5;
    i1 = 4294967288u;
    i0 += i1;
    l5 = i0;
    if (i0) {goto L2;}
  B0:;
  i0 = p1;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  if (i0) {goto B8;}
  i0 = l6;
  l7 = i0;
  goto B7;
  B8:;
  i0 = l4;
  if (i0) {goto B9;}
  i0 = 0u;
  i1 = 0u;
  i2 = 1057064u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  B9:;
  i0 = l6;
  i1 = 15u;
  i0 = i0 > i1;
  if (i0) {goto B11;}
  i0 = l3;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = !(i0);
  if (i0) {goto B10;}
  B11:;
  i0 = l6;
  i1 = l6;
  i0 += i1;
  l7 = i0;
  i1 = l6;
  i0 = i0 >= i1;
  if (i0) {goto B7;}
  B10:;
  i0 = 0u;
  l7 = i0;
  i0 = 1u;
  l5 = i0;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l6 = i0;
  goto B6;
  B7:;
  i0 = l7;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B5;}
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l6 = i0;
  i0 = l7;
  if (i0) {goto B12;}
  i0 = 0u;
  l7 = i0;
  i0 = 1u;
  l5 = i0;
  goto B6;
  B12:;
  i0 = l7;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B4;}
  B6:;
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = l7;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = l2;
  i1 = 24u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 24u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l2;
  i1 = 20u;
  i0 += i1;
  i1 = 1056968u;
  i2 = l2;
  i3 = 24u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  if (i0) {goto B3;}
  i0 = p0;
  i1 = l6;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l6;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B5:;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h08088d9b25d6a95aE();
  UNREACHABLE;
  B4:;
  i0 = l7;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17ha9e5510550e81555E(i0, i1);
  UNREACHABLE;
  B3:;
  i0 = 1057096u;
  i1 = 51u;
  i2 = l2;
  i3 = 24u;
  i2 += i3;
  i3 = 1057080u;
  i4 = 1057168u;
  _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN5alloc5slice29__LT_impl_u20__u5b_T_u5d__GT_6to_vec17h36ab9f401e213751E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p2;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  i0 = p2;
  if (i0) {goto B4;}
  i0 = 0u;
  l3 = i0;
  i0 = 1u;
  l4 = i0;
  goto B3;
  B4:;
  i0 = p2;
  l3 = i0;
  i0 = p2;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  B3:;
  i0 = l3;
  i1 = p2;
  i0 = i0 >= i1;
  if (i0) {goto B6;}
  i0 = l3;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = p2;
  i2 = l5;
  i3 = p2;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B5;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = l4;
  if (i0) {goto B8;}
  B9:;
  i0 = l5;
  i1 = 1u;
  i0 = __rust_alloc(i0, i1);
  l4 = i0;
  if (i0) {goto B7;}
  goto B0;
  B8:;
  i0 = l3;
  i1 = l5;
  i0 = i0 == i1;
  if (i0) {goto B6;}
  i0 = l4;
  i1 = l3;
  i2 = 1u;
  i3 = l5;
  i0 = __rust_realloc(i0, i1, i2, i3);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  B7:;
  i0 = l5;
  l3 = i0;
  B6:;
  i0 = l4;
  i1 = p1;
  i2 = p2;
  i0 = memcpy_0(i0, i1, i2);
  l4 = i0;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B5:;
  _ZN5alloc7raw_vec17capacity_overflow17hc5a974c6ebf943a3E();
  UNREACHABLE;
  B2:;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h08088d9b25d6a95aE();
  UNREACHABLE;
  B1:;
  i0 = p2;
  i1 = 1u;
  _ZN5alloc7raw_vec19RawVec_LT_T_C_A_GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17ha9e5510550e81555E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = l5;
  i1 = 1u;
  _ZN5alloc5alloc18handle_alloc_error17h0f835bfbfb029df2E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN60__LT_alloc__string__String_u20_as_u20_core__clone__Clone_GT_5clone17hd5bc8de5dcbfa5d2E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 8));
  _ZN5alloc5slice29__LT_impl_u20__u5b_T_u5d__GT_6to_vec17h36ab9f401e213751E(i0, i1, i2);
  FUNC_EPILOGUE;
}

static void _ZN5alloc6string104__LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__vec__Vec_LT_u8_GT__GT_4from17h645290af10f55923E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = p0;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN5alloc3vec12Vec_LT_T_GT_5drain17end_assert_failed17hccc4a24f1f7369a6E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 28u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 44u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  j1 = 3ull;
  i64_store((&memory), (u64)(i0 + 12), j1);
  i0 = l2;
  i1 = 1057304u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l2;
  i1 = l2;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l2;
  i1 = l2;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l2;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 1057328u;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3ops8function6FnOnce9call_once17h0c772a731295e95aE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  L0: 
    goto L0;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3ptr13drop_in_place17h01fc6f5e51d8edbeE(u32 p0) {
  FUNC_PROLOGUE;
  FUNC_EPILOGUE;
}

static void _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 28u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 44u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 12), j1);
  i0 = l3;
  i1 = 1057696u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l3;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l3;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l3;
  i1 = l3;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN4core9panicking5panic17hab35b75b6c5c31f2E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = 20u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 1057344u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l3;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l3;
  i1 = l3;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = p2;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 28u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 44u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 12), j1);
  i0 = l3;
  i1 = 1058216u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l3;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l3;
  i1 = l3;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l3;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 28u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 44u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 12), j1);
  i0 = l3;
  i1 = 1058268u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l3;
  i1 = l3;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l3;
  i1 = l3;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l3;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l3;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3fmt9Formatter3pad17h18e6ccc150f9bfbcE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, 
      l11 = 0, l12 = 0, l13 = 0, l14 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i1 = 16u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B3;}
  i0 = l3;
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B2;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l3 = i0;
  goto B0;
  B3:;
  i0 = l3;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  B2:;
  i0 = p2;
  if (i0) {goto B5;}
  i0 = 0u;
  p2 = i0;
  goto B4;
  B5:;
  i0 = p1;
  i1 = p2;
  i0 += i1;
  l5 = i0;
  i0 = p0;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 1u;
  i0 += i1;
  l6 = i0;
  i0 = 0u;
  l7 = i0;
  i0 = p1;
  l3 = i0;
  i0 = p1;
  l8 = i0;
  L6: 
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    l9 = i0;
    i0 = l3;
    i0 = i32_load8_s((&memory), (u64)(i0));
    l10 = i0;
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    if (i0) {goto B9;}
    i0 = l9;
    i1 = l5;
    i0 = i0 != i1;
    if (i0) {goto B11;}
    i0 = 0u;
    l11 = i0;
    i0 = l5;
    l3 = i0;
    goto B10;
    B11:;
    i0 = l3;
    i0 = i32_load8_u((&memory), (u64)(i0 + 1));
    i1 = 63u;
    i0 &= i1;
    l11 = i0;
    i0 = l3;
    i1 = 2u;
    i0 += i1;
    l9 = i0;
    l3 = i0;
    B10:;
    i0 = l10;
    i1 = 31u;
    i0 &= i1;
    l12 = i0;
    i0 = l10;
    i1 = 255u;
    i0 &= i1;
    l10 = i0;
    i1 = 223u;
    i0 = i0 > i1;
    if (i0) {goto B12;}
    i0 = l11;
    i1 = l12;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l10 = i0;
    goto B8;
    B12:;
    i0 = l3;
    i1 = l5;
    i0 = i0 != i1;
    if (i0) {goto B14;}
    i0 = 0u;
    l13 = i0;
    i0 = l5;
    l14 = i0;
    goto B13;
    B14:;
    i0 = l3;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    l13 = i0;
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    l9 = i0;
    l14 = i0;
    B13:;
    i0 = l13;
    i1 = l11;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l11 = i0;
    i0 = l10;
    i1 = 240u;
    i0 = i0 >= i1;
    if (i0) {goto B15;}
    i0 = l11;
    i1 = l12;
    i2 = 12u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l10 = i0;
    goto B8;
    B15:;
    i0 = l14;
    i1 = l5;
    i0 = i0 != i1;
    if (i0) {goto B17;}
    i0 = 0u;
    l10 = i0;
    i0 = l9;
    l3 = i0;
    goto B16;
    B17:;
    i0 = l14;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    i0 = l14;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    l10 = i0;
    B16:;
    i0 = l11;
    i1 = 6u;
    i0 <<= (i1 & 31);
    i1 = l12;
    i2 = 18u;
    i1 <<= (i2 & 31);
    i2 = 1835008u;
    i1 &= i2;
    i0 |= i1;
    i1 = l10;
    i0 |= i1;
    l10 = i0;
    i1 = 1114112u;
    i0 = i0 != i1;
    if (i0) {goto B7;}
    goto B4;
    B9:;
    i0 = l10;
    i1 = 255u;
    i0 &= i1;
    l10 = i0;
    B8:;
    i0 = l9;
    l3 = i0;
    B7:;
    i0 = l6;
    i1 = 4294967295u;
    i0 += i1;
    l6 = i0;
    i0 = !(i0);
    if (i0) {goto B18;}
    i0 = l7;
    i1 = l8;
    i0 -= i1;
    i1 = l3;
    i0 += i1;
    l7 = i0;
    i0 = l3;
    l8 = i0;
    i0 = l5;
    i1 = l3;
    i0 = i0 != i1;
    if (i0) {goto L6;}
    goto B4;
    B18:;
  i0 = l10;
  i1 = 1114112u;
  i0 = i0 == i1;
  if (i0) {goto B4;}
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B20;}
  i0 = l7;
  i1 = p2;
  i0 = i0 == i1;
  if (i0) {goto B20;}
  i0 = 0u;
  l3 = i0;
  i0 = l7;
  i1 = p2;
  i0 = i0 >= i1;
  if (i0) {goto B19;}
  i0 = p1;
  i1 = l7;
  i0 += i1;
  i0 = i32_load8_s((&memory), (u64)(i0));
  i1 = 4294967232u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B19;}
  B20:;
  i0 = p1;
  l3 = i0;
  B19:;
  i0 = l7;
  i1 = p2;
  i2 = l3;
  i0 = i2 ? i0 : i1;
  p2 = i0;
  i0 = l3;
  i1 = p1;
  i2 = l3;
  i0 = i2 ? i0 : i1;
  p1 = i0;
  B4:;
  i0 = l4;
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  goto Bfunc;
  B1:;
  i0 = 0u;
  l9 = i0;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B21;}
  i0 = p2;
  l10 = i0;
  i0 = p1;
  l3 = i0;
  L22: 
    i0 = l9;
    i1 = l3;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i2 = 192u;
    i1 &= i2;
    i2 = 128u;
    i1 = i1 == i2;
    i0 += i1;
    l9 = i0;
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    i0 = l10;
    i1 = 4294967295u;
    i0 += i1;
    l10 = i0;
    if (i0) {goto L22;}
  B21:;
  i0 = p2;
  i1 = l9;
  i0 -= i1;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 12));
  l6 = i1;
  i0 = i0 < i1;
  if (i0) {goto B23;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  goto Bfunc;
  B23:;
  i0 = 0u;
  l7 = i0;
  i0 = 0u;
  l9 = i0;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B24;}
  i0 = 0u;
  l9 = i0;
  i0 = p2;
  l10 = i0;
  i0 = p1;
  l3 = i0;
  L25: 
    i0 = l9;
    i1 = l3;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i2 = 192u;
    i1 &= i2;
    i2 = 128u;
    i1 = i1 == i2;
    i0 += i1;
    l9 = i0;
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    i0 = l10;
    i1 = 4294967295u;
    i0 += i1;
    l10 = i0;
    if (i0) {goto L25;}
  B24:;
  i0 = l9;
  i1 = p2;
  i0 -= i1;
  i1 = l6;
  i0 += i1;
  l9 = i0;
  l10 = i0;
  i0 = 0u;
  i1 = p0;
  i1 = i32_load8_u((&memory), (u64)(i1 + 32));
  l3 = i1;
  i2 = l3;
  i3 = 3u;
  i2 = i2 == i3;
  i0 = i2 ? i0 : i1;
  switch (i0) {
    case 0: goto B26;
    case 1: goto B27;
    case 2: goto B28;
    case 3: goto B27;
    default: goto B26;
  }
  B28:;
  i0 = l9;
  i1 = 1u;
  i0 >>= (i1 & 31);
  l7 = i0;
  i0 = l9;
  i1 = 1u;
  i0 += i1;
  i1 = 1u;
  i0 >>= (i1 & 31);
  l10 = i0;
  goto B26;
  B27:;
  i0 = 0u;
  l10 = i0;
  i0 = l9;
  l7 = i0;
  B26:;
  i0 = l7;
  i1 = 1u;
  i0 += i1;
  l3 = i0;
  L30: 
    i0 = l3;
    i1 = 4294967295u;
    i0 += i1;
    l3 = i0;
    i0 = !(i0);
    if (i0) {goto B29;}
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    i1 = p0;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i2 = p0;
    i2 = i32_load((&memory), (u64)(i2 + 28));
    i2 = i32_load((&memory), (u64)(i2 + 16));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    i0 = !(i0);
    if (i0) {goto L30;}
  i0 = 1u;
  goto Bfunc;
  B29:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l9 = i0;
  i0 = 1u;
  l3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i3 = i32_load((&memory), (u64)(i3 + 28));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = l10;
  i1 = 1u;
  i0 += i1;
  l3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  l10 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  p0 = i0;
  L31: 
    i0 = l3;
    i1 = 4294967295u;
    i0 += i1;
    l3 = i0;
    if (i0) {goto B32;}
    i0 = 0u;
    goto Bfunc;
    B32:;
    i0 = p0;
    i1 = l9;
    i2 = l10;
    i2 = i32_load((&memory), (u64)(i2 + 16));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    i0 = !(i0);
    if (i0) {goto L31;}
  i0 = 1u;
  goto Bfunc;
  B0:;
  i0 = l3;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3str16slice_error_fail17h756d0528f966c096E(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4) {
  u32 l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 112u;
  i0 -= i1;
  l5 = i0;
  g0 = i0;
  i0 = l5;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l5;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = 1u;
  l6 = i0;
  i0 = p1;
  l7 = i0;
  i0 = p1;
  i1 = 257u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = 0u;
  i1 = p1;
  i0 -= i1;
  l8 = i0;
  i0 = 256u;
  l9 = i0;
  L1: 
    i0 = l9;
    i1 = p1;
    i0 = i0 >= i1;
    if (i0) {goto B2;}
    i0 = p0;
    i1 = l9;
    i0 += i1;
    i0 = i32_load8_s((&memory), (u64)(i0));
    i1 = 4294967231u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B2;}
    i0 = 0u;
    l6 = i0;
    i0 = l9;
    l7 = i0;
    goto B0;
    B2:;
    i0 = l9;
    i1 = 4294967295u;
    i0 += i1;
    l7 = i0;
    i0 = 0u;
    l6 = i0;
    i0 = l9;
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B0;}
    i0 = l8;
    i1 = l9;
    i0 += i1;
    l10 = i0;
    i0 = l7;
    l9 = i0;
    i0 = l10;
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto L1;}
  B0:;
  i0 = l5;
  i1 = l7;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = l5;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l5;
  i1 = 0u;
  i2 = 5u;
  i3 = l6;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0 + 28), i1);
  i0 = l5;
  i1 = 1057344u;
  i2 = 1058888u;
  i3 = l6;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = p2;
  i1 = p1;
  i0 = i0 > i1;
  l9 = i0;
  if (i0) {goto B6;}
  i0 = p3;
  i1 = p1;
  i0 = i0 > i1;
  if (i0) {goto B6;}
  i0 = p2;
  i1 = p3;
  i0 = i0 > i1;
  if (i0) {goto B5;}
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B8;}
  i0 = p1;
  i1 = p2;
  i0 = i0 == i1;
  if (i0) {goto B8;}
  i0 = p1;
  i1 = p2;
  i0 = i0 <= i1;
  if (i0) {goto B7;}
  i0 = p0;
  i1 = p2;
  i0 += i1;
  i0 = i32_load8_s((&memory), (u64)(i0));
  i1 = 4294967232u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B7;}
  B8:;
  i0 = p3;
  p2 = i0;
  B7:;
  i0 = l5;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = p2;
  i1 = p1;
  i0 = i0 == i1;
  if (i0) {goto B4;}
  i0 = p1;
  i1 = 1u;
  i0 += i1;
  l10 = i0;
  L9: 
    i0 = p2;
    i1 = p1;
    i0 = i0 >= i1;
    if (i0) {goto B10;}
    i0 = p0;
    i1 = p2;
    i0 += i1;
    i0 = i32_load8_s((&memory), (u64)(i0));
    i1 = 4294967232u;
    i0 = (u32)((s32)i0 >= (s32)i1);
    if (i0) {goto B4;}
    B10:;
    i0 = p2;
    i1 = 4294967295u;
    i0 += i1;
    l9 = i0;
    i0 = p2;
    i1 = 1u;
    i0 = i0 == i1;
    if (i0) {goto B3;}
    i0 = l10;
    i1 = p2;
    i0 = i0 == i1;
    l7 = i0;
    i0 = l9;
    p2 = i0;
    i0 = l7;
    i0 = !(i0);
    if (i0) {goto L9;}
    goto B3;
  B6:;
  i0 = l5;
  i1 = p2;
  i2 = p3;
  i3 = l9;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l5;
  i1 = 48u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 72u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 107u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 84u;
  i0 += i1;
  i1 = 107u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  j1 = 3ull;
  i64_store((&memory), (u64)(i0 + 52), j1);
  i0 = l5;
  i1 = 1058928u;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l5;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 76), i1);
  i0 = l5;
  i1 = l5;
  i2 = 72u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 64), i1);
  i0 = l5;
  i1 = l5;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 88), i1);
  i0 = l5;
  i1 = l5;
  i2 = 16u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 80), i1);
  i0 = l5;
  i1 = l5;
  i2 = 40u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l5;
  i1 = 48u;
  i0 += i1;
  i1 = p4;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  B5:;
  i0 = l5;
  i1 = 100u;
  i0 += i1;
  i1 = 107u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 72u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 107u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 84u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 48u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 4u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  j1 = 4ull;
  i64_store((&memory), (u64)(i0 + 52), j1);
  i0 = l5;
  i1 = 1058988u;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l5;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 76), i1);
  i0 = l5;
  i1 = l5;
  i2 = 72u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 64), i1);
  i0 = l5;
  i1 = l5;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 96), i1);
  i0 = l5;
  i1 = l5;
  i2 = 16u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 88), i1);
  i0 = l5;
  i1 = l5;
  i2 = 12u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 80), i1);
  i0 = l5;
  i1 = l5;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l5;
  i1 = 48u;
  i0 += i1;
  i1 = p4;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  B4:;
  i0 = p2;
  l9 = i0;
  B3:;
  i0 = l9;
  i1 = p1;
  i0 = i0 == i1;
  if (i0) {goto B11;}
  i0 = 1u;
  l7 = i0;
  i0 = p0;
  i1 = l9;
  i0 += i1;
  l10 = i0;
  i0 = i32_load8_s((&memory), (u64)(i0));
  p2 = i0;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 > (s32)i1);
  if (i0) {goto B15;}
  i0 = 0u;
  l6 = i0;
  i0 = p0;
  i1 = p1;
  i0 += i1;
  l7 = i0;
  p1 = i0;
  i0 = l10;
  i1 = 1u;
  i0 += i1;
  i1 = l7;
  i0 = i0 == i1;
  if (i0) {goto B16;}
  i0 = l10;
  i1 = 2u;
  i0 += i1;
  p1 = i0;
  i0 = l10;
  i0 = i32_load8_u((&memory), (u64)(i0 + 1));
  i1 = 63u;
  i0 &= i1;
  l6 = i0;
  B16:;
  i0 = p2;
  i1 = 31u;
  i0 &= i1;
  l10 = i0;
  i0 = p2;
  i1 = 255u;
  i0 &= i1;
  i1 = 223u;
  i0 = i0 > i1;
  if (i0) {goto B14;}
  i0 = l6;
  i1 = l10;
  i2 = 6u;
  i1 <<= (i2 & 31);
  i0 |= i1;
  p1 = i0;
  goto B13;
  B15:;
  i0 = l5;
  i1 = p2;
  i2 = 255u;
  i1 &= i2;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l5;
  i1 = 40u;
  i0 += i1;
  p2 = i0;
  goto B12;
  B14:;
  i0 = 0u;
  p0 = i0;
  i0 = l7;
  l8 = i0;
  i0 = p1;
  i1 = l7;
  i0 = i0 == i1;
  if (i0) {goto B17;}
  i0 = p1;
  i1 = 1u;
  i0 += i1;
  l8 = i0;
  i0 = p1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 63u;
  i0 &= i1;
  p0 = i0;
  B17:;
  i0 = p0;
  i1 = l6;
  i2 = 6u;
  i1 <<= (i2 & 31);
  i0 |= i1;
  p1 = i0;
  i0 = p2;
  i1 = 255u;
  i0 &= i1;
  i1 = 240u;
  i0 = i0 >= i1;
  if (i0) {goto B18;}
  i0 = p1;
  i1 = l10;
  i2 = 12u;
  i1 <<= (i2 & 31);
  i0 |= i1;
  p1 = i0;
  goto B13;
  B18:;
  i0 = 0u;
  p2 = i0;
  i0 = l8;
  i1 = l7;
  i0 = i0 == i1;
  if (i0) {goto B19;}
  i0 = l8;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 63u;
  i0 &= i1;
  p2 = i0;
  B19:;
  i0 = p1;
  i1 = 6u;
  i0 <<= (i1 & 31);
  i1 = l10;
  i2 = 18u;
  i1 <<= (i2 & 31);
  i2 = 1835008u;
  i1 &= i2;
  i0 |= i1;
  i1 = p2;
  i0 |= i1;
  p1 = i0;
  i1 = 1114112u;
  i0 = i0 == i1;
  if (i0) {goto B11;}
  B13:;
  i0 = l5;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = 1u;
  l7 = i0;
  i0 = l5;
  i1 = 40u;
  i0 += i1;
  p2 = i0;
  i0 = p1;
  i1 = 128u;
  i0 = i0 < i1;
  if (i0) {goto B12;}
  i0 = 2u;
  l7 = i0;
  i0 = p1;
  i1 = 2048u;
  i0 = i0 < i1;
  if (i0) {goto B12;}
  i0 = 3u;
  i1 = 4u;
  i2 = p1;
  i3 = 65536u;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l7 = i0;
  B12:;
  i0 = l5;
  i1 = l9;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l5;
  i1 = l7;
  i2 = l9;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l5;
  i1 = 48u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 5u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 108u;
  i0 += i1;
  i1 = 107u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 100u;
  i0 += i1;
  i1 = 107u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 72u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 108u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 84u;
  i0 += i1;
  i1 = 109u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  j1 = 5ull;
  i64_store((&memory), (u64)(i0 + 52), j1);
  i0 = l5;
  i1 = 1059072u;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l5;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 88), i1);
  i0 = l5;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 76), i1);
  i0 = l5;
  i1 = l5;
  i2 = 72u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 64), i1);
  i0 = l5;
  i1 = l5;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 104), i1);
  i0 = l5;
  i1 = l5;
  i2 = 16u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 96), i1);
  i0 = l5;
  i1 = l5;
  i2 = 36u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 80), i1);
  i0 = l5;
  i1 = l5;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l5;
  i1 = 48u;
  i0 += i1;
  i1 = p4;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  B11:;
  i0 = 1057529u;
  i1 = 43u;
  i2 = p4;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 1057600u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 1057344u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  rust_begin_unwind(i0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3fmt3num3imp52__LT_impl_u20_core__fmt__Display_u20_for_u20_u32_GT_3fmt17haffb72d949b13748E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j0;
  i0 = p0;
  j0 = i64_load32_u((&memory), (u64)(i0));
  i1 = 1u;
  i2 = p1;
  i0 = _ZN4core3fmt3num3imp7fmt_u6417h1d17ceced9d6225fE(j0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3num14from_str_radix17ha04c95ba4acb47c5E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0, l8 = 0;
  u64 l7 = 0, l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = l4;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p3;
  i1 = 4294967294u;
  i0 += i1;
  i1 = 34u;
  i0 = i0 > i1;
  if (i0) {goto B10;}
  i0 = p2;
  if (i0) {goto B11;}
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  goto B1;
  B11:;
  i0 = p1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 4294967253u;
  i0 += i1;
  l5 = i0;
  i1 = 2u;
  i0 = i0 > i1;
  if (i0) {goto B9;}
  i0 = 1u;
  l6 = i0;
  i0 = l5;
  switch (i0) {
    case 0: goto B12;
    case 1: goto B9;
    case 2: goto B13;
    default: goto B12;
  }
  B13:;
  i0 = 0u;
  l6 = i0;
  B12:;
  i0 = 1u;
  l5 = i0;
  i0 = p2;
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B7;}
  i0 = p1;
  i1 = 1u;
  i0 += i1;
  l5 = i0;
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B14;}
  i0 = p1;
  i1 = p2;
  i0 += i1;
  l6 = i0;
  i0 = l5;
  p1 = i0;
  goto B8;
  B14:;
  i0 = p3;
  i1 = 11u;
  i0 = i0 < i1;
  if (i0) {goto B6;}
  i0 = p2;
  i1 = 4294967295u;
  i0 += i1;
  l6 = i0;
  i0 = 0u;
  p2 = i0;
  i0 = p3;
  j0 = (u64)(s64)(s32)(i0);
  l7 = j0;
  L15: 
    i0 = l6;
    i0 = !(i0);
    if (i0) {goto B3;}
    i0 = l5;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l8 = i0;
    i1 = 4294967248u;
    i0 += i1;
    p1 = i0;
    i1 = 10u;
    i0 = i0 < i1;
    if (i0) {goto B16;}
    i0 = l8;
    i1 = 4294967199u;
    i0 += i1;
    i1 = 26u;
    i0 = i0 < i1;
    if (i0) {goto B17;}
    i0 = l8;
    i1 = 4294967231u;
    i0 += i1;
    i1 = 26u;
    i0 = i0 >= i1;
    if (i0) {goto B5;}
    i0 = l8;
    i1 = 4294967241u;
    i0 += i1;
    p1 = i0;
    goto B16;
    B17:;
    i0 = l8;
    i1 = 4294967209u;
    i0 += i1;
    p1 = i0;
    B16:;
    i0 = p1;
    i1 = p3;
    i0 = i0 >= i1;
    if (i0) {goto B5;}
    i0 = p2;
    j0 = (u64)(s64)(s32)(i0);
    j1 = l7;
    j0 *= j1;
    l9 = j0;
    j1 = 32ull;
    j0 >>= (j1 & 63);
    i0 = (u32)(j0);
    j1 = l9;
    i1 = (u32)(j1);
    p2 = i1;
    i2 = 31u;
    i1 = (u32)((s32)i1 >> (i2 & 31));
    i0 = i0 != i1;
    if (i0) {goto B2;}
    i0 = l5;
    i1 = 1u;
    i0 += i1;
    l5 = i0;
    i0 = l6;
    i1 = 4294967295u;
    i0 += i1;
    l6 = i0;
    i0 = p2;
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    l8 = i0;
    i1 = p1;
    i2 = 4294967295u;
    i1 = (u32)((s32)i1 > (s32)i2);
    i0 = i0 != i1;
    i1 = l8;
    i2 = p2;
    i3 = p1;
    i2 -= i3;
    p2 = i2;
    i3 = 4294967295u;
    i2 = (u32)((s32)i2 > (s32)i3);
    i1 = i1 != i2;
    i0 &= i1;
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto L15;}
    goto B4;
  B10:;
  i0 = l4;
  i1 = 36u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 20), j1);
  i0 = l4;
  i1 = 1057408u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l4;
  i1 = 3u;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l4;
  i1 = l4;
  i2 = 40u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l4;
  i1 = l4;
  i2 = 12u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = 1057440u;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  B9:;
  i0 = p1;
  i1 = p2;
  i0 += i1;
  l6 = i0;
  B8:;
  i0 = p3;
  i1 = 11u;
  i0 = i0 < i1;
  if (i0) {goto B20;}
  i0 = 0u;
  p2 = i0;
  i0 = p3;
  j0 = (u64)(s64)(s32)(i0);
  l7 = j0;
  L21: 
    i0 = l6;
    i1 = p1;
    i0 = i0 == i1;
    if (i0) {goto B3;}
    i0 = p1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l8 = i0;
    i1 = 4294967248u;
    i0 += i1;
    l5 = i0;
    i1 = 10u;
    i0 = i0 < i1;
    if (i0) {goto B22;}
    i0 = l8;
    i1 = 4294967199u;
    i0 += i1;
    i1 = 26u;
    i0 = i0 < i1;
    if (i0) {goto B23;}
    i0 = l8;
    i1 = 4294967231u;
    i0 += i1;
    i1 = 26u;
    i0 = i0 >= i1;
    if (i0) {goto B5;}
    i0 = l8;
    i1 = 4294967241u;
    i0 += i1;
    l5 = i0;
    goto B22;
    B23:;
    i0 = l8;
    i1 = 4294967209u;
    i0 += i1;
    l5 = i0;
    B22:;
    i0 = l5;
    i1 = p3;
    i0 = i0 >= i1;
    if (i0) {goto B5;}
    i0 = p2;
    j0 = (u64)(s64)(s32)(i0);
    j1 = l7;
    j0 *= j1;
    l9 = j0;
    j1 = 32ull;
    j0 >>= (j1 & 63);
    i0 = (u32)(j0);
    j1 = l9;
    i1 = (u32)(j1);
    p2 = i1;
    i2 = 31u;
    i1 = (u32)((s32)i1 >> (i2 & 31));
    i0 = i0 != i1;
    if (i0) {goto B19;}
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    p1 = i0;
    i0 = p2;
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    l8 = i0;
    i1 = l5;
    i2 = 4294967295u;
    i1 = (u32)((s32)i1 > (s32)i2);
    i0 = i0 == i1;
    i1 = l8;
    i2 = p2;
    i3 = l5;
    i2 += i3;
    p2 = i2;
    i3 = 4294967295u;
    i2 = (u32)((s32)i2 > (s32)i3);
    i1 = i1 != i2;
    i0 &= i1;
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto L21;}
    goto B18;
  B20:;
  i0 = 0u;
  p2 = i0;
  i0 = p3;
  j0 = (u64)(s64)(s32)(i0);
  l7 = j0;
  L24: 
    i0 = l6;
    i1 = p1;
    i0 = i0 == i1;
    if (i0) {goto B3;}
    i0 = p1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 4294967248u;
    i0 += i1;
    l5 = i0;
    i1 = 9u;
    i0 = i0 > i1;
    if (i0) {goto B5;}
    i0 = l5;
    i1 = p3;
    i0 = i0 >= i1;
    if (i0) {goto B5;}
    i0 = p2;
    j0 = (u64)(s64)(s32)(i0);
    j1 = l7;
    j0 *= j1;
    l9 = j0;
    j1 = 32ull;
    j0 >>= (j1 & 63);
    i0 = (u32)(j0);
    j1 = l9;
    i1 = (u32)(j1);
    p2 = i1;
    i2 = 31u;
    i1 = (u32)((s32)i1 >> (i2 & 31));
    i0 = i0 != i1;
    if (i0) {goto B19;}
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    p1 = i0;
    i0 = p2;
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    l8 = i0;
    i1 = l5;
    i2 = 4294967295u;
    i1 = (u32)((s32)i1 > (s32)i2);
    i0 = i0 == i1;
    i1 = l8;
    i2 = p2;
    i3 = l5;
    i2 += i3;
    p2 = i2;
    i3 = 4294967295u;
    i2 = (u32)((s32)i2 > (s32)i3);
    i1 = i1 != i2;
    i0 &= i1;
    i0 = !(i0);
    if (i0) {goto L24;}
    goto B18;
  B19:;
  i0 = p0;
  i1 = 2u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  goto B1;
  B18:;
  i0 = p0;
  i1 = 2u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  goto B1;
  B7:;
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  goto B0;
  B6:;
  i0 = p2;
  i1 = 4294967295u;
  i0 += i1;
  l6 = i0;
  i0 = 0u;
  p2 = i0;
  i0 = p3;
  j0 = (u64)(s64)(s32)(i0);
  l7 = j0;
  L25: 
    i0 = l6;
    i0 = !(i0);
    if (i0) {goto B3;}
    i0 = l5;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 4294967248u;
    i0 += i1;
    p1 = i0;
    i1 = 9u;
    i0 = i0 > i1;
    if (i0) {goto B5;}
    i0 = p1;
    i1 = p3;
    i0 = i0 >= i1;
    if (i0) {goto B5;}
    i0 = p2;
    j0 = (u64)(s64)(s32)(i0);
    j1 = l7;
    j0 *= j1;
    l9 = j0;
    j1 = 32ull;
    j0 >>= (j1 & 63);
    i0 = (u32)(j0);
    j1 = l9;
    i1 = (u32)(j1);
    p2 = i1;
    i2 = 31u;
    i1 = (u32)((s32)i1 >> (i2 & 31));
    i0 = i0 != i1;
    if (i0) {goto B2;}
    i0 = l5;
    i1 = 1u;
    i0 += i1;
    l5 = i0;
    i0 = l6;
    i1 = 4294967295u;
    i0 += i1;
    l6 = i0;
    i0 = p2;
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    l8 = i0;
    i1 = p1;
    i2 = 4294967295u;
    i1 = (u32)((s32)i1 > (s32)i2);
    i0 = i0 != i1;
    i1 = l8;
    i2 = p2;
    i3 = p1;
    i2 -= i3;
    p2 = i2;
    i3 = 4294967295u;
    i2 = (u32)((s32)i2 > (s32)i3);
    i1 = i1 != i2;
    i0 &= i1;
    i0 = !(i0);
    if (i0) {goto L25;}
    goto B4;
  B5:;
  i0 = 1u;
  l5 = i0;
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  goto B0;
  B4:;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  goto B1;
  B3:;
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 0u;
  l5 = i0;
  goto B0;
  B2:;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  B1:;
  i0 = 1u;
  l5 = i0;
  B0:;
  i0 = p0;
  i1 = l5;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3fmt5write17h4834d85ce1be7131E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, 
      l11 = 0, l12 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = 36u;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0 + 40), i1);
  i0 = l3;
  j1 = 137438953472ull;
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = 0u;
  l4 = i0;
  i0 = l3;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l3;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l7 = i0;
  i1 = p2;
  i2 = 12u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l8 = i1;
  i2 = l8;
  i3 = l7;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l9 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p2;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l10 = i0;
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l11 = i0;
  i0 = 1u;
  l8 = i0;
  i0 = p0;
  i1 = l6;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = l6;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i3 = p1;
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = l6;
  i1 = 12u;
  i0 += i1;
  p2 = i0;
  i0 = 1u;
  l4 = i0;
  L6: 
    i0 = l3;
    i1 = l5;
    i2 = 4u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0 + 12), i1);
    i0 = l3;
    i1 = l5;
    i2 = 28u;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0 + 40), i1);
    i0 = l3;
    i1 = l5;
    i2 = 8u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0 + 8), i1);
    i0 = l5;
    i1 = 24u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    l8 = i0;
    i0 = 0u;
    p1 = i0;
    i0 = 0u;
    p0 = i0;
    i0 = l5;
    i1 = 20u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    switch (i0) {
      case 0: goto B8;
      case 1: goto B9;
      case 2: goto B7;
      default: goto B8;
    }
    B9:;
    i0 = l8;
    i1 = l10;
    i0 = i0 >= i1;
    if (i0) {goto B5;}
    i0 = l8;
    i1 = 3u;
    i0 <<= (i1 & 31);
    l12 = i0;
    i0 = 0u;
    p0 = i0;
    i0 = l11;
    i1 = l12;
    i0 += i1;
    l12 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i1 = 110u;
    i0 = i0 != i1;
    if (i0) {goto B7;}
    i0 = l12;
    i0 = i32_load((&memory), (u64)(i0));
    i0 = i32_load((&memory), (u64)(i0));
    l8 = i0;
    B8:;
    i0 = 1u;
    p0 = i0;
    B7:;
    i0 = l3;
    i1 = l8;
    i32_store((&memory), (u64)(i0 + 20), i1);
    i0 = l3;
    i1 = p0;
    i32_store((&memory), (u64)(i0 + 16), i1);
    i0 = l5;
    i1 = 16u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    l8 = i0;
    i0 = l5;
    i1 = 12u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    switch (i0) {
      case 0: goto B11;
      case 1: goto B12;
      case 2: goto B10;
      default: goto B11;
    }
    B12:;
    i0 = l8;
    i1 = l10;
    i0 = i0 >= i1;
    if (i0) {goto B4;}
    i0 = l8;
    i1 = 3u;
    i0 <<= (i1 & 31);
    p0 = i0;
    i0 = l11;
    i1 = p0;
    i0 += i1;
    p0 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i1 = 110u;
    i0 = i0 != i1;
    if (i0) {goto B10;}
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0));
    i0 = i32_load((&memory), (u64)(i0));
    l8 = i0;
    B11:;
    i0 = 1u;
    p1 = i0;
    B10:;
    i0 = l3;
    i1 = l8;
    i32_store((&memory), (u64)(i0 + 28), i1);
    i0 = l3;
    i1 = p1;
    i32_store((&memory), (u64)(i0 + 24), i1);
    i0 = l5;
    i0 = i32_load((&memory), (u64)(i0));
    l8 = i0;
    i1 = l10;
    i0 = i0 >= i1;
    if (i0) {goto B13;}
    i0 = l11;
    i1 = l8;
    i2 = 3u;
    i1 <<= (i2 & 31);
    i0 += i1;
    l8 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l3;
    i2 = 8u;
    i1 += i2;
    i2 = l8;
    i2 = i32_load((&memory), (u64)(i2 + 4));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    if (i0) {goto B1;}
    i0 = l4;
    i1 = l9;
    i0 = i0 >= i1;
    if (i0) {goto B2;}
    i0 = p2;
    i1 = 4294967292u;
    i0 += i1;
    p0 = i0;
    i0 = p2;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = p2;
    i1 = 8u;
    i0 += i1;
    p2 = i0;
    i0 = l5;
    i1 = 32u;
    i0 += i1;
    l5 = i0;
    i0 = 1u;
    l8 = i0;
    i0 = l4;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 32));
    i1 = p0;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = p1;
    i3 = l3;
    i3 = i32_load((&memory), (u64)(i3 + 36));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
    i0 = !(i0);
    if (i0) {goto L6;}
    goto B0;
    B13:;
  i0 = l8;
  i1 = l10;
  i2 = 1058068u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  B5:;
  i0 = l8;
  i1 = l10;
  i2 = 1058084u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  B4:;
  i0 = l8;
  i1 = l10;
  i2 = 1058084u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  B3:;
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l7 = i0;
  i1 = p2;
  i2 = 20u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i2 = l5;
  i3 = l7;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l10 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l5 = i0;
  i0 = 1u;
  l8 = i0;
  i0 = p0;
  i1 = l6;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = l6;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i3 = p1;
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = l6;
  i1 = 12u;
  i0 += i1;
  p2 = i0;
  i0 = 1u;
  l4 = i0;
  L14: 
    i0 = l5;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l3;
    i2 = 8u;
    i1 += i2;
    i2 = l5;
    i3 = 4u;
    i2 += i3;
    i2 = i32_load((&memory), (u64)(i2));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    if (i0) {goto B1;}
    i0 = l4;
    i1 = l10;
    i0 = i0 >= i1;
    if (i0) {goto B2;}
    i0 = p2;
    i1 = 4294967292u;
    i0 += i1;
    p0 = i0;
    i0 = p2;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = p2;
    i1 = 8u;
    i0 += i1;
    p2 = i0;
    i0 = l5;
    i1 = 8u;
    i0 += i1;
    l5 = i0;
    i0 = 1u;
    l8 = i0;
    i0 = l4;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 32));
    i1 = p0;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = p1;
    i3 = l3;
    i3 = i32_load((&memory), (u64)(i3 + 36));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
    i0 = !(i0);
    if (i0) {goto L14;}
    goto B0;
  B2:;
  i0 = l7;
  i1 = l4;
  i0 = i0 <= i1;
  if (i0) {goto B15;}
  i0 = 1u;
  l8 = i0;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 32));
  i1 = l6;
  i2 = l4;
  i3 = 3u;
  i2 <<= (i3 & 31);
  i1 += i2;
  l5 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = l5;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i3 = l3;
  i3 = i32_load((&memory), (u64)(i3 + 36));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  B15:;
  i0 = 0u;
  l8 = i0;
  goto B0;
  B1:;
  i0 = 1u;
  l8 = i0;
  B0:;
  i0 = l3;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  i0 = l8;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN71__LT_core__ops__range__Range_LT_Idx_GT__u20_as_u20_core__fmt__Debug_GT_3fmt17h560d60a49501f432E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i1 = p1;
  i0 = _ZN4core3fmt3num52__LT_impl_u20_core__fmt__Debug_u20_for_u20_usize_GT_3fmt17hd9e5ee56a3abf985E(i0, i1);
  if (i0) {goto B1;}
  i0 = p1;
  i1 = 28u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l4 = i0;
  i0 = l2;
  i1 = 28u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1057344u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 12), j1);
  i0 = l2;
  i1 = 1057460u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l4;
  i1 = l3;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  i0 = !(i0);
  if (i0) {goto B0;}
  B1:;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = 1u;
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = p1;
  i0 = _ZN4core3fmt3num52__LT_impl_u20_core__fmt__Debug_u20_for_u20_usize_GT_3fmt17hd9e5ee56a3abf985E(i0, i1);
  p1 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt3num52__LT_impl_u20_core__fmt__Debug_u20_for_u20_usize_GT_3fmt17hd9e5ee56a3abf985E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  u64 j0;
  i0 = g0;
  i1 = 128u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i1 = 16u;
  i0 &= i1;
  if (i0) {goto B4;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i0 = l3;
  i1 = 32u;
  i0 &= i1;
  if (i0) {goto B3;}
  i0 = l4;
  j0 = (u64)(i0);
  i1 = 1u;
  i2 = p1;
  i0 = _ZN4core3fmt3num3imp7fmt_u6417h1d17ceced9d6225fE(j0, i1, i2);
  p0 = i0;
  goto B2;
  B4:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i0 = 0u;
  p0 = i0;
  L5: 
    i0 = l2;
    i1 = p0;
    i0 += i1;
    i1 = 127u;
    i0 += i1;
    i1 = l4;
    i2 = 15u;
    i1 &= i2;
    l3 = i1;
    i2 = 48u;
    i1 |= i2;
    i2 = l3;
    i3 = 87u;
    i2 += i3;
    i3 = l3;
    i4 = 10u;
    i3 = i3 < i4;
    i1 = i3 ? i1 : i2;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4294967295u;
    i0 += i1;
    p0 = i0;
    i0 = l4;
    i1 = 4u;
    i0 >>= (i1 & 31);
    l4 = i0;
    if (i0) {goto L5;}
  i0 = p0;
  i1 = 128u;
  i0 += i1;
  l4 = i0;
  i1 = 129u;
  i0 = i0 >= i1;
  if (i0) {goto B1;}
  i0 = p1;
  i1 = 1u;
  i2 = 1057816u;
  i3 = 2u;
  i4 = l2;
  i5 = p0;
  i4 += i5;
  i5 = 128u;
  i4 += i5;
  i5 = 0u;
  i6 = p0;
  i5 -= i6;
  i0 = _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(i0, i1, i2, i3, i4, i5);
  p0 = i0;
  goto B2;
  B3:;
  i0 = 0u;
  p0 = i0;
  L6: 
    i0 = l2;
    i1 = p0;
    i0 += i1;
    i1 = 127u;
    i0 += i1;
    i1 = l4;
    i2 = 15u;
    i1 &= i2;
    l3 = i1;
    i2 = 48u;
    i1 |= i2;
    i2 = l3;
    i3 = 55u;
    i2 += i3;
    i3 = l3;
    i4 = 10u;
    i3 = i3 < i4;
    i1 = i3 ? i1 : i2;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4294967295u;
    i0 += i1;
    p0 = i0;
    i0 = l4;
    i1 = 4u;
    i0 >>= (i1 & 31);
    l4 = i0;
    if (i0) {goto L6;}
  i0 = p0;
  i1 = 128u;
  i0 += i1;
  l4 = i0;
  i1 = 129u;
  i0 = i0 >= i1;
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 1u;
  i2 = 1057816u;
  i3 = 2u;
  i4 = l2;
  i5 = p0;
  i4 += i5;
  i5 = 128u;
  i4 += i5;
  i5 = 0u;
  i6 = p0;
  i5 -= i6;
  i0 = _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(i0, i1, i2, i3, i4, i5);
  p0 = i0;
  B2:;
  i0 = l2;
  i1 = 128u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  goto Bfunc;
  B1:;
  i0 = l4;
  i1 = 128u;
  i2 = 1057800u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l4;
  i1 = 128u;
  i2 = 1057800u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u64 _ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h21038e7fd8af2881E(u32 p0) {
  FUNC_PROLOGUE;
  u64 j0;
  j0 = 12613753443797613946ull;
  FUNC_EPILOGUE;
  return j0;
}

static void _ZN4core5ascii14escape_default17h0c71e6816c4ab86eE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = 2u;
  l2 = i0;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  l3 = i0;
  i1 = 4294967287u;
  i0 += i1;
  l4 = i0;
  i1 = 30u;
  i0 = i0 <= i1;
  if (i0) {goto B2;}
  i0 = l3;
  i1 = 92u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = 23644u;
  l3 = i0;
  goto B0;
  B2:;
  i0 = 29788u;
  l3 = i0;
  i0 = l4;
  switch (i0) {
    case 0: goto B0;
    case 1: goto B4;
    case 2: goto B1;
    case 3: goto B1;
    case 4: goto B3;
    case 5: goto B1;
    case 6: goto B1;
    case 7: goto B1;
    case 8: goto B1;
    case 9: goto B1;
    case 10: goto B1;
    case 11: goto B1;
    case 12: goto B1;
    case 13: goto B1;
    case 14: goto B1;
    case 15: goto B1;
    case 16: goto B1;
    case 17: goto B1;
    case 18: goto B1;
    case 19: goto B1;
    case 20: goto B1;
    case 21: goto B1;
    case 22: goto B1;
    case 23: goto B1;
    case 24: goto B1;
    case 25: goto B6;
    case 26: goto B1;
    case 27: goto B1;
    case 28: goto B1;
    case 29: goto B1;
    case 30: goto B5;
    default: goto B0;
  }
  B6:;
  i0 = 8796u;
  l3 = i0;
  goto B0;
  B5:;
  i0 = 10076u;
  l3 = i0;
  goto B0;
  B4:;
  i0 = 28252u;
  l3 = i0;
  goto B0;
  B3:;
  i0 = 29276u;
  l3 = i0;
  goto B0;
  B1:;
  i0 = p1;
  i1 = 4294967264u;
  i0 += i1;
  i1 = 255u;
  i0 &= i1;
  i1 = 95u;
  i0 = i0 < i1;
  if (i0) {goto B7;}
  i0 = 4u;
  l2 = i0;
  i0 = 48u;
  i1 = 87u;
  i2 = p1;
  i3 = 255u;
  i2 &= i3;
  l3 = i2;
  i3 = 160u;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  i1 = l3;
  i2 = 4u;
  i1 >>= (i2 & 31);
  i0 += i1;
  i1 = 16u;
  i0 <<= (i1 & 31);
  i1 = 48u;
  i2 = 87u;
  i3 = p1;
  i4 = 15u;
  i3 &= i4;
  l3 = i3;
  i4 = 10u;
  i3 = i3 < i4;
  i1 = i3 ? i1 : i2;
  i2 = l3;
  i1 += i2;
  i2 = 24u;
  i1 <<= (i2 & 31);
  i0 |= i1;
  i1 = 30812u;
  i0 |= i1;
  l3 = i0;
  goto B0;
  B7:;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  l3 = i0;
  i0 = 1u;
  l2 = i0;
  B0:;
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN85__LT_core__ascii__EscapeDefault_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17h75372c571a88c631E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = 0u;
  l3 = i0;
  goto B1;
  B2:;
  i0 = 1u;
  l3 = i0;
  i0 = p1;
  i1 = l2;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 4u;
  i0 = i0 >= i1;
  if (i0) {goto B0;}
  i0 = p1;
  i1 = l2;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  p1 = i0;
  B1:;
  i0 = p0;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = p0;
  i1 = l3;
  i32_store8((&memory), (u64)(i0), i1);
  goto Bfunc;
  B0:;
  i0 = l2;
  i1 = 4u;
  i2 = 1057488u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 _ZN60__LT_core__cell__BorrowError_u20_as_u20_core__fmt__Debug_GT_3fmt17hdfa14f22cbd9ae5fE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057504u;
  i2 = 11u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN63__LT_core__cell__BorrowMutError_u20_as_u20_core__fmt__Debug_GT_3fmt17h888db12a3966bea9E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057515u;
  i2 = 14u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN82__LT_core__char__EscapeDebug_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17h31831fc6cb32f772E(u32 p0) {
  u32 l1 = 0, l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = 1114112u;
  l1 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  switch (i0) {
    case 0: goto B0;
    case 1: goto B1;
    case 2: goto B2;
    case 3: goto B3;
    default: goto B0;
  }
  B3:;
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  switch (i0) {
    case 0: goto B0;
    case 1: goto B4;
    case 2: goto B5;
    case 3: goto B6;
    case 4: goto B7;
    case 5: goto B8;
    default: goto B0;
  }
  B8:;
  i0 = p0;
  i1 = 4u;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 92u;
  goto Bfunc;
  B7:;
  i0 = p0;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 117u;
  goto Bfunc;
  B6:;
  i0 = p0;
  i1 = 2u;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 123u;
  goto Bfunc;
  B5:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = 28u;
  i1 &= i2;
  i0 >>= (i1 & 31);
  i1 = 15u;
  i0 &= i1;
  l1 = i0;
  i1 = 48u;
  i0 |= i1;
  i1 = l1;
  i2 = 87u;
  i1 += i2;
  i2 = l1;
  i3 = 10u;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l1 = i0;
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = p0;
  i1 = l2;
  i2 = 4294967295u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l1;
  goto Bfunc;
  B9:;
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l1;
  goto Bfunc;
  B4:;
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 125u;
  goto Bfunc;
  B2:;
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 92u;
  goto Bfunc;
  B1:;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l1 = i0;
  B0:;
  i0 = l1;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt8builders11DebugStruct5field17h8526abf557e6a496E(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4) {
  u32 l5 = 0, l6 = 0, l7 = 0, l8 = 0;
  u64 l9 = 0, l10 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l5 = i0;
  g0 = i0;
  i0 = 1u;
  l6 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 5));
  l7 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l8 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 4u;
  i0 &= i1;
  if (i0) {goto B1;}
  i0 = 1u;
  l6 = i0;
  i0 = l8;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057745u;
  i2 = 1057747u;
  i3 = l7;
  i4 = 255u;
  i3 &= i4;
  l7 = i3;
  i1 = i3 ? i1 : i2;
  i2 = 2u;
  i3 = 3u;
  i4 = l7;
  i2 = i4 ? i2 : i3;
  i3 = l8;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = 1u;
  l6 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l8 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p2;
  i3 = l8;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = 1u;
  l6 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l8 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057580u;
  i2 = 2u;
  i3 = l8;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = p3;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p4;
  i2 = i32_load((&memory), (u64)(i2 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  l6 = i0;
  goto B0;
  B1:;
  i0 = l7;
  i1 = 255u;
  i0 &= i1;
  if (i0) {goto B2;}
  i0 = 1u;
  l6 = i0;
  i0 = l8;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057740u;
  i2 = 3u;
  i3 = l8;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l8 = i0;
  B2:;
  i0 = 1u;
  l6 = i0;
  i0 = l5;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 23), i1);
  i0 = l5;
  i1 = 52u;
  i0 += i1;
  i1 = 1057712u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = l8;
  j1 = i64_load((&memory), (u64)(i1 + 24));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l5;
  i1 = l5;
  i2 = 23u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l8;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l9 = j0;
  i0 = l8;
  j0 = i64_load((&memory), (u64)(i0 + 16));
  l10 = j0;
  i0 = l5;
  i1 = l8;
  i1 = i32_load8_u((&memory), (u64)(i1 + 32));
  i32_store8((&memory), (u64)(i0 + 56), i1);
  i0 = l5;
  j1 = l10;
  i64_store((&memory), (u64)(i0 + 40), j1);
  i0 = l5;
  j1 = l9;
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = l5;
  i1 = l8;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l5;
  i1 = l5;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l5;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = p2;
  i0 = _ZN68__LT_core__fmt__builders__PadAdapter_u20_as_u20_core__fmt__Write_GT_9write_str17hb63bd9b52d2ea355E(i0, i1, i2);
  if (i0) {goto B0;}
  i0 = l5;
  i1 = 8u;
  i0 += i1;
  i1 = 1057580u;
  i2 = 2u;
  i0 = _ZN68__LT_core__fmt__builders__PadAdapter_u20_as_u20_core__fmt__Write_GT_9write_str17hb63bd9b52d2ea355E(i0, i1, i2);
  if (i0) {goto B0;}
  i0 = p3;
  i1 = l5;
  i2 = 24u;
  i1 += i2;
  i2 = p4;
  i2 = i32_load((&memory), (u64)(i2 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  if (i0) {goto B0;}
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  i1 = 1057743u;
  i2 = 2u;
  i3 = l5;
  i3 = i32_load((&memory), (u64)(i3 + 52));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l6 = i0;
  B0:;
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = p0;
  i1 = l6;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l5;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core6option13expect_failed17hdd81bfbb4998aefaE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = 36u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 20), j1);
  i0 = l3;
  i1 = 1057572u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l3;
  i1 = 107u;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l3;
  i1 = l3;
  i2 = 40u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l3;
  i1 = l3;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  i1 = p2;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17ha84d8cd9be8910c1E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p1;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i0 = _ZN4core3fmt9Formatter3pad17h18e6ccc150f9bfbcE(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core6option18expect_none_failed17habae0dd01495a6a7E(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4) {
  u32 l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l5 = i0;
  g0 = i0;
  i0 = l5;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l5;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l5;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = l5;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l5;
  i1 = 44u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 60u;
  i0 += i1;
  i1 = 111u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 28), j1);
  i0 = l5;
  i1 = 1057584u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l5;
  i1 = 107u;
  i32_store((&memory), (u64)(i0 + 52), i1);
  i0 = l5;
  i1 = l5;
  i2 = 48u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l5;
  i1 = l5;
  i2 = 16u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l5;
  i1 = l5;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l5;
  i1 = 24u;
  i0 += i1;
  i1 = p4;
  _ZN4core9panicking9panic_fmt17hdd2ab611a748a491E(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17hb3a7d31ca8f59d32E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i2 = i32_load((&memory), (u64)(i2 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core5panic9PanicInfo7message17h92bd97d427b892e1E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core5panic9PanicInfo8location17hadae980b9a5e60d2E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core5panic8Location6caller17ha977844962a520efE(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core5panic8Location4file17hd78f3cde5f346820E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  u64 j1;
  i0 = p0;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  FUNC_EPILOGUE;
}

static u32 _ZN60__LT_core__panic__Location_u20_as_u20_core__fmt__Display_GT_3fmt17h5a11f7908f87d86dE(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 20u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 12u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 107u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = p0;
  i2 = 12u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p1;
  i1 = 28u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  p1 = i0;
  i0 = l2;
  i1 = 24u;
  i0 += i1;
  i1 = 20u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  j1 = 3ull;
  i64_store((&memory), (u64)(i0 + 28), j1);
  i0 = l2;
  i1 = 1057620u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l2;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = p1;
  i1 = p0;
  i2 = l2;
  i3 = 24u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p0 = i0;
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN68__LT_core__fmt__builders__PadAdapter_u20_as_u20_core__fmt__Write_GT_9write_str17hb63bd9b52d2ea355E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = p2;
  if (i0) {goto B1;}
  i0 = 0u;
  l4 = i0;
  goto B0;
  B1:;
  i0 = l3;
  i1 = 40u;
  i0 += i1;
  l5 = i0;
  L6: 
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    i0 = i32_load8_u((&memory), (u64)(i0));
    i0 = !(i0);
    if (i0) {goto B7;}
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = 1057736u;
    i2 = 4u;
    i3 = p0;
    i3 = i32_load((&memory), (u64)(i3 + 4));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
    if (i0) {goto B2;}
    B7:;
    i0 = l3;
    i1 = 10u;
    i32_store((&memory), (u64)(i0 + 40), i1);
    i0 = l3;
    j1 = 4294967306ull;
    i64_store((&memory), (u64)(i0 + 32), j1);
    i0 = l3;
    i1 = p2;
    i32_store((&memory), (u64)(i0 + 28), i1);
    i0 = l3;
    i1 = 0u;
    i32_store((&memory), (u64)(i0 + 24), i1);
    i0 = l3;
    i1 = p2;
    i32_store((&memory), (u64)(i0 + 20), i1);
    i0 = l3;
    i1 = p1;
    i32_store((&memory), (u64)(i0 + 16), i1);
    i0 = l3;
    i1 = 8u;
    i0 += i1;
    i1 = 10u;
    i2 = p1;
    i3 = p2;
    _ZN4core5slice6memchr6memchr17h4b6f86a8dda0136aE(i0, i1, i2, i3);
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B11;}
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 12));
    l4 = i0;
    L12: 
      i0 = l3;
      i1 = l4;
      i2 = l3;
      i2 = i32_load((&memory), (u64)(i2 + 24));
      i1 += i2;
      i2 = 1u;
      i1 += i2;
      l4 = i1;
      i32_store((&memory), (u64)(i0 + 24), i1);
      i0 = l4;
      i1 = l3;
      i1 = i32_load((&memory), (u64)(i1 + 36));
      l6 = i1;
      i0 = i0 >= i1;
      if (i0) {goto B14;}
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 20));
      l7 = i0;
      goto B13;
      B14:;
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 20));
      l7 = i0;
      i1 = l4;
      i0 = i0 < i1;
      if (i0) {goto B13;}
      i0 = l6;
      i1 = 5u;
      i0 = i0 >= i1;
      if (i0) {goto B5;}
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 16));
      i1 = l4;
      i2 = l6;
      i1 -= i2;
      l8 = i1;
      i0 += i1;
      l9 = i0;
      i1 = l5;
      i0 = i0 == i1;
      if (i0) {goto B9;}
      i0 = l9;
      i1 = l5;
      i2 = l6;
      i0 = memcmp_0(i0, i1, i2);
      i0 = !(i0);
      if (i0) {goto B9;}
      B13:;
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 28));
      l9 = i0;
      i1 = l4;
      i0 = i0 < i1;
      if (i0) {goto B10;}
      i0 = l7;
      i1 = l9;
      i0 = i0 < i1;
      if (i0) {goto B10;}
      i0 = l3;
      i1 = l6;
      i2 = l3;
      i3 = 16u;
      i2 += i3;
      i1 += i2;
      i2 = 23u;
      i1 += i2;
      i1 = i32_load8_u((&memory), (u64)(i1));
      i2 = l3;
      i2 = i32_load((&memory), (u64)(i2 + 16));
      i3 = l4;
      i2 += i3;
      i3 = l9;
      i4 = l4;
      i3 -= i4;
      _ZN4core5slice6memchr6memchr17h4b6f86a8dda0136aE(i0, i1, i2, i3);
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0 + 4));
      l4 = i0;
      i0 = l3;
      i0 = i32_load((&memory), (u64)(i0));
      i1 = 1u;
      i0 = i0 == i1;
      if (i0) {goto L12;}
    B11:;
    i0 = l3;
    i1 = l3;
    i1 = i32_load((&memory), (u64)(i1 + 28));
    i32_store((&memory), (u64)(i0 + 24), i1);
    B10:;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    i1 = 0u;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p2;
    l4 = i0;
    goto B8;
    B9:;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    i1 = 1u;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = l8;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    B8:;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l9 = i0;
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    i0 = l4;
    i0 = !(i0);
    i1 = p2;
    i2 = l4;
    i1 = i1 == i2;
    i0 |= i1;
    l7 = i0;
    if (i0) {goto B15;}
    i0 = p2;
    i1 = l4;
    i0 = i0 <= i1;
    if (i0) {goto B4;}
    i0 = p1;
    i1 = l4;
    i0 += i1;
    i0 = i32_load8_s((&memory), (u64)(i0));
    i1 = 4294967231u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B4;}
    B15:;
    i0 = l6;
    i1 = p1;
    i2 = l4;
    i3 = l9;
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
    if (i0) {goto B2;}
    i0 = l7;
    if (i0) {goto B16;}
    i0 = p2;
    i1 = l4;
    i0 = i0 <= i1;
    if (i0) {goto B3;}
    i0 = p1;
    i1 = l4;
    i0 += i1;
    i0 = i32_load8_s((&memory), (u64)(i0));
    i1 = 4294967231u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B3;}
    B16:;
    i0 = p1;
    i1 = l4;
    i0 += i1;
    p1 = i0;
    i0 = p2;
    i1 = l4;
    i0 -= i1;
    p2 = i0;
    if (i0) {goto L6;}
  i0 = 0u;
  l4 = i0;
  goto B0;
  B5:;
  i0 = l6;
  i1 = 4u;
  i2 = 1058356u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B4:;
  i0 = p1;
  i1 = p2;
  i2 = 0u;
  i3 = l4;
  i4 = 1058856u;
  _ZN4core3str16slice_error_fail17h756d0528f966c096E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B3:;
  i0 = p1;
  i1 = p2;
  i2 = l4;
  i3 = p2;
  i4 = 1058872u;
  _ZN4core3str16slice_error_fail17h756d0528f966c096E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  B2:;
  i0 = 1u;
  l4 = i0;
  B0:;
  i0 = l3;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  i0 = l4;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core5slice6memchr6memchr17h4b6f86a8dda0136aE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = 0u;
  l4 = i0;
  i0 = p2;
  i1 = 3u;
  i0 &= i1;
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = 4u;
  i1 = l5;
  i0 -= i1;
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p3;
  i1 = l5;
  i2 = l5;
  i3 = p3;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l4 = i0;
  i0 = 0u;
  l5 = i0;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  l6 = i0;
  L2: 
    i0 = l4;
    i1 = l5;
    i0 = i0 == i1;
    if (i0) {goto B1;}
    i0 = p2;
    i1 = l5;
    i0 += i1;
    l7 = i0;
    i0 = l5;
    i1 = 1u;
    i0 += i1;
    l5 = i0;
    i0 = l7;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l7 = i0;
    i1 = l6;
    i0 = i0 != i1;
    if (i0) {goto L2;}
  i0 = 1u;
  p3 = i0;
  i0 = l7;
  i1 = p1;
  i2 = 255u;
  i1 &= i2;
  i0 = i0 == i1;
  i1 = 1u;
  i0 += i1;
  i1 = 1u;
  i0 &= i1;
  i1 = l5;
  i0 += i1;
  i1 = 4294967295u;
  i0 += i1;
  l5 = i0;
  goto B0;
  B1:;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  l6 = i0;
  i0 = p3;
  i1 = 8u;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l4;
  i1 = p3;
  i2 = 4294967288u;
  i1 += i2;
  l8 = i1;
  i0 = i0 > i1;
  if (i0) {goto B4;}
  i0 = l6;
  i1 = 16843009u;
  i0 *= i1;
  l5 = i0;
  L6: 
    i0 = p2;
    i1 = l4;
    i0 += i1;
    l7 = i0;
    i1 = 4u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l5;
    i0 ^= i1;
    l9 = i0;
    i1 = 4294967295u;
    i0 ^= i1;
    i1 = l9;
    i2 = 4278124287u;
    i1 += i2;
    i0 &= i1;
    i1 = l7;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = l5;
    i1 ^= i2;
    l7 = i1;
    i2 = 4294967295u;
    i1 ^= i2;
    i2 = l7;
    i3 = 4278124287u;
    i2 += i3;
    i1 &= i2;
    i0 |= i1;
    i1 = 2155905152u;
    i0 &= i1;
    if (i0) {goto B5;}
    i0 = l4;
    i1 = 8u;
    i0 += i1;
    l4 = i0;
    i1 = l8;
    i0 = i0 <= i1;
    if (i0) {goto L6;}
  B5:;
  i0 = l4;
  i1 = p3;
  i0 = i0 > i1;
  if (i0) {goto B3;}
  B4:;
  i0 = p2;
  i1 = l4;
  i0 += i1;
  l9 = i0;
  i0 = p3;
  i1 = l4;
  i0 -= i1;
  p2 = i0;
  i0 = 0u;
  p3 = i0;
  i0 = 0u;
  l5 = i0;
  L8: 
    i0 = p2;
    i1 = l5;
    i0 = i0 == i1;
    if (i0) {goto B7;}
    i0 = l9;
    i1 = l5;
    i0 += i1;
    l7 = i0;
    i0 = l5;
    i1 = 1u;
    i0 += i1;
    l5 = i0;
    i0 = l7;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l7 = i0;
    i1 = l6;
    i0 = i0 != i1;
    if (i0) {goto L8;}
  i0 = 1u;
  p3 = i0;
  i0 = l7;
  i1 = p1;
  i2 = 255u;
  i1 &= i2;
  i0 = i0 == i1;
  i1 = 1u;
  i0 += i1;
  i1 = 1u;
  i0 &= i1;
  i1 = l5;
  i0 += i1;
  i1 = 4294967295u;
  i0 += i1;
  l5 = i0;
  B7:;
  i0 = l5;
  i1 = l4;
  i0 += i1;
  l5 = i0;
  goto B0;
  B3:;
  i0 = l4;
  i1 = p3;
  i2 = 1058128u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p3;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static u32 _ZN4core3fmt8builders11DebugStruct6finish17hab8f7dfb856acfc0E(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  l1 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 5));
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i1 = 255u;
  i0 &= i1;
  l2 = i0;
  i0 = 1u;
  l1 = i0;
  i0 = l2;
  if (i0) {goto B1;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i1 = 28u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = i32_load((&memory), (u64)(i0 + 12));
  l2 = i0;
  i0 = l1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l3 = i0;
  i0 = l1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 4u;
  i0 &= i1;
  if (i0) {goto B2;}
  i0 = l3;
  i1 = 1057751u;
  i2 = 2u;
  i3 = l2;
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l1 = i0;
  goto B1;
  B2:;
  i0 = l3;
  i1 = 1057750u;
  i2 = 1u;
  i3 = l2;
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l1 = i0;
  B1:;
  i0 = p0;
  i1 = l1;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  B0:;
  i0 = l1;
  i1 = 255u;
  i0 &= i1;
  i1 = 0u;
  i0 = i0 != i1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt8builders10DebugTuple5field17h16202dfa3a9387a4E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  u64 l7 = 0, l8 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = 1u;
  l4 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 4u;
  i0 &= i1;
  if (i0) {goto B1;}
  i0 = 1u;
  l4 = i0;
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057745u;
  i2 = 1057755u;
  i3 = l5;
  i1 = i3 ? i1 : i2;
  i2 = 2u;
  i3 = 1u;
  i4 = l5;
  i2 = i4 ? i2 : i3;
  i3 = l6;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  l4 = i0;
  goto B0;
  B1:;
  i0 = l5;
  if (i0) {goto B2;}
  i0 = 1u;
  l4 = i0;
  i0 = l6;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057753u;
  i2 = 2u;
  i3 = l6;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  B2:;
  i0 = 1u;
  l4 = i0;
  i0 = l3;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 23), i1);
  i0 = l3;
  i1 = 52u;
  i0 += i1;
  i1 = 1057712u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l6;
  j1 = i64_load((&memory), (u64)(i1 + 24));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l3;
  i1 = l3;
  i2 = 23u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l6;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l7 = j0;
  i0 = l6;
  j0 = i64_load((&memory), (u64)(i0 + 16));
  l8 = j0;
  i0 = l3;
  i1 = l6;
  i1 = i32_load8_u((&memory), (u64)(i1 + 32));
  i32_store8((&memory), (u64)(i0 + 56), i1);
  i0 = l3;
  j1 = l8;
  i64_store((&memory), (u64)(i0 + 40), j1);
  i0 = l3;
  j1 = l7;
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = l3;
  i1 = l6;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l3;
  i1 = l3;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = p1;
  i1 = l3;
  i2 = 24u;
  i1 += i2;
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  if (i0) {goto B0;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  i1 = 1057743u;
  i2 = 2u;
  i3 = l3;
  i3 = i32_load((&memory), (u64)(i3 + 52));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l4 = i0;
  B0:;
  i0 = p0;
  i1 = l4;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt8builders10DebugTuple6finish17h540db6bc8e5a3697E(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  l1 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i1 = 255u;
  i0 &= i1;
  l3 = i0;
  i0 = 1u;
  l1 = i0;
  i0 = l3;
  if (i0) {goto B1;}
  i0 = l2;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B2;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 9));
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 4u;
  i0 &= i1;
  if (i0) {goto B2;}
  i0 = 1u;
  l1 = i0;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057756u;
  i2 = 1u;
  i3 = l3;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B1;}
  B2:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057757u;
  i2 = 1u;
  i3 = l1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l1 = i0;
  B1:;
  i0 = p0;
  i1 = l1;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  B0:;
  i0 = l1;
  i1 = 255u;
  i0 &= i1;
  i1 = 0u;
  i0 = i0 != i1;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3fmt8builders10DebugInner5entry17hcf0cc88c48da1d40E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0;
  u64 l6 = 0, l7 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = 1u;
  l4 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 5));
  l4 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 4u;
  i0 &= i1;
  if (i0) {goto B1;}
  i0 = l4;
  i1 = 255u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = 1u;
  l4 = i0;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057745u;
  i2 = 2u;
  i3 = l5;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  B2:;
  i0 = p1;
  i1 = l5;
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  l4 = i0;
  goto B0;
  B1:;
  i0 = l4;
  i1 = 255u;
  i0 &= i1;
  if (i0) {goto B3;}
  i0 = 1u;
  l4 = i0;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057758u;
  i2 = 1u;
  i3 = l5;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  B3:;
  i0 = 1u;
  l4 = i0;
  i0 = l3;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 23), i1);
  i0 = l3;
  i1 = 52u;
  i0 += i1;
  i1 = 1057712u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l5;
  j1 = i64_load((&memory), (u64)(i1 + 24));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l3;
  i1 = l3;
  i2 = 23u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l5;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l6 = j0;
  i0 = l5;
  j0 = i64_load((&memory), (u64)(i0 + 16));
  l7 = j0;
  i0 = l3;
  i1 = l5;
  i1 = i32_load8_u((&memory), (u64)(i1 + 32));
  i32_store8((&memory), (u64)(i0 + 56), i1);
  i0 = l3;
  j1 = l7;
  i64_store((&memory), (u64)(i0 + 40), j1);
  i0 = l3;
  j1 = l6;
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = l3;
  i1 = l5;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l3;
  i1 = l3;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = p1;
  i1 = l3;
  i2 = 24u;
  i1 += i2;
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  if (i0) {goto B0;}
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  i1 = 1057743u;
  i2 = 2u;
  i3 = l3;
  i3 = i32_load((&memory), (u64)(i3 + 52));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l4 = i0;
  B0:;
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = p0;
  i1 = l4;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l3;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3fmt8builders8DebugSet5entry17he2607966213fa565E(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i1 = p1;
  i2 = p2;
  _ZN4core3fmt8builders10DebugInner5entry17hcf0cc88c48da1d40E(i0, i1, i2);
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt8builders9DebugList6finish17hf24d2051438d787aE(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = 1u;
  l1 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  if (i0) {goto B0;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057776u;
  i2 = 1u;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l1 = i0;
  B0:;
  i0 = l1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt5Write10write_char17h2e3be12005dd62ddE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p1;
  i1 = 128u;
  i0 = i0 < i1;
  if (i0) {goto B3;}
  i0 = p1;
  i1 = 2048u;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 12u;
  i0 += i1;
  l3 = i0;
  i0 = p1;
  i1 = 65536u;
  i0 = i0 >= i1;
  if (i0) {goto B1;}
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 15u;
  i1 &= i2;
  i2 = 224u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 3u;
  p1 = i0;
  goto B0;
  B3:;
  i0 = l2;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 12u;
  i0 += i1;
  l3 = i0;
  i0 = 1u;
  p1 = i0;
  goto B0;
  B2:;
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 31u;
  i1 &= i2;
  i2 = 192u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 12u;
  i0 += i1;
  l3 = i0;
  i0 = 2u;
  p1 = i0;
  goto B0;
  B1:;
  i0 = l2;
  i1 = p1;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 15), i1);
  i0 = l2;
  i1 = p1;
  i2 = 18u;
  i1 >>= (i2 & 31);
  i2 = 240u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = p1;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l2;
  i1 = p1;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = 4u;
  p1 = i0;
  B0:;
  i0 = p0;
  i1 = l3;
  i2 = p1;
  i0 = _ZN68__LT_core__fmt__builders__PadAdapter_u20_as_u20_core__fmt__Write_GT_9write_str17hb63bd9b52d2ea355E(i0, i1, i2);
  p1 = i0;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt5Write9write_fmt17h0c139c28d79b9a60E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  i1 = 1058020u;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p1 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h079bfd1e4c225fd5E(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p2;
  i0 = _ZN68__LT_core__fmt__builders__PadAdapter_u20_as_u20_core__fmt__Write_GT_9write_str17hb63bd9b52d2ea355E(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17h6458f56299ed9010E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i0 = _ZN4core3fmt5Write10write_char17h2e3be12005dd62ddE(i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17h8b43657baa867c64E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  i1 = 1058020u;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p1 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN59__LT_core__fmt__Arguments_u20_as_u20_core__fmt__Display_GT_3fmt17h25afdf22ace19a57E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  i1 = 28u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  p1 = i0;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p0;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p0;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = p1;
  i1 = l3;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p0 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4, u32 p5) {
  u32 l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, l11 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p1;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = 43u;
  i1 = 1114112u;
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2));
  l6 = i2;
  i3 = 1u;
  i2 &= i3;
  p1 = i2;
  i0 = i2 ? i0 : i1;
  l7 = i0;
  i0 = p1;
  i1 = p5;
  i0 += i1;
  l8 = i0;
  goto B0;
  B1:;
  i0 = p5;
  i1 = 1u;
  i0 += i1;
  l8 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i0 = 45u;
  l7 = i0;
  B0:;
  i0 = l6;
  i1 = 4u;
  i0 &= i1;
  if (i0) {goto B3;}
  i0 = 0u;
  p2 = i0;
  goto B2;
  B3:;
  i0 = 0u;
  l9 = i0;
  i0 = p3;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = p3;
  l10 = i0;
  i0 = p2;
  p1 = i0;
  L5: 
    i0 = l9;
    i1 = p1;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i2 = 192u;
    i1 &= i2;
    i2 = 128u;
    i1 = i1 == i2;
    i0 += i1;
    l9 = i0;
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    p1 = i0;
    i0 = l10;
    i1 = 4294967295u;
    i0 += i1;
    l10 = i0;
    if (i0) {goto L5;}
  B4:;
  i0 = l8;
  i1 = p3;
  i0 += i1;
  i1 = l9;
  i0 -= i1;
  l8 = i0;
  B2:;
  i0 = 1u;
  p1 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B7;}
  i0 = p0;
  i1 = l7;
  i2 = p2;
  i3 = p3;
  i0 = _ZN4core3fmt9Formatter12pad_integral12write_prefix17h8315a5e67d65fa1fE(i0, i1, i2, i3);
  if (i0) {goto B6;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p4;
  i2 = p5;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  p1 = i0;
  goto B6;
  B7:;
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l9 = i0;
  i1 = l8;
  i0 = i0 > i1;
  if (i0) {goto B8;}
  i0 = p0;
  i1 = l7;
  i2 = p2;
  i3 = p3;
  i0 = _ZN4core3fmt9Formatter12pad_integral12write_prefix17h8315a5e67d65fa1fE(i0, i1, i2, i3);
  if (i0) {goto B6;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p4;
  i2 = p5;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  goto Bfunc;
  B8:;
  i0 = l6;
  i1 = 8u;
  i0 &= i1;
  if (i0) {goto B10;}
  i0 = 0u;
  p1 = i0;
  i0 = l9;
  i1 = l8;
  i0 -= i1;
  l9 = i0;
  l8 = i0;
  i0 = 1u;
  i1 = p0;
  i1 = i32_load8_u((&memory), (u64)(i1 + 32));
  l10 = i1;
  i2 = l10;
  i3 = 3u;
  i2 = i2 == i3;
  i0 = i2 ? i0 : i1;
  switch (i0) {
    case 0: goto B11;
    case 1: goto B12;
    case 2: goto B13;
    case 3: goto B12;
    default: goto B11;
  }
  B13:;
  i0 = l9;
  i1 = 1u;
  i0 >>= (i1 & 31);
  p1 = i0;
  i0 = l9;
  i1 = 1u;
  i0 += i1;
  i1 = 1u;
  i0 >>= (i1 & 31);
  l8 = i0;
  goto B11;
  B12:;
  i0 = 0u;
  l8 = i0;
  i0 = l9;
  p1 = i0;
  B11:;
  i0 = p1;
  i1 = 1u;
  i0 += i1;
  p1 = i0;
  L14: 
    i0 = p1;
    i1 = 4294967295u;
    i0 += i1;
    p1 = i0;
    i0 = !(i0);
    if (i0) {goto B9;}
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    i1 = p0;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i2 = p0;
    i2 = i32_load((&memory), (u64)(i2 + 28));
    i2 = i32_load((&memory), (u64)(i2 + 16));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    i0 = !(i0);
    if (i0) {goto L14;}
  i0 = 1u;
  goto Bfunc;
  B10:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l6 = i0;
  i0 = p0;
  i1 = 48u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0 + 32));
  l11 = i0;
  i0 = 1u;
  p1 = i0;
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 32), i1);
  i0 = p0;
  i1 = l7;
  i2 = p2;
  i3 = p3;
  i0 = _ZN4core3fmt9Formatter12pad_integral12write_prefix17h8315a5e67d65fa1fE(i0, i1, i2, i3);
  if (i0) {goto B6;}
  i0 = 0u;
  p1 = i0;
  i0 = l9;
  i1 = l8;
  i0 -= i1;
  l10 = i0;
  p3 = i0;
  i0 = 1u;
  i1 = p0;
  i1 = i32_load8_u((&memory), (u64)(i1 + 32));
  l9 = i1;
  i2 = l9;
  i3 = 3u;
  i2 = i2 == i3;
  i0 = i2 ? i0 : i1;
  switch (i0) {
    case 0: goto B15;
    case 1: goto B16;
    case 2: goto B17;
    case 3: goto B16;
    default: goto B15;
  }
  B17:;
  i0 = l10;
  i1 = 1u;
  i0 >>= (i1 & 31);
  p1 = i0;
  i0 = l10;
  i1 = 1u;
  i0 += i1;
  i1 = 1u;
  i0 >>= (i1 & 31);
  p3 = i0;
  goto B15;
  B16:;
  i0 = 0u;
  p3 = i0;
  i0 = l10;
  p1 = i0;
  B15:;
  i0 = p1;
  i1 = 1u;
  i0 += i1;
  p1 = i0;
  L19: 
    i0 = p1;
    i1 = 4294967295u;
    i0 += i1;
    p1 = i0;
    i0 = !(i0);
    if (i0) {goto B18;}
    i0 = p0;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    i1 = p0;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i2 = p0;
    i2 = i32_load((&memory), (u64)(i2 + 28));
    i2 = i32_load((&memory), (u64)(i2 + 16));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    i0 = !(i0);
    if (i0) {goto L19;}
  i0 = 1u;
  goto Bfunc;
  B18:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l10 = i0;
  i0 = 1u;
  p1 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p4;
  i2 = p5;
  i3 = p0;
  i3 = i32_load((&memory), (u64)(i3 + 28));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B6;}
  i0 = p3;
  i1 = 1u;
  i0 += i1;
  l9 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  p3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  p2 = i0;
  L21: 
    i0 = l9;
    i1 = 4294967295u;
    i0 += i1;
    l9 = i0;
    i0 = !(i0);
    if (i0) {goto B20;}
    i0 = 1u;
    p1 = i0;
    i0 = p2;
    i1 = l10;
    i2 = p3;
    i2 = i32_load((&memory), (u64)(i2 + 16));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    if (i0) {goto B6;}
    goto L21;
  B20:;
  i0 = p0;
  i1 = l11;
  i32_store8((&memory), (u64)(i0 + 32), i1);
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = 0u;
  goto Bfunc;
  B9:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l10 = i0;
  i0 = 1u;
  p1 = i0;
  i0 = p0;
  i1 = l7;
  i2 = p2;
  i3 = p3;
  i0 = _ZN4core3fmt9Formatter12pad_integral12write_prefix17h8315a5e67d65fa1fE(i0, i1, i2, i3);
  if (i0) {goto B6;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p4;
  i2 = p5;
  i3 = p0;
  i3 = i32_load((&memory), (u64)(i3 + 28));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B6;}
  i0 = l8;
  i1 = 1u;
  i0 += i1;
  l9 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  p3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  p0 = i0;
  L22: 
    i0 = l9;
    i1 = 4294967295u;
    i0 += i1;
    l9 = i0;
    if (i0) {goto B23;}
    i0 = 0u;
    goto Bfunc;
    B23:;
    i0 = 1u;
    p1 = i0;
    i0 = p0;
    i1 = l10;
    i2 = p3;
    i2 = i32_load((&memory), (u64)(i2 + 16));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    i0 = !(i0);
    if (i0) {goto L22;}
  B6:;
  i0 = p1;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt9Formatter12pad_integral12write_prefix17h8315a5e67d65fa1fE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p1;
  i1 = 1114112u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = 1u;
  l4 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p0;
  i3 = 28u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  if (i0) {goto B0;}
  B1:;
  i0 = p2;
  if (i0) {goto B2;}
  i0 = 0u;
  goto Bfunc;
  B2:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p2;
  i2 = p3;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l4 = i0;
  B0:;
  i0 = l4;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt9Formatter9write_str17h3d77f3190807e699E(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt9Formatter9write_fmt17h5f4a789bf06948b3E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i1 = 28u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  p0 = i0;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = p0;
  i1 = l3;
  i2 = l2;
  i3 = 8u;
  i2 += i3;
  i0 = _ZN4core3fmt5write17h4834d85ce1be7131E(i0, i1, i2);
  p1 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt9Formatter15debug_lower_hex17h613d71a0ae3bc060E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 16u;
  i0 &= i1;
  i1 = 4u;
  i0 >>= (i1 & 31);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt9Formatter15debug_upper_hex17h5c3e903ff5236763E(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 32u;
  i0 &= i1;
  i1 = 5u;
  i0 >>= (i1 & 31);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3fmt9Formatter12debug_struct17h46183d60fb16cd21E(u32 p0, u32 p1, u32 p2, u32 p3) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p2;
  i2 = p3;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  p2 = i0;
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = p0;
  i1 = p2;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN4core3fmt9Formatter11debug_tuple17h141929d5811b3949E(u32 p0, u32 p1, u32 p2, u32 p3) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5;
  i0 = p0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 24));
  i2 = p2;
  i3 = p3;
  i4 = p1;
  i5 = 28u;
  i4 += i5;
  i4 = i32_load((&memory), (u64)(i4));
  i4 = i32_load((&memory), (u64)(i4 + 12));
  i1 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i4, i1, i2, i3);
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p3;
  i1 = !(i1);
  i32_store8((&memory), (u64)(i0 + 9), i1);
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  FUNC_EPILOGUE;
}

static void _ZN4core3fmt9Formatter10debug_list17h71cfa9ce1b3f9f44E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057759u;
  i2 = 1u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l2 = i0;
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = p0;
  i1 = l2;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static u32 _ZN57__LT_core__fmt__Formatter_u20_as_u20_core__fmt__Write_GT_10write_char17h22afcca50c7c4efdE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p0;
  i3 = 28u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN40__LT_str_u20_as_u20_core__fmt__Debug_GT_3fmt17hc81f6984a0ce9960E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, 
      l11 = 0, l12 = 0, l13 = 0, l14 = 0;
  u64 l15 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  u64 j0, j1, j2;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = 1u;
  l4 = i0;
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 34u;
  i2 = p2;
  i3 = 28u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  if (i0) {goto B1;}
  i0 = p1;
  if (i0) {goto B3;}
  i0 = 0u;
  l5 = i0;
  goto B2;
  B3:;
  i0 = p0;
  i1 = p1;
  i0 += i1;
  l6 = i0;
  i0 = 0u;
  l5 = i0;
  i0 = p0;
  l7 = i0;
  i0 = 0u;
  l8 = i0;
  L5: 
    i0 = l7;
    l9 = i0;
    i0 = l7;
    i1 = 1u;
    i0 += i1;
    l10 = i0;
    i0 = l7;
    i0 = i32_load8_s((&memory), (u64)(i0));
    l11 = i0;
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    if (i0) {goto B8;}
    i0 = l10;
    i1 = l6;
    i0 = i0 != i1;
    if (i0) {goto B10;}
    i0 = 0u;
    l12 = i0;
    i0 = l6;
    l7 = i0;
    goto B9;
    B10:;
    i0 = l7;
    i0 = i32_load8_u((&memory), (u64)(i0 + 1));
    i1 = 63u;
    i0 &= i1;
    l12 = i0;
    i0 = l7;
    i1 = 2u;
    i0 += i1;
    l10 = i0;
    l7 = i0;
    B9:;
    i0 = l11;
    i1 = 31u;
    i0 &= i1;
    l4 = i0;
    i0 = l11;
    i1 = 255u;
    i0 &= i1;
    l11 = i0;
    i1 = 223u;
    i0 = i0 > i1;
    if (i0) {goto B11;}
    i0 = l12;
    i1 = l4;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l12 = i0;
    goto B7;
    B11:;
    i0 = l7;
    i1 = l6;
    i0 = i0 != i1;
    if (i0) {goto B13;}
    i0 = 0u;
    l13 = i0;
    i0 = l6;
    l14 = i0;
    goto B12;
    B13:;
    i0 = l7;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    l13 = i0;
    i0 = l7;
    i1 = 1u;
    i0 += i1;
    l10 = i0;
    l14 = i0;
    B12:;
    i0 = l13;
    i1 = l12;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l12 = i0;
    i0 = l11;
    i1 = 240u;
    i0 = i0 >= i1;
    if (i0) {goto B14;}
    i0 = l12;
    i1 = l4;
    i2 = 12u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l12 = i0;
    goto B7;
    B14:;
    i0 = l14;
    i1 = l6;
    i0 = i0 != i1;
    if (i0) {goto B16;}
    i0 = 0u;
    l11 = i0;
    i0 = l10;
    l7 = i0;
    goto B15;
    B16:;
    i0 = l14;
    i1 = 1u;
    i0 += i1;
    l7 = i0;
    i0 = l14;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    l11 = i0;
    B15:;
    i0 = l12;
    i1 = 6u;
    i0 <<= (i1 & 31);
    i1 = l4;
    i2 = 18u;
    i1 <<= (i2 & 31);
    i2 = 1835008u;
    i1 &= i2;
    i0 |= i1;
    i1 = l11;
    i0 |= i1;
    l12 = i0;
    i1 = 1114112u;
    i0 = i0 != i1;
    if (i0) {goto B6;}
    goto B4;
    B8:;
    i0 = l11;
    i1 = 255u;
    i0 &= i1;
    l12 = i0;
    B7:;
    i0 = l10;
    l7 = i0;
    B6:;
    i0 = 2u;
    l10 = i0;
    i0 = l12;
    i1 = 4294967287u;
    i0 += i1;
    l11 = i0;
    i1 = 30u;
    i0 = i0 <= i1;
    if (i0) {goto B22;}
    i0 = l12;
    i1 = 92u;
    i0 = i0 != i1;
    if (i0) {goto B21;}
    goto B20;
    B22:;
    i0 = 116u;
    l14 = i0;
    i0 = l11;
    switch (i0) {
      case 0: goto B18;
      case 1: goto B23;
      case 2: goto B21;
      case 3: goto B21;
      case 4: goto B24;
      case 5: goto B21;
      case 6: goto B21;
      case 7: goto B21;
      case 8: goto B21;
      case 9: goto B21;
      case 10: goto B21;
      case 11: goto B21;
      case 12: goto B21;
      case 13: goto B21;
      case 14: goto B21;
      case 15: goto B21;
      case 16: goto B21;
      case 17: goto B21;
      case 18: goto B21;
      case 19: goto B21;
      case 20: goto B21;
      case 21: goto B21;
      case 22: goto B21;
      case 23: goto B21;
      case 24: goto B21;
      case 25: goto B20;
      case 26: goto B21;
      case 27: goto B21;
      case 28: goto B21;
      case 29: goto B21;
      case 30: goto B20;
      default: goto B18;
    }
    B24:;
    i0 = 114u;
    l14 = i0;
    goto B18;
    B23:;
    i0 = 110u;
    l14 = i0;
    goto B18;
    B21:;
    i0 = l12;
    i0 = _ZN4core7unicode12unicode_data15grapheme_extend6lookup17h138f528bd4ec82e3E(i0);
    if (i0) {goto B25;}
    i0 = l12;
    i1 = 65536u;
    i0 = i0 < i1;
    if (i0) {goto B27;}
    i0 = l12;
    i1 = 131072u;
    i0 = i0 < i1;
    if (i0) {goto B26;}
    i0 = l12;
    i1 = 4294049296u;
    i0 += i1;
    i1 = 196112u;
    i0 = i0 < i1;
    if (i0) {goto B25;}
    i0 = l12;
    i1 = 4294765749u;
    i0 += i1;
    i1 = 716213u;
    i0 = i0 < i1;
    if (i0) {goto B25;}
    i0 = l12;
    i1 = 4294772194u;
    i0 += i1;
    i1 = 1506u;
    i0 = i0 < i1;
    if (i0) {goto B25;}
    i0 = l12;
    i1 = 4294775839u;
    i0 += i1;
    i1 = 3103u;
    i0 = i0 < i1;
    if (i0) {goto B25;}
    i0 = l12;
    i1 = 4294783326u;
    i0 += i1;
    i1 = 14u;
    i0 = i0 < i1;
    if (i0) {goto B25;}
    i0 = l12;
    i1 = 2097150u;
    i0 &= i1;
    i1 = 178206u;
    i0 = i0 == i1;
    if (i0) {goto B25;}
    i0 = l12;
    i1 = 4294793506u;
    i0 += i1;
    i1 = 34u;
    i0 = i0 < i1;
    if (i0) {goto B25;}
    i0 = l12;
    i1 = 4294789323u;
    i0 += i1;
    i1 = 10u;
    i0 = i0 <= i1;
    if (i0) {goto B25;}
    goto B17;
    B27:;
    i0 = l12;
    i1 = 1059176u;
    i2 = 41u;
    i3 = 1059258u;
    i4 = 290u;
    i5 = 1059548u;
    i6 = 309u;
    i0 = _ZN4core7unicode9printable5check17hc49c8dda078b527eE(i0, i1, i2, i3, i4, i5, i6);
    i0 = !(i0);
    if (i0) {goto B25;}
    goto B17;
    B26:;
    i0 = l12;
    i1 = 1059857u;
    i2 = 38u;
    i3 = 1059933u;
    i4 = 175u;
    i5 = 1060108u;
    i6 = 419u;
    i0 = _ZN4core7unicode9printable5check17hc49c8dda078b527eE(i0, i1, i2, i3, i4, i5, i6);
    if (i0) {goto B17;}
    B25:;
    i0 = l12;
    i1 = 1u;
    i0 |= i1;
    i0 = I32_CLZ(i0);
    i1 = 2u;
    i0 >>= (i1 & 31);
    i1 = 7u;
    i0 ^= i1;
    j0 = (u64)(i0);
    j1 = 21474836480ull;
    j0 |= j1;
    l15 = j0;
    i0 = 3u;
    l10 = i0;
    goto B19;
    B20:;
    B19:;
    i0 = l12;
    l14 = i0;
    B18:;
    i0 = l3;
    i1 = p1;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l3;
    i1 = p0;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = l5;
    i32_store((&memory), (u64)(i0 + 8), i1);
    i0 = l3;
    i1 = l8;
    i32_store((&memory), (u64)(i0 + 12), i1);
    i0 = l8;
    i1 = l5;
    i0 = i0 < i1;
    if (i0) {goto B29;}
    i0 = l5;
    i0 = !(i0);
    if (i0) {goto B30;}
    i0 = l5;
    i1 = p1;
    i0 = i0 == i1;
    if (i0) {goto B30;}
    i0 = l5;
    i1 = p1;
    i0 = i0 >= i1;
    if (i0) {goto B29;}
    i0 = p0;
    i1 = l5;
    i0 += i1;
    i0 = i32_load8_s((&memory), (u64)(i0));
    i1 = 4294967231u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B29;}
    B30:;
    i0 = l8;
    i0 = !(i0);
    if (i0) {goto B31;}
    i0 = l8;
    i1 = p1;
    i0 = i0 == i1;
    if (i0) {goto B31;}
    i0 = l8;
    i1 = p1;
    i0 = i0 >= i1;
    if (i0) {goto B29;}
    i0 = p0;
    i1 = l8;
    i0 += i1;
    i0 = i32_load8_s((&memory), (u64)(i0));
    i1 = 4294967231u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B29;}
    B31:;
    i0 = p2;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    i1 = p0;
    i2 = l5;
    i1 += i2;
    i2 = l8;
    i3 = l5;
    i2 -= i3;
    i3 = p2;
    i3 = i32_load((&memory), (u64)(i3 + 28));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
    i0 = !(i0);
    if (i0) {goto B28;}
    i0 = 1u;
    l4 = i0;
    goto B1;
    B29:;
    i0 = l3;
    i1 = l3;
    i2 = 12u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 24), i1);
    i0 = l3;
    i1 = l3;
    i2 = 8u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 20), i1);
    i0 = l3;
    i1 = l3;
    i32_store((&memory), (u64)(i0 + 16), i1);
    i0 = l3;
    i1 = 16u;
    i0 += i1;
    _ZN4core3str6traits101__LT_impl_u20_core__slice__SliceIndex_LT_str_GT__u20_for_u20_core__ops__range__Range_LT_usize_GT__GT_5index28__u7b__u7b_closure_u7d__u7d_17h834e63e786a4d85dE(i0);
    UNREACHABLE;
    B28:;
    L32: 
      i0 = l10;
      l11 = i0;
      i0 = 1u;
      l4 = i0;
      i0 = 92u;
      l5 = i0;
      i0 = 1u;
      l10 = i0;
      i0 = l11;
      switch (i0) {
        case 0: goto B36;
        case 1: goto B37;
        case 2: goto B33;
        case 3: goto B38;
        default: goto B36;
      }
      B38:;
      j0 = l15;
      j1 = 32ull;
      j0 >>= (j1 & 63);
      i0 = (u32)(j0);
      i1 = 255u;
      i0 &= i1;
      switch (i0) {
        case 0: goto B36;
        case 1: goto B39;
        case 2: goto B40;
        case 3: goto B41;
        case 4: goto B42;
        case 5: goto B35;
        default: goto B36;
      }
      B42:;
      j0 = l15;
      j1 = 18446742978492891135ull;
      j0 &= j1;
      j1 = 12884901888ull;
      j0 |= j1;
      l15 = j0;
      i0 = 3u;
      l10 = i0;
      i0 = 117u;
      l5 = i0;
      goto B33;
      B41:;
      j0 = l15;
      j1 = 18446742978492891135ull;
      j0 &= j1;
      j1 = 8589934592ull;
      j0 |= j1;
      l15 = j0;
      i0 = 3u;
      l10 = i0;
      i0 = 123u;
      l5 = i0;
      goto B33;
      B40:;
      i0 = l14;
      j1 = l15;
      i1 = (u32)(j1);
      l11 = i1;
      i2 = 2u;
      i1 <<= (i2 & 31);
      i2 = 28u;
      i1 &= i2;
      i0 >>= (i1 & 31);
      i1 = 15u;
      i0 &= i1;
      l10 = i0;
      i1 = 48u;
      i0 |= i1;
      i1 = l10;
      i2 = 87u;
      i1 += i2;
      i2 = l10;
      i3 = 10u;
      i2 = i2 < i3;
      i0 = i2 ? i0 : i1;
      l5 = i0;
      i0 = l11;
      i0 = !(i0);
      if (i0) {goto B43;}
      j0 = l15;
      j1 = 18446744073709551615ull;
      j0 += j1;
      j1 = 4294967295ull;
      j0 &= j1;
      j1 = l15;
      j2 = 18446744069414584320ull;
      j1 &= j2;
      j0 |= j1;
      l15 = j0;
      goto B34;
      B43:;
      j0 = l15;
      j1 = 18446742978492891135ull;
      j0 &= j1;
      j1 = 4294967296ull;
      j0 |= j1;
      l15 = j0;
      goto B34;
      B39:;
      j0 = l15;
      j1 = 18446742978492891135ull;
      j0 &= j1;
      l15 = j0;
      i0 = 3u;
      l10 = i0;
      i0 = 125u;
      l5 = i0;
      goto B33;
      B37:;
      i0 = 0u;
      l10 = i0;
      i0 = l14;
      l5 = i0;
      goto B33;
      B36:;
      i0 = 1u;
      l10 = i0;
      i0 = l12;
      i1 = 128u;
      i0 = i0 < i1;
      if (i0) {goto B44;}
      i0 = 2u;
      l10 = i0;
      i0 = l12;
      i1 = 2048u;
      i0 = i0 < i1;
      if (i0) {goto B44;}
      i0 = 3u;
      i1 = 4u;
      i2 = l12;
      i3 = 65536u;
      i2 = i2 < i3;
      i0 = i2 ? i0 : i1;
      l10 = i0;
      B44:;
      i0 = l10;
      i1 = l8;
      i0 += i1;
      l5 = i0;
      goto B17;
      B35:;
      j0 = l15;
      j1 = 18446742978492891135ull;
      j0 &= j1;
      j1 = 17179869184ull;
      j0 |= j1;
      l15 = j0;
      B34:;
      i0 = 3u;
      l10 = i0;
      B33:;
      i0 = p2;
      i0 = i32_load((&memory), (u64)(i0 + 24));
      i1 = l5;
      i2 = p2;
      i2 = i32_load((&memory), (u64)(i2 + 28));
      i2 = i32_load((&memory), (u64)(i2 + 16));
      i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
      i0 = !(i0);
      if (i0) {goto L32;}
      goto B1;
    B17:;
    i0 = l8;
    i1 = l9;
    i0 -= i1;
    i1 = l7;
    i0 += i1;
    l8 = i0;
    i0 = l6;
    i1 = l7;
    i0 = i0 != i1;
    if (i0) {goto L5;}
  B4:;
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l5;
  i1 = p1;
  i0 = i0 == i1;
  if (i0) {goto B2;}
  i0 = l5;
  i1 = p1;
  i0 = i0 >= i1;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = l5;
  i0 += i1;
  i0 = i32_load8_s((&memory), (u64)(i0));
  i1 = 4294967231u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B0;}
  B2:;
  i0 = 1u;
  l4 = i0;
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p0;
  i2 = l5;
  i1 += i2;
  i2 = p1;
  i3 = l5;
  i2 -= i3;
  i3 = p2;
  i3 = i32_load((&memory), (u64)(i3 + 28));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B1;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 34u;
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 28));
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  l4 = i0;
  B1:;
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = l4;
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = p1;
  i2 = l5;
  i3 = p1;
  i4 = 1058872u;
  _ZN4core3str16slice_error_fail17h756d0528f966c096E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core7unicode12unicode_data15grapheme_extend6lookup17h138f528bd4ec82e3E(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = 0u;
  i1 = 15u;
  i2 = p0;
  i3 = 68900u;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l1 = i0;
  i1 = l1;
  i2 = 8u;
  i1 += i2;
  l1 = i1;
  i2 = l1;
  i3 = 2u;
  i2 <<= (i3 & 31);
  i3 = 1060764u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i3 = 11u;
  i2 <<= (i3 & 31);
  i3 = p0;
  i4 = 11u;
  i3 <<= (i4 & 31);
  l1 = i3;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l2 = i0;
  i1 = l2;
  i2 = 4u;
  i1 += i2;
  l2 = i1;
  i2 = l2;
  i3 = 2u;
  i2 <<= (i3 & 31);
  i3 = 1060764u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i3 = 11u;
  i2 <<= (i3 & 31);
  i3 = l1;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l2 = i0;
  i1 = l2;
  i2 = 2u;
  i1 += i2;
  l2 = i1;
  i2 = l2;
  i3 = 2u;
  i2 <<= (i3 & 31);
  i3 = 1060764u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i3 = 11u;
  i2 <<= (i3 & 31);
  i3 = l1;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l2 = i0;
  i1 = l2;
  i2 = 1u;
  i1 += i2;
  l2 = i1;
  i2 = l2;
  i3 = 2u;
  i2 <<= (i3 & 31);
  i3 = 1060764u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i3 = 11u;
  i2 <<= (i3 & 31);
  i3 = l1;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l2 = i0;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1060764u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 11u;
  i0 <<= (i1 & 31);
  l3 = i0;
  i1 = l1;
  i0 = i0 == i1;
  i1 = l3;
  i2 = l1;
  i1 = i1 < i2;
  i0 += i1;
  i1 = l2;
  i0 += i1;
  l1 = i0;
  i1 = 30u;
  i0 = i0 > i1;
  if (i0) {goto B2;}
  i0 = l1;
  i1 = 2u;
  i0 <<= (i1 & 31);
  l2 = i0;
  i0 = 689u;
  l3 = i0;
  i0 = l1;
  i1 = 30u;
  i0 = i0 == i1;
  if (i0) {goto B3;}
  i0 = l2;
  i1 = 1060768u;
  i0 += i1;
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 21u;
  i0 >>= (i1 & 31);
  l3 = i0;
  B3:;
  i0 = 0u;
  l4 = i0;
  i0 = l1;
  i1 = 4294967295u;
  i0 += i1;
  l5 = i0;
  i1 = l1;
  i0 = i0 > i1;
  if (i0) {goto B4;}
  i0 = l5;
  i1 = 31u;
  i0 = i0 >= i1;
  if (i0) {goto B0;}
  i0 = l5;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1060764u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 2097151u;
  i0 &= i1;
  l4 = i0;
  B4:;
  i0 = l3;
  i1 = l2;
  i2 = 1060764u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 21u;
  i1 >>= (i2 & 31);
  l1 = i1;
  i2 = 1u;
  i1 += i2;
  i0 = i0 == i1;
  if (i0) {goto B5;}
  i0 = p0;
  i1 = l4;
  i0 -= i1;
  l2 = i0;
  i0 = l3;
  i1 = 4294967295u;
  i0 += i1;
  l3 = i0;
  i0 = 0u;
  p0 = i0;
  L6: 
    i0 = l1;
    i1 = 688u;
    i0 = i0 > i1;
    if (i0) {goto B1;}
    i0 = p0;
    i1 = l1;
    i2 = 1060888u;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i0 += i1;
    p0 = i0;
    i1 = l2;
    i0 = i0 > i1;
    if (i0) {goto B5;}
    i0 = l3;
    i1 = l1;
    i2 = 1u;
    i1 += i2;
    l1 = i1;
    i0 = i0 != i1;
    if (i0) {goto L6;}
  B5:;
  i0 = l1;
  i1 = 1u;
  i0 &= i1;
  goto Bfunc;
  B2:;
  i0 = l1;
  i1 = 31u;
  i2 = 1060564u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = l1;
  i1 = 689u;
  i2 = 1060580u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l5;
  i1 = 31u;
  i2 = 1060596u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core7unicode9printable5check17hc49c8dda078b527eE(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4, u32 p5, u32 p6) {
  u32 l7 = 0, l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = 1u;
  l7 = i0;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  i1 = p2;
  i2 = 1u;
  i1 <<= (i2 & 31);
  i0 += i1;
  l8 = i0;
  i0 = p0;
  i1 = 65280u;
  i0 &= i1;
  i1 = 8u;
  i0 >>= (i1 & 31);
  l9 = i0;
  i0 = 0u;
  l10 = i0;
  i0 = p0;
  i1 = 255u;
  i0 &= i1;
  l11 = i0;
  L3: 
    i0 = p1;
    i1 = 2u;
    i0 += i1;
    l12 = i0;
    i0 = l10;
    i1 = p1;
    i1 = i32_load8_u((&memory), (u64)(i1 + 1));
    p2 = i1;
    i0 += i1;
    l13 = i0;
    i0 = p1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    p1 = i0;
    i1 = l9;
    i0 = i0 == i1;
    if (i0) {goto B4;}
    i0 = p1;
    i1 = l9;
    i0 = i0 > i1;
    if (i0) {goto B1;}
    i0 = l13;
    l10 = i0;
    i0 = l12;
    p1 = i0;
    i0 = l12;
    i1 = l8;
    i0 = i0 != i1;
    if (i0) {goto L3;}
    goto B1;
    B4:;
    i0 = l13;
    i1 = l10;
    i0 = i0 < i1;
    if (i0) {goto B5;}
    i0 = l13;
    i1 = p4;
    i0 = i0 > i1;
    if (i0) {goto B2;}
    i0 = p3;
    i1 = l10;
    i0 += i1;
    p1 = i0;
    L7: 
      i0 = p2;
      i0 = !(i0);
      if (i0) {goto B6;}
      i0 = p2;
      i1 = 4294967295u;
      i0 += i1;
      p2 = i0;
      i0 = p1;
      i0 = i32_load8_u((&memory), (u64)(i0));
      l10 = i0;
      i0 = p1;
      i1 = 1u;
      i0 += i1;
      p1 = i0;
      i0 = l10;
      i1 = l11;
      i0 = i0 != i1;
      if (i0) {goto L7;}
    i0 = 0u;
    l7 = i0;
    goto B0;
    B6:;
    i0 = l13;
    l10 = i0;
    i0 = l12;
    p1 = i0;
    i0 = l12;
    i1 = l8;
    i0 = i0 != i1;
    if (i0) {goto L3;}
    goto B1;
    B5:;
  i0 = l10;
  i1 = l13;
  i2 = 1059144u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B2:;
  i0 = l13;
  i1 = p4;
  i2 = 1059144u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = p6;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p5;
  i1 = p6;
  i0 += i1;
  l11 = i0;
  i0 = p0;
  i1 = 65535u;
  i0 &= i1;
  p1 = i0;
  i0 = 1u;
  l7 = i0;
  L9: 
    i0 = p5;
    i1 = 1u;
    i0 += i1;
    l10 = i0;
    i0 = p5;
    i0 = i32_load8_u((&memory), (u64)(i0));
    p2 = i0;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    l13 = i0;
    i1 = 0u;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto B11;}
    i0 = l10;
    p5 = i0;
    goto B10;
    B11:;
    i0 = l10;
    i1 = l11;
    i0 = i0 == i1;
    if (i0) {goto B8;}
    i0 = l13;
    i1 = 127u;
    i0 &= i1;
    i1 = 8u;
    i0 <<= (i1 & 31);
    i1 = p5;
    i1 = i32_load8_u((&memory), (u64)(i1 + 1));
    i0 |= i1;
    p2 = i0;
    i0 = p5;
    i1 = 2u;
    i0 += i1;
    p5 = i0;
    B10:;
    i0 = p1;
    i1 = p2;
    i0 -= i1;
    p1 = i0;
    i1 = 0u;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto B0;}
    i0 = l7;
    i1 = 1u;
    i0 ^= i1;
    l7 = i0;
    i0 = p5;
    i1 = l11;
    i0 = i0 != i1;
    if (i0) {goto L9;}
    goto B0;
  B8:;
  i0 = 1057529u;
  i1 = 43u;
  i2 = 1059160u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l7;
  i1 = 1u;
  i0 &= i1;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3str6traits101__LT_impl_u20_core__slice__SliceIndex_LT_str_GT__u20_for_u20_core__ops__range__Range_LT_usize_GT__GT_5index28__u7b__u7b_closure_u7d__u7d_17h834e63e786a4d85dE(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l1 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l1;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i2 = i32_load((&memory), (u64)(i2));
  i3 = p0;
  i3 = i32_load((&memory), (u64)(i3 + 8));
  i3 = i32_load((&memory), (u64)(i3));
  i4 = 1058840u;
  _ZN4core3str16slice_error_fail17h756d0528f966c096E(i0, i1, i2, i3, i4);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN42__LT_str_u20_as_u20_core__fmt__Display_GT_3fmt17h503be603f26e92cbE(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p2;
  i1 = p0;
  i2 = p1;
  i0 = _ZN4core3fmt9Formatter3pad17h18e6ccc150f9bfbcE(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN41__LT_char_u20_as_u20_core__fmt__Debug_GT_3fmt17hb09a68fda0268a45E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  u64 l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  u64 j0, j1, j2;
  i0 = 1u;
  l2 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 39u;
  i2 = p1;
  i3 = 28u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
  if (i0) {goto B0;}
  i0 = 2u;
  l3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i1 = 4294967287u;
  i0 += i1;
  l4 = i0;
  i1 = 30u;
  i0 = i0 <= i1;
  if (i0) {goto B5;}
  i0 = p0;
  i1 = 92u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  goto B3;
  B5:;
  i0 = 116u;
  l5 = i0;
  i0 = l4;
  switch (i0) {
    case 0: goto B1;
    case 1: goto B6;
    case 2: goto B4;
    case 3: goto B4;
    case 4: goto B7;
    case 5: goto B4;
    case 6: goto B4;
    case 7: goto B4;
    case 8: goto B4;
    case 9: goto B4;
    case 10: goto B4;
    case 11: goto B4;
    case 12: goto B4;
    case 13: goto B4;
    case 14: goto B4;
    case 15: goto B4;
    case 16: goto B4;
    case 17: goto B4;
    case 18: goto B4;
    case 19: goto B4;
    case 20: goto B4;
    case 21: goto B4;
    case 22: goto B4;
    case 23: goto B4;
    case 24: goto B4;
    case 25: goto B3;
    case 26: goto B4;
    case 27: goto B4;
    case 28: goto B4;
    case 29: goto B4;
    case 30: goto B3;
    default: goto B1;
  }
  B7:;
  i0 = 114u;
  l5 = i0;
  goto B1;
  B6:;
  i0 = 110u;
  l5 = i0;
  goto B1;
  B4:;
  i0 = p0;
  i0 = _ZN4core7unicode12unicode_data15grapheme_extend6lookup17h138f528bd4ec82e3E(i0);
  if (i0) {goto B10;}
  i0 = p0;
  i1 = 65536u;
  i0 = i0 < i1;
  if (i0) {goto B13;}
  i0 = p0;
  i1 = 131072u;
  i0 = i0 < i1;
  if (i0) {goto B12;}
  i0 = p0;
  i1 = 4294049296u;
  i0 += i1;
  i1 = 196112u;
  i0 = i0 < i1;
  if (i0) {goto B11;}
  i0 = p0;
  i1 = 4294765749u;
  i0 += i1;
  i1 = 716213u;
  i0 = i0 < i1;
  if (i0) {goto B11;}
  i0 = p0;
  i1 = 4294772194u;
  i0 += i1;
  i1 = 1506u;
  i0 = i0 < i1;
  if (i0) {goto B11;}
  i0 = p0;
  i1 = 4294775839u;
  i0 += i1;
  i1 = 3103u;
  i0 = i0 < i1;
  if (i0) {goto B11;}
  i0 = p0;
  i1 = 4294783326u;
  i0 += i1;
  i1 = 14u;
  i0 = i0 < i1;
  if (i0) {goto B11;}
  i0 = p0;
  i1 = 2097150u;
  i0 &= i1;
  i1 = 178206u;
  i0 = i0 == i1;
  if (i0) {goto B11;}
  i0 = p0;
  i1 = 4294793506u;
  i0 += i1;
  i1 = 34u;
  i0 = i0 < i1;
  if (i0) {goto B11;}
  i0 = p0;
  i1 = 4294789323u;
  i0 += i1;
  i1 = 10u;
  i0 = i0 > i1;
  if (i0) {goto B8;}
  goto B11;
  B13:;
  i0 = p0;
  i1 = 1059176u;
  i2 = 41u;
  i3 = 1059258u;
  i4 = 290u;
  i5 = 1059548u;
  i6 = 309u;
  i0 = _ZN4core7unicode9printable5check17hc49c8dda078b527eE(i0, i1, i2, i3, i4, i5, i6);
  i0 = !(i0);
  if (i0) {goto B11;}
  goto B8;
  B12:;
  i0 = p0;
  i1 = 1059857u;
  i2 = 38u;
  i3 = 1059933u;
  i4 = 175u;
  i5 = 1060108u;
  i6 = 419u;
  i0 = _ZN4core7unicode9printable5check17hc49c8dda078b527eE(i0, i1, i2, i3, i4, i5, i6);
  if (i0) {goto B8;}
  B11:;
  i0 = p0;
  i1 = 1u;
  i0 |= i1;
  i0 = I32_CLZ(i0);
  i1 = 2u;
  i0 >>= (i1 & 31);
  i1 = 7u;
  i0 ^= i1;
  j0 = (u64)(i0);
  j1 = 21474836480ull;
  j0 |= j1;
  l6 = j0;
  goto B9;
  B10:;
  i0 = p0;
  i1 = 1u;
  i0 |= i1;
  i0 = I32_CLZ(i0);
  i1 = 2u;
  i0 >>= (i1 & 31);
  i1 = 7u;
  i0 ^= i1;
  j0 = (u64)(i0);
  j1 = 21474836480ull;
  j0 |= j1;
  l6 = j0;
  B9:;
  i0 = 3u;
  l3 = i0;
  goto B2;
  B8:;
  i0 = 1u;
  l3 = i0;
  goto B2;
  B3:;
  B2:;
  i0 = p0;
  l5 = i0;
  B1:;
  L14: 
    i0 = l3;
    l4 = i0;
    i0 = 92u;
    p0 = i0;
    i0 = 1u;
    l2 = i0;
    i0 = 1u;
    l3 = i0;
    i0 = l4;
    switch (i0) {
      case 0: goto B18;
      case 1: goto B19;
      case 2: goto B15;
      case 3: goto B20;
      default: goto B18;
    }
    B20:;
    j0 = l6;
    j1 = 32ull;
    j0 >>= (j1 & 63);
    i0 = (u32)(j0);
    i1 = 255u;
    i0 &= i1;
    switch (i0) {
      case 0: goto B18;
      case 1: goto B21;
      case 2: goto B22;
      case 3: goto B23;
      case 4: goto B24;
      case 5: goto B17;
      default: goto B18;
    }
    B24:;
    j0 = l6;
    j1 = 18446742978492891135ull;
    j0 &= j1;
    j1 = 12884901888ull;
    j0 |= j1;
    l6 = j0;
    i0 = 117u;
    p0 = i0;
    goto B16;
    B23:;
    j0 = l6;
    j1 = 18446742978492891135ull;
    j0 &= j1;
    j1 = 8589934592ull;
    j0 |= j1;
    l6 = j0;
    i0 = 123u;
    p0 = i0;
    goto B16;
    B22:;
    i0 = l5;
    j1 = l6;
    i1 = (u32)(j1);
    l4 = i1;
    i2 = 2u;
    i1 <<= (i2 & 31);
    i2 = 28u;
    i1 &= i2;
    i0 >>= (i1 & 31);
    i1 = 15u;
    i0 &= i1;
    l3 = i0;
    i1 = 48u;
    i0 |= i1;
    i1 = l3;
    i2 = 87u;
    i1 += i2;
    i2 = l3;
    i3 = 10u;
    i2 = i2 < i3;
    i0 = i2 ? i0 : i1;
    p0 = i0;
    i0 = l4;
    i0 = !(i0);
    if (i0) {goto B25;}
    j0 = l6;
    j1 = 18446744073709551615ull;
    j0 += j1;
    j1 = 4294967295ull;
    j0 &= j1;
    j1 = l6;
    j2 = 18446744069414584320ull;
    j1 &= j2;
    j0 |= j1;
    l6 = j0;
    goto B16;
    B25:;
    j0 = l6;
    j1 = 18446742978492891135ull;
    j0 &= j1;
    j1 = 4294967296ull;
    j0 |= j1;
    l6 = j0;
    goto B16;
    B21:;
    j0 = l6;
    j1 = 18446742978492891135ull;
    j0 &= j1;
    l6 = j0;
    i0 = 125u;
    p0 = i0;
    goto B16;
    B19:;
    i0 = 0u;
    l3 = i0;
    i0 = l5;
    p0 = i0;
    goto B15;
    B18:;
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    i1 = 39u;
    i2 = p1;
    i2 = i32_load((&memory), (u64)(i2 + 28));
    i2 = i32_load((&memory), (u64)(i2 + 16));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    goto Bfunc;
    B17:;
    j0 = l6;
    j1 = 18446742978492891135ull;
    j0 &= j1;
    j1 = 17179869184ull;
    j0 |= j1;
    l6 = j0;
    B16:;
    i0 = 3u;
    l3 = i0;
    B15:;
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    i1 = p0;
    i2 = p1;
    i2 = i32_load((&memory), (u64)(i2 + 28));
    i2 = i32_load((&memory), (u64)(i2 + 16));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    i0 = !(i0);
    if (i0) {goto L14;}
  B0:;
  i0 = l2;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core5slice6memchr7memrchr17heee7616632cba075E(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5;
  i0 = p3;
  i1 = 0u;
  i2 = p3;
  i3 = 4u;
  i4 = p2;
  i5 = 3u;
  i4 &= i5;
  l4 = i4;
  i3 -= i4;
  i4 = 0u;
  i5 = l4;
  i3 = i5 ? i3 : i4;
  l5 = i3;
  i2 -= i3;
  i3 = 7u;
  i2 &= i3;
  i3 = p3;
  i4 = l5;
  i3 = i3 < i4;
  l6 = i3;
  i1 = i3 ? i1 : i2;
  l4 = i1;
  i0 -= i1;
  l7 = i0;
  i0 = p3;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B3;}
  i0 = p3;
  i1 = l5;
  i2 = l6;
  i0 = i2 ? i0 : i1;
  l8 = i0;
  i0 = p2;
  i1 = l7;
  i0 += i1;
  i1 = p2;
  i2 = p3;
  i1 += i2;
  l5 = i1;
  i0 -= i1;
  l6 = i0;
  i0 = l5;
  i1 = 4294967295u;
  i0 += i1;
  l5 = i0;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  l9 = i0;
  L5: 
    i0 = l4;
    i0 = !(i0);
    if (i0) {goto B4;}
    i0 = l6;
    i1 = 1u;
    i0 += i1;
    l6 = i0;
    i0 = l4;
    i1 = 4294967295u;
    i0 += i1;
    l4 = i0;
    i0 = l5;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l10 = i0;
    i0 = l5;
    i1 = 4294967295u;
    i0 += i1;
    l5 = i0;
    i0 = l10;
    i1 = l9;
    i0 = i0 != i1;
    if (i0) {goto L5;}
  i0 = l7;
  i1 = l6;
  i0 -= i1;
  l4 = i0;
  goto B1;
  B4:;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  i1 = 16843009u;
  i0 *= i1;
  l5 = i0;
  L7: 
    i0 = l7;
    l4 = i0;
    i1 = l8;
    i0 = i0 <= i1;
    if (i0) {goto B6;}
    i0 = l4;
    i1 = 4294967288u;
    i0 += i1;
    l7 = i0;
    i0 = p2;
    i1 = l4;
    i0 += i1;
    l6 = i0;
    i1 = 4294967292u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l5;
    i0 ^= i1;
    l10 = i0;
    i1 = 4294967295u;
    i0 ^= i1;
    i1 = l10;
    i2 = 4278124287u;
    i1 += i2;
    i0 &= i1;
    i1 = l6;
    i2 = 4294967288u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = l5;
    i1 ^= i2;
    l6 = i1;
    i2 = 4294967295u;
    i1 ^= i2;
    i2 = l6;
    i3 = 4278124287u;
    i2 += i3;
    i1 &= i2;
    i0 |= i1;
    i1 = 2155905152u;
    i0 &= i1;
    i0 = !(i0);
    if (i0) {goto L7;}
  B6:;
  i0 = l4;
  i1 = p3;
  i0 = i0 > i1;
  if (i0) {goto B2;}
  i0 = p2;
  i1 = 4294967295u;
  i0 += i1;
  l6 = i0;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  l10 = i0;
  L8: 
    i0 = l4;
    if (i0) {goto B9;}
    i0 = 0u;
    l5 = i0;
    goto B0;
    B9:;
    i0 = l6;
    i1 = l4;
    i0 += i1;
    l5 = i0;
    i0 = l4;
    i1 = 4294967295u;
    i0 += i1;
    l4 = i0;
    i0 = l5;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = l10;
    i0 = i0 == i1;
    if (i0) {goto B1;}
    goto L8;
  B3:;
  i0 = l7;
  i1 = p3;
  i2 = 1058144u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B2:;
  i0 = l4;
  i1 = p3;
  i2 = 1058160u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = 1u;
  l5 = i0;
  B0:;
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN4core5slice25slice_index_overflow_fail17h96c96832494e835eE(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = 1058284u;
  i1 = 44u;
  i2 = p0;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN4core3str5lossy9Utf8Lossy10from_bytes17h1fc730ab18994b0dE(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN4core3str5lossy9Utf8Lossy6chunks17ha62e90201a5f69d8E(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN96__LT_core__str__lossy__Utf8LossyChunksIter_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17he3cf0b2f3c5f8b4eE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, 
      l10 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = 0u;
  l4 = i0;
  L18: 
    i0 = l4;
    i1 = 1u;
    i0 += i1;
    l5 = i0;
    i0 = l3;
    i1 = l4;
    i0 += i1;
    l6 = i0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l7 = i0;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    l8 = i0;
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B20;}
    i0 = l5;
    l4 = i0;
    goto B19;
    B20:;
    i0 = l7;
    i1 = 1058582u;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 4294967294u;
    i0 += i1;
    l9 = i0;
    i1 = 2u;
    i0 = i0 > i1;
    if (i0) {goto B24;}
    i0 = l9;
    switch (i0) {
      case 0: goto B23;
      case 1: goto B22;
      case 2: goto B21;
      default: goto B23;
    }
    B24:;
    i0 = l2;
    i1 = l4;
    i0 = i0 < i1;
    if (i0) {goto B15;}
    i0 = l2;
    i1 = l4;
    i0 = i0 <= i1;
    if (i0) {goto B14;}
    i0 = p0;
    i1 = l4;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = p0;
    i1 = l3;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p1;
    i1 = l2;
    i2 = l5;
    i1 -= i2;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = p1;
    i1 = l3;
    i2 = l5;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 12u;
    i0 += i1;
    i1 = 1u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 8u;
    i0 += i1;
    i1 = l6;
    i32_store((&memory), (u64)(i0), i1);
    goto Bfunc;
    B23:;
    i0 = l3;
    i1 = l5;
    i0 += i1;
    l8 = i0;
    i1 = 0u;
    i2 = l2;
    i3 = l5;
    i2 = i2 > i3;
    i0 = i2 ? i0 : i1;
    l7 = i0;
    i1 = 1057345u;
    i2 = l7;
    i0 = i2 ? i0 : i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 192u;
    i0 &= i1;
    i1 = 128u;
    i0 = i0 != i1;
    if (i0) {goto B25;}
    i0 = l4;
    i1 = 2u;
    i0 += i1;
    l4 = i0;
    goto B19;
    B25:;
    i0 = l2;
    i1 = l4;
    i0 = i0 < i1;
    if (i0) {goto B13;}
    i0 = l2;
    i1 = l4;
    i0 = i0 <= i1;
    if (i0) {goto B12;}
    i0 = p1;
    i1 = l8;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = l4;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = p0;
    i1 = l3;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p1;
    i1 = l2;
    i2 = l5;
    i1 -= i2;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = p0;
    i1 = 12u;
    i0 += i1;
    i1 = 1u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 8u;
    i0 += i1;
    i1 = l6;
    i32_store((&memory), (u64)(i0), i1);
    goto Bfunc;
    B22:;
    i0 = l3;
    i1 = l5;
    i0 += i1;
    l10 = i0;
    i1 = 0u;
    i2 = l2;
    i3 = l5;
    i2 = i2 > i3;
    i0 = i2 ? i0 : i1;
    l9 = i0;
    i1 = 1057345u;
    i2 = l9;
    i0 = i2 ? i0 : i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l9 = i0;
    i0 = l7;
    i1 = 4294967072u;
    i0 += i1;
    l7 = i0;
    i1 = 13u;
    i0 = i0 > i1;
    if (i0) {goto B27;}
    i0 = l7;
    switch (i0) {
      case 0: goto B29;
      case 1: goto B27;
      case 2: goto B27;
      case 3: goto B27;
      case 4: goto B27;
      case 5: goto B27;
      case 6: goto B27;
      case 7: goto B27;
      case 8: goto B27;
      case 9: goto B27;
      case 10: goto B27;
      case 11: goto B27;
      case 12: goto B27;
      case 13: goto B28;
      default: goto B29;
    }
    B29:;
    i0 = l9;
    i1 = 224u;
    i0 &= i1;
    i1 = 160u;
    i0 = i0 == i1;
    if (i0) {goto B26;}
    goto B1;
    B28:;
    i0 = l9;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    if (i0) {goto B1;}
    i0 = l9;
    i1 = 255u;
    i0 &= i1;
    i1 = 160u;
    i0 = i0 >= i1;
    if (i0) {goto B1;}
    goto B26;
    B27:;
    i0 = l8;
    i1 = 31u;
    i0 += i1;
    i1 = 255u;
    i0 &= i1;
    i1 = 11u;
    i0 = i0 > i1;
    if (i0) {goto B30;}
    i0 = l9;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    if (i0) {goto B1;}
    i0 = l9;
    i1 = 255u;
    i0 &= i1;
    i1 = 192u;
    i0 = i0 >= i1;
    if (i0) {goto B1;}
    goto B26;
    B30:;
    i0 = l9;
    i1 = 255u;
    i0 &= i1;
    i1 = 191u;
    i0 = i0 > i1;
    if (i0) {goto B1;}
    i0 = l8;
    i1 = 254u;
    i0 &= i1;
    i1 = 238u;
    i0 = i0 != i1;
    if (i0) {goto B1;}
    i0 = l9;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    if (i0) {goto B1;}
    B26:;
    i0 = l3;
    i1 = l4;
    i2 = 2u;
    i1 += i2;
    l5 = i1;
    i0 += i1;
    l8 = i0;
    i1 = 0u;
    i2 = l2;
    i3 = l5;
    i2 = i2 > i3;
    i0 = i2 ? i0 : i1;
    l7 = i0;
    i1 = 1057345u;
    i2 = l7;
    i0 = i2 ? i0 : i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 192u;
    i0 &= i1;
    i1 = 128u;
    i0 = i0 != i1;
    if (i0) {goto B31;}
    i0 = l4;
    i1 = 3u;
    i0 += i1;
    l4 = i0;
    goto B19;
    B31:;
    i0 = l2;
    i1 = l4;
    i0 = i0 < i1;
    if (i0) {goto B11;}
    i0 = l4;
    i1 = 4294967293u;
    i0 = i0 > i1;
    if (i0) {goto B10;}
    i0 = l2;
    i1 = l5;
    i0 = i0 < i1;
    if (i0) {goto B9;}
    i0 = p1;
    i1 = l8;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = l4;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = p0;
    i1 = l3;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p1;
    i1 = l2;
    i2 = l5;
    i1 -= i2;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = p0;
    i1 = 12u;
    i0 += i1;
    i1 = 2u;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 8u;
    i0 += i1;
    i1 = l6;
    i32_store((&memory), (u64)(i0), i1);
    goto Bfunc;
    B21:;
    i0 = l3;
    i1 = l5;
    i0 += i1;
    l10 = i0;
    i1 = 0u;
    i2 = l2;
    i3 = l5;
    i2 = i2 > i3;
    i0 = i2 ? i0 : i1;
    l9 = i0;
    i1 = 1057345u;
    i2 = l9;
    i0 = i2 ? i0 : i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l9 = i0;
    i0 = l7;
    i1 = 4294967056u;
    i0 += i1;
    l7 = i0;
    i1 = 4u;
    i0 = i0 > i1;
    if (i0) {goto B33;}
    i0 = l7;
    switch (i0) {
      case 0: goto B35;
      case 1: goto B33;
      case 2: goto B33;
      case 3: goto B33;
      case 4: goto B34;
      default: goto B35;
    }
    B35:;
    i0 = l9;
    i1 = 112u;
    i0 += i1;
    i1 = 255u;
    i0 &= i1;
    i1 = 48u;
    i0 = i0 < i1;
    if (i0) {goto B32;}
    goto B2;
    B34:;
    i0 = l9;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    if (i0) {goto B2;}
    i0 = l9;
    i1 = 255u;
    i0 &= i1;
    i1 = 144u;
    i0 = i0 >= i1;
    if (i0) {goto B2;}
    goto B32;
    B33:;
    i0 = l9;
    i1 = 255u;
    i0 &= i1;
    i1 = 191u;
    i0 = i0 > i1;
    if (i0) {goto B2;}
    i0 = l8;
    i1 = 15u;
    i0 += i1;
    i1 = 255u;
    i0 &= i1;
    i1 = 2u;
    i0 = i0 > i1;
    if (i0) {goto B2;}
    i0 = l9;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    if (i0) {goto B2;}
    B32:;
    i0 = l3;
    i1 = l4;
    i2 = 2u;
    i1 += i2;
    l5 = i1;
    i0 += i1;
    l8 = i0;
    i1 = 0u;
    i2 = l2;
    i3 = l5;
    i2 = i2 > i3;
    i0 = i2 ? i0 : i1;
    l7 = i0;
    i1 = 1057345u;
    i2 = l7;
    i0 = i2 ? i0 : i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 192u;
    i0 &= i1;
    i1 = 128u;
    i0 = i0 != i1;
    if (i0) {goto B17;}
    i0 = l3;
    i1 = l4;
    i2 = 3u;
    i1 += i2;
    l5 = i1;
    i0 += i1;
    l8 = i0;
    i1 = 0u;
    i2 = l2;
    i3 = l5;
    i2 = i2 > i3;
    i0 = i2 ? i0 : i1;
    l7 = i0;
    i1 = 1057345u;
    i2 = l7;
    i0 = i2 ? i0 : i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 192u;
    i0 &= i1;
    i1 = 128u;
    i0 = i0 != i1;
    if (i0) {goto B16;}
    i0 = l4;
    i1 = 4u;
    i0 += i1;
    l4 = i0;
    B19:;
    i0 = l4;
    i1 = l2;
    i0 = i0 < i1;
    if (i0) {goto L18;}
  i0 = p1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p1;
  i1 = 1057344u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = 1057344u;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B17:;
  i0 = l2;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B8;}
  i0 = l4;
  i1 = 4294967293u;
  i0 = i0 > i1;
  if (i0) {goto B7;}
  i0 = l2;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B6;}
  i0 = p1;
  i1 = l8;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l2;
  i2 = l5;
  i1 -= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B16:;
  i0 = l2;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B5;}
  i0 = l4;
  i1 = 4294967292u;
  i0 = i0 > i1;
  if (i0) {goto B4;}
  i0 = l2;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B3;}
  i0 = p1;
  i1 = l8;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l2;
  i2 = l5;
  i1 -= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B15:;
  i0 = l4;
  i1 = l2;
  i2 = 1058396u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B14:;
  i0 = l5;
  i1 = l2;
  i2 = 1058396u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B13:;
  i0 = l4;
  i1 = l2;
  i2 = 1058492u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B12:;
  i0 = l5;
  i1 = l2;
  i2 = 1058492u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B11:;
  i0 = l4;
  i1 = l2;
  i2 = 1058460u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B10:;
  i0 = l4;
  i1 = l5;
  i2 = 1058460u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B9:;
  i0 = l5;
  i1 = l2;
  i2 = 1058460u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B8:;
  i0 = l4;
  i1 = l2;
  i2 = 1058412u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B7:;
  i0 = l4;
  i1 = l5;
  i2 = 1058412u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B6:;
  i0 = l5;
  i1 = l2;
  i2 = 1058412u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B5:;
  i0 = l4;
  i1 = l2;
  i2 = 1058428u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B4:;
  i0 = l4;
  i1 = l5;
  i2 = 1058428u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B3:;
  i0 = l5;
  i1 = l2;
  i2 = 1058428u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B2:;
  i0 = l2;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B37;}
  i0 = l2;
  i1 = l4;
  i0 = i0 <= i1;
  if (i0) {goto B36;}
  i0 = p1;
  i1 = l10;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l2;
  i2 = l5;
  i1 -= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B37:;
  i0 = l4;
  i1 = l2;
  i2 = 1058444u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B36:;
  i0 = l5;
  i1 = l2;
  i2 = 1058444u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = l2;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B39;}
  i0 = l2;
  i1 = l4;
  i0 = i0 <= i1;
  if (i0) {goto B38;}
  i0 = p1;
  i1 = l10;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l2;
  i2 = l5;
  i1 -= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B39:;
  i0 = l4;
  i1 = l2;
  i2 = 1058476u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B38:;
  i0 = l5;
  i1 = l2;
  i2 = 1058476u;
  _ZN4core5slice20slice_index_len_fail17h4969c86ab59570e3E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 _ZN66__LT_core__str__lossy__Utf8Lossy_u20_as_u20_core__fmt__Display_GT_3fmt17h9396f0cf1136f103E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = p1;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l3;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l3;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  i1 = l3;
  i2 = 8u;
  i1 += i2;
  _ZN96__LT_core__str__lossy__Utf8LossyChunksIter_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17he3cf0b2f3c5f8b4eE(i0, i1);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  L4: 
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 28));
    l4 = i0;
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 20));
    l5 = i0;
    i1 = p1;
    i0 = i0 == i1;
    if (i0) {goto B1;}
    i0 = 1u;
    l6 = i0;
    i0 = p2;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    i1 = p0;
    i2 = l5;
    i3 = p2;
    i3 = i32_load((&memory), (u64)(i3 + 28));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
    if (i0) {goto B0;}
    i0 = l4;
    i0 = !(i0);
    if (i0) {goto B5;}
    i0 = p2;
    i0 = i32_load((&memory), (u64)(i0 + 24));
    i1 = 65533u;
    i2 = p2;
    i2 = i32_load((&memory), (u64)(i2 + 28));
    i2 = i32_load((&memory), (u64)(i2 + 16));
    i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32), 3, i2, i0, i1);
    if (i0) {goto B0;}
    B5:;
    i0 = l3;
    i1 = 16u;
    i0 += i1;
    i1 = l3;
    i2 = 8u;
    i1 += i2;
    _ZN96__LT_core__str__lossy__Utf8LossyChunksIter_u20_as_u20_core__iter__traits__iterator__Iterator_GT_4next17he3cf0b2f3c5f8b4eE(i0, i1);
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    p0 = i0;
    if (i0) {goto L4;}
  B3:;
  i0 = 0u;
  l6 = i0;
  goto B0;
  B2:;
  i0 = p2;
  i1 = 1057344u;
  i2 = 0u;
  i0 = _ZN4core3fmt9Formatter3pad17h18e6ccc150f9bfbcE(i0, i1, i2);
  l6 = i0;
  goto B0;
  B1:;
  i0 = l4;
  if (i0) {goto B6;}
  i0 = p2;
  i1 = p0;
  i2 = p1;
  i0 = _ZN4core3fmt9Formatter3pad17h18e6ccc150f9bfbcE(i0, i1, i2);
  l6 = i0;
  goto B0;
  B6:;
  i0 = 1058508u;
  i1 = 35u;
  i2 = 1058544u;
  _ZN4core9panicking5panic17hab35b75b6c5c31f2E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l3;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = l6;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt3num52__LT_impl_u20_core__fmt__LowerHex_u20_for_u20_i8_GT_3fmt17h6b3e03432bfb2278E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  i0 = g0;
  i1 = 128u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  l3 = i0;
  i0 = 0u;
  p0 = i0;
  L0: 
    i0 = l2;
    i1 = p0;
    i0 += i1;
    i1 = 127u;
    i0 += i1;
    i1 = l3;
    i2 = 15u;
    i1 &= i2;
    l4 = i1;
    i2 = 48u;
    i1 |= i2;
    i2 = l4;
    i3 = 87u;
    i2 += i3;
    i3 = l4;
    i4 = 10u;
    i3 = i3 < i4;
    i1 = i3 ? i1 : i2;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4294967295u;
    i0 += i1;
    p0 = i0;
    i0 = l3;
    i1 = 4u;
    i0 >>= (i1 & 31);
    i1 = 15u;
    i0 &= i1;
    l3 = i0;
    if (i0) {goto L0;}
  i0 = p0;
  i1 = 128u;
  i0 += i1;
  l3 = i0;
  i1 = 129u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = l3;
  i1 = 128u;
  i2 = 1057800u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = p1;
  i1 = 1u;
  i2 = 1057816u;
  i3 = 2u;
  i4 = l2;
  i5 = p0;
  i4 += i5;
  i5 = 128u;
  i4 += i5;
  i5 = 0u;
  i6 = p0;
  i5 -= i6;
  i0 = _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(i0, i1, i2, i3, i4, i5);
  p0 = i0;
  i0 = l2;
  i1 = 128u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3str9from_utf817he6f02ee8cec749d4E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l9 = 0;
  u64 l8 = 0, l10 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1, j2;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = 0u;
  i1 = p1;
  i0 -= i1;
  i1 = 0u;
  i2 = p1;
  i3 = 3u;
  i2 &= i3;
  i0 = i2 ? i0 : i1;
  l3 = i0;
  i0 = p2;
  i1 = 4294967289u;
  i0 += i1;
  i1 = 0u;
  i2 = p2;
  i3 = 7u;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l4 = i0;
  i0 = 0u;
  l5 = i0;
  L4: 
    i0 = p1;
    i1 = l5;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l6 = i0;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    l7 = i0;
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    if (i0) {goto B6;}
    j0 = 1099511627776ull;
    l8 = j0;
    i0 = l6;
    i1 = 1058582u;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 4294967294u;
    i0 += i1;
    l9 = i0;
    i1 = 2u;
    i0 = i0 <= i1;
    if (i0) {goto B7;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B7:;
    i0 = l9;
    switch (i0) {
      case 0: goto B12;
      case 1: goto B11;
      case 2: goto B10;
      default: goto B12;
    }
    B12:;
    i0 = l5;
    i1 = 1u;
    i0 += i1;
    l6 = i0;
    i1 = p2;
    i0 = i0 < i1;
    if (i0) {goto B9;}
    j0 = 0ull;
    l10 = j0;
    goto B1;
    B11:;
    j0 = 0ull;
    l10 = j0;
    i0 = l5;
    i1 = 1u;
    i0 += i1;
    l9 = i0;
    i1 = p2;
    i0 = i0 >= i1;
    if (i0) {goto B1;}
    i0 = p1;
    i1 = l9;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l9 = i0;
    i0 = l6;
    i1 = 4294967072u;
    i0 += i1;
    l6 = i0;
    i1 = 13u;
    i0 = i0 > i1;
    if (i0) {goto B14;}
    i0 = l6;
    switch (i0) {
      case 0: goto B16;
      case 1: goto B14;
      case 2: goto B14;
      case 3: goto B14;
      case 4: goto B14;
      case 5: goto B14;
      case 6: goto B14;
      case 7: goto B14;
      case 8: goto B14;
      case 9: goto B14;
      case 10: goto B14;
      case 11: goto B14;
      case 12: goto B14;
      case 13: goto B15;
      default: goto B16;
    }
    B16:;
    i0 = l9;
    i1 = 224u;
    i0 &= i1;
    i1 = 160u;
    i0 = i0 == i1;
    if (i0) {goto B13;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B15:;
    i0 = l9;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B17;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B17:;
    i0 = l9;
    i1 = 255u;
    i0 &= i1;
    i1 = 160u;
    i0 = i0 < i1;
    if (i0) {goto B13;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B14:;
    i0 = l7;
    i1 = 31u;
    i0 += i1;
    i1 = 255u;
    i0 &= i1;
    i1 = 11u;
    i0 = i0 > i1;
    if (i0) {goto B18;}
    i0 = l9;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B19;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B19:;
    i0 = l9;
    i1 = 255u;
    i0 &= i1;
    i1 = 192u;
    i0 = i0 < i1;
    if (i0) {goto B13;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B18:;
    i0 = l9;
    i1 = 255u;
    i0 &= i1;
    i1 = 191u;
    i0 = i0 <= i1;
    if (i0) {goto B20;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B20:;
    i0 = l7;
    i1 = 254u;
    i0 &= i1;
    i1 = 238u;
    i0 = i0 == i1;
    if (i0) {goto B21;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B21:;
    i0 = l9;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B13;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B13:;
    j0 = 0ull;
    l8 = j0;
    i0 = l5;
    i1 = 2u;
    i0 += i1;
    l6 = i0;
    i1 = p2;
    i0 = i0 >= i1;
    if (i0) {goto B0;}
    i0 = p1;
    i1 = l6;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 192u;
    i0 &= i1;
    i1 = 128u;
    i0 = i0 == i1;
    if (i0) {goto B8;}
    goto B2;
    B10:;
    j0 = 0ull;
    l10 = j0;
    i0 = l5;
    i1 = 1u;
    i0 += i1;
    l9 = i0;
    i1 = p2;
    i0 = i0 >= i1;
    if (i0) {goto B1;}
    i0 = p1;
    i1 = l9;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l9 = i0;
    i0 = l6;
    i1 = 4294967056u;
    i0 += i1;
    l6 = i0;
    i1 = 4u;
    i0 = i0 > i1;
    if (i0) {goto B23;}
    i0 = l6;
    switch (i0) {
      case 0: goto B25;
      case 1: goto B23;
      case 2: goto B23;
      case 3: goto B23;
      case 4: goto B24;
      default: goto B25;
    }
    B25:;
    i0 = l9;
    i1 = 112u;
    i0 += i1;
    i1 = 255u;
    i0 &= i1;
    i1 = 48u;
    i0 = i0 < i1;
    if (i0) {goto B22;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B24:;
    i0 = l9;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B26;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B26:;
    i0 = l9;
    i1 = 255u;
    i0 &= i1;
    i1 = 144u;
    i0 = i0 < i1;
    if (i0) {goto B22;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B23:;
    i0 = l9;
    i1 = 255u;
    i0 &= i1;
    i1 = 191u;
    i0 = i0 <= i1;
    if (i0) {goto B27;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B27:;
    i0 = l7;
    i1 = 15u;
    i0 += i1;
    i1 = 255u;
    i0 &= i1;
    i1 = 2u;
    i0 = i0 <= i1;
    if (i0) {goto B28;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B28:;
    i0 = l9;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 <= (s32)i1);
    if (i0) {goto B22;}
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B22:;
    i0 = l5;
    i1 = 2u;
    i0 += i1;
    l6 = i0;
    i1 = p2;
    i0 = i0 >= i1;
    if (i0) {goto B1;}
    i0 = p1;
    i1 = l6;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 192u;
    i0 &= i1;
    i1 = 128u;
    i0 = i0 != i1;
    if (i0) {goto B2;}
    j0 = 0ull;
    l8 = j0;
    i0 = l5;
    i1 = 3u;
    i0 += i1;
    l6 = i0;
    i1 = p2;
    i0 = i0 >= i1;
    if (i0) {goto B0;}
    i0 = p1;
    i1 = l6;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 192u;
    i0 &= i1;
    i1 = 128u;
    i0 = i0 == i1;
    if (i0) {goto B8;}
    j0 = 3298534883328ull;
    l8 = j0;
    j0 = 4294967296ull;
    l10 = j0;
    goto B0;
    B9:;
    j0 = 4294967296ull;
    l10 = j0;
    i0 = p1;
    i1 = l6;
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 192u;
    i0 &= i1;
    i1 = 128u;
    i0 = i0 != i1;
    if (i0) {goto B0;}
    B8:;
    i0 = l6;
    i1 = 1u;
    i0 += i1;
    l5 = i0;
    goto B5;
    B6:;
    i0 = l3;
    i1 = l5;
    i0 -= i1;
    i1 = 3u;
    i0 &= i1;
    if (i0) {goto B29;}
    i0 = l5;
    i1 = l4;
    i0 = i0 >= i1;
    if (i0) {goto B30;}
    L31: 
      i0 = p1;
      i1 = l5;
      i0 += i1;
      l6 = i0;
      i1 = 4u;
      i0 += i1;
      i0 = i32_load((&memory), (u64)(i0));
      i1 = l6;
      i1 = i32_load((&memory), (u64)(i1));
      i0 |= i1;
      i1 = 2155905152u;
      i0 &= i1;
      if (i0) {goto B30;}
      i0 = l5;
      i1 = 8u;
      i0 += i1;
      l5 = i0;
      i1 = l4;
      i0 = i0 < i1;
      if (i0) {goto L31;}
    B30:;
    i0 = l5;
    i1 = p2;
    i0 = i0 >= i1;
    if (i0) {goto B5;}
    L32: 
      i0 = p1;
      i1 = l5;
      i0 += i1;
      i0 = i32_load8_s((&memory), (u64)(i0));
      i1 = 0u;
      i0 = (u32)((s32)i0 < (s32)i1);
      if (i0) {goto B5;}
      i0 = p2;
      i1 = l5;
      i2 = 1u;
      i1 += i2;
      l5 = i1;
      i0 = i0 != i1;
      if (i0) {goto L32;}
      goto B3;
    B29:;
    i0 = l5;
    i1 = 1u;
    i0 += i1;
    l5 = i0;
    B5:;
    i0 = l5;
    i1 = p2;
    i0 = i0 < i1;
    if (i0) {goto L4;}
  B3:;
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = p2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B2:;
  j0 = 2199023255552ull;
  l8 = j0;
  j0 = 4294967296ull;
  l10 = j0;
  goto B0;
  B1:;
  j0 = 0ull;
  l8 = j0;
  B0:;
  i0 = p0;
  j1 = l10;
  i2 = l5;
  j2 = (u64)(i2);
  j1 |= j2;
  j2 = l8;
  j1 |= j2;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3fmt3num3imp51__LT_impl_u20_core__fmt__Display_u20_for_u20_u8_GT_3fmt17hfd698e1eaf4e0cebE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j0;
  i0 = p0;
  j0 = i64_load8_u((&memory), (u64)(i0));
  i1 = 1u;
  i2 = p1;
  i0 = _ZN4core3fmt3num3imp7fmt_u6417h1d17ceced9d6225fE(j0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3str21__LT_impl_u20_str_GT_4trim17h7b79618a50b556d3E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, 
      l11 = 0, l12 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p1;
  i1 = p2;
  i0 += i1;
  l3 = i0;
  i0 = p2;
  if (i0) {goto B2;}
  i0 = 0u;
  l4 = i0;
  i0 = p1;
  p2 = i0;
  i0 = 0u;
  l5 = i0;
  goto B1;
  B2:;
  i0 = 0u;
  l5 = i0;
  i0 = p1;
  p2 = i0;
  L3: 
    i0 = p2;
    l6 = i0;
    i0 = l5;
    l7 = i0;
    i0 = p2;
    i1 = 1u;
    i0 += i1;
    l5 = i0;
    i0 = p2;
    i0 = i32_load8_s((&memory), (u64)(i0));
    l8 = i0;
    i1 = 4294967295u;
    i0 = (u32)((s32)i0 > (s32)i1);
    if (i0) {goto B6;}
    i0 = l5;
    i1 = l3;
    i0 = i0 != i1;
    if (i0) {goto B8;}
    i0 = 0u;
    l9 = i0;
    i0 = l3;
    p2 = i0;
    goto B7;
    B8:;
    i0 = p2;
    i0 = i32_load8_u((&memory), (u64)(i0 + 1));
    i1 = 63u;
    i0 &= i1;
    l9 = i0;
    i0 = p2;
    i1 = 2u;
    i0 += i1;
    l5 = i0;
    p2 = i0;
    B7:;
    i0 = l8;
    i1 = 31u;
    i0 &= i1;
    l10 = i0;
    i0 = l8;
    i1 = 255u;
    i0 &= i1;
    l8 = i0;
    i1 = 223u;
    i0 = i0 > i1;
    if (i0) {goto B9;}
    i0 = l9;
    i1 = l10;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l8 = i0;
    goto B5;
    B9:;
    i0 = p2;
    i1 = l3;
    i0 = i0 != i1;
    if (i0) {goto B11;}
    i0 = 0u;
    l4 = i0;
    i0 = l5;
    p2 = i0;
    i0 = l3;
    l5 = i0;
    goto B10;
    B11:;
    i0 = p2;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    l4 = i0;
    i0 = p2;
    i1 = 1u;
    i0 += i1;
    p2 = i0;
    l5 = i0;
    B10:;
    i0 = l4;
    i1 = l9;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l9 = i0;
    i0 = l8;
    i1 = 240u;
    i0 = i0 >= i1;
    if (i0) {goto B12;}
    i0 = l9;
    i1 = l10;
    i2 = 12u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l8 = i0;
    goto B4;
    B12:;
    i0 = 0u;
    l4 = i0;
    i0 = 0u;
    l8 = i0;
    i0 = l5;
    i1 = l3;
    i0 = i0 == i1;
    if (i0) {goto B13;}
    i0 = l5;
    i1 = 1u;
    i0 += i1;
    p2 = i0;
    i0 = l5;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    l8 = i0;
    B13:;
    i0 = l9;
    i1 = 6u;
    i0 <<= (i1 & 31);
    i1 = l10;
    i2 = 18u;
    i1 <<= (i2 & 31);
    i2 = 1835008u;
    i1 &= i2;
    i0 |= i1;
    i1 = l8;
    i0 |= i1;
    l8 = i0;
    i1 = 1114112u;
    i0 = i0 != i1;
    if (i0) {goto B4;}
    i0 = l7;
    l5 = i0;
    goto B1;
    B6:;
    i0 = l8;
    i1 = 255u;
    i0 &= i1;
    l8 = i0;
    B5:;
    i0 = l5;
    p2 = i0;
    B4:;
    i0 = p2;
    i1 = l6;
    i0 -= i1;
    i1 = l7;
    i0 += i1;
    l5 = i0;
    i0 = l8;
    i1 = 4294967287u;
    i0 += i1;
    i1 = 5u;
    i0 = i0 < i1;
    if (i0) {goto B14;}
    i0 = l8;
    i1 = 32u;
    i0 = i0 == i1;
    if (i0) {goto B14;}
    i0 = l8;
    i1 = 128u;
    i0 = i0 >= i1;
    if (i0) {goto B15;}
    i0 = l5;
    l4 = i0;
    goto B0;
    B15:;
    i0 = l8;
    i0 = _ZN4core7unicode12unicode_data11white_space6lookup17hc2ed76cfbabc0c2fE(i0);
    if (i0) {goto B14;}
    i0 = l5;
    l4 = i0;
    goto B0;
    B14:;
    i0 = l3;
    i1 = p2;
    i0 = i0 != i1;
    if (i0) {goto L3;}
  i0 = 0u;
  l4 = i0;
  B1:;
  i0 = 0u;
  l7 = i0;
  B0:;
  i0 = l3;
  i1 = p2;
  i0 = i0 == i1;
  if (i0) {goto B16;}
  i0 = l3;
  i1 = p2;
  i0 -= i1;
  l10 = i0;
  L17: 
    i0 = l3;
    i1 = 4294967295u;
    i0 += i1;
    l6 = i0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l8 = i0;
    i1 = 24u;
    i0 <<= (i1 & 31);
    i1 = 24u;
    i0 = (u32)((s32)i0 >> (i1 & 31));
    l9 = i0;
    i1 = 0u;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto B19;}
    i0 = l6;
    l3 = i0;
    goto B18;
    B19:;
    i0 = l6;
    i1 = p2;
    i0 = i0 != i1;
    if (i0) {goto B21;}
    i0 = 0u;
    l8 = i0;
    i0 = l6;
    l3 = i0;
    goto B20;
    B21:;
    i0 = l3;
    i1 = 4294967294u;
    i0 += i1;
    l6 = i0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l8 = i0;
    i1 = 192u;
    i0 &= i1;
    i1 = 128u;
    i0 = i0 == i1;
    if (i0) {goto B22;}
    i0 = l8;
    i1 = 31u;
    i0 &= i1;
    l8 = i0;
    i0 = l6;
    l3 = i0;
    goto B20;
    B22:;
    i0 = l6;
    i1 = p2;
    i0 = i0 != i1;
    if (i0) {goto B24;}
    i0 = 0u;
    l11 = i0;
    i0 = l6;
    l3 = i0;
    goto B23;
    B24:;
    i0 = l3;
    i1 = 4294967293u;
    i0 += i1;
    l6 = i0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    l11 = i0;
    i1 = 192u;
    i0 &= i1;
    i1 = 128u;
    i0 = i0 == i1;
    if (i0) {goto B25;}
    i0 = l11;
    i1 = 15u;
    i0 &= i1;
    l11 = i0;
    i0 = l6;
    l3 = i0;
    goto B23;
    B25:;
    i0 = l6;
    i1 = p2;
    i0 = i0 != i1;
    if (i0) {goto B27;}
    i0 = 0u;
    l12 = i0;
    i0 = l6;
    l3 = i0;
    goto B26;
    B27:;
    i0 = l3;
    i1 = 4294967292u;
    i0 += i1;
    l3 = i0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 7u;
    i0 &= i1;
    i1 = 6u;
    i0 <<= (i1 & 31);
    l12 = i0;
    B26:;
    i0 = l12;
    i1 = l11;
    i2 = 63u;
    i1 &= i2;
    i0 |= i1;
    l11 = i0;
    B23:;
    i0 = l11;
    i1 = 6u;
    i0 <<= (i1 & 31);
    i1 = l8;
    i2 = 63u;
    i1 &= i2;
    i0 |= i1;
    l8 = i0;
    B20:;
    i0 = l8;
    i1 = 6u;
    i0 <<= (i1 & 31);
    i1 = l9;
    i2 = 63u;
    i1 &= i2;
    i0 |= i1;
    l8 = i0;
    i1 = 1114112u;
    i0 = i0 == i1;
    if (i0) {goto B16;}
    B18:;
    i0 = l8;
    i1 = 4294967287u;
    i0 += i1;
    i1 = 5u;
    i0 = i0 < i1;
    if (i0) {goto B29;}
    i0 = l8;
    i1 = 32u;
    i0 = i0 == i1;
    if (i0) {goto B29;}
    i0 = l8;
    i1 = 128u;
    i0 = i0 < i1;
    if (i0) {goto B28;}
    i0 = l8;
    i0 = _ZN4core7unicode12unicode_data11white_space6lookup17hc2ed76cfbabc0c2fE(i0);
    i0 = !(i0);
    if (i0) {goto B28;}
    B29:;
    i0 = l3;
    i1 = p2;
    i0 -= i1;
    l10 = i0;
    i0 = l3;
    i1 = p2;
    i0 = i0 != i1;
    if (i0) {goto L17;}
    goto B16;
    B28:;
  i0 = l10;
  i1 = l5;
  i0 += i1;
  l4 = i0;
  B16:;
  i0 = p0;
  i1 = l4;
  i2 = l7;
  i1 -= i2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = p1;
  i2 = l7;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static u32 _ZN4core7unicode12unicode_data11white_space6lookup17hc2ed76cfbabc0c2fE(u32 p0) {
  u32 l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i1 = 12287u;
  i0 = i0 > i1;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l1 = i0;
  i1 = l1;
  i2 = 1u;
  i1 |= i2;
  l1 = i1;
  i2 = l1;
  i3 = 2u;
  i2 <<= (i3 & 31);
  i3 = 1061580u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i3 = 11u;
  i2 <<= (i3 & 31);
  i3 = p0;
  i4 = 11u;
  i3 <<= (i4 & 31);
  l1 = i3;
  i2 = i2 > i3;
  i0 = i2 ? i0 : i1;
  l2 = i0;
  i1 = l2;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = 1061580u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 11u;
  i1 <<= (i2 & 31);
  l2 = i1;
  i2 = l1;
  i1 = i1 < i2;
  i0 += i1;
  i1 = l2;
  i2 = l1;
  i1 = i1 == i2;
  i0 += i1;
  l1 = i0;
  i1 = 3u;
  i0 = i0 > i1;
  if (i0) {goto B2;}
  i0 = l1;
  i1 = 2u;
  i0 <<= (i1 & 31);
  l3 = i0;
  i0 = 21u;
  l2 = i0;
  i0 = l1;
  i1 = 3u;
  i0 = i0 == i1;
  if (i0) {goto B3;}
  i0 = 21u;
  l2 = i0;
  i0 = l3;
  i1 = 1061584u;
  i0 += i1;
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 21u;
  i0 >>= (i1 & 31);
  l2 = i0;
  B3:;
  i0 = 0u;
  l4 = i0;
  i0 = l1;
  i1 = 4294967295u;
  i0 += i1;
  l5 = i0;
  i1 = l1;
  i0 = i0 > i1;
  if (i0) {goto B4;}
  i0 = l5;
  i1 = 4u;
  i0 = i0 >= i1;
  if (i0) {goto B0;}
  i0 = l5;
  i1 = 2u;
  i0 <<= (i1 & 31);
  i1 = 1061580u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 2097151u;
  i0 &= i1;
  l4 = i0;
  B4:;
  i0 = l2;
  i1 = l3;
  i2 = 1061580u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 21u;
  i1 >>= (i2 & 31);
  l1 = i1;
  i2 = 1u;
  i1 += i2;
  i0 = i0 == i1;
  if (i0) {goto B5;}
  i0 = p0;
  i1 = l4;
  i0 -= i1;
  p0 = i0;
  i0 = l2;
  i1 = 4294967295u;
  i0 += i1;
  l3 = i0;
  i0 = 0u;
  l2 = i0;
  L6: 
    i0 = l1;
    i1 = 20u;
    i0 = i0 > i1;
    if (i0) {goto B1;}
    i0 = l2;
    i1 = l1;
    i2 = 1061596u;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i0 += i1;
    l2 = i0;
    i1 = p0;
    i0 = i0 > i1;
    if (i0) {goto B5;}
    i0 = l3;
    i1 = l1;
    i2 = 1u;
    i1 += i2;
    l1 = i1;
    i0 = i0 != i1;
    if (i0) {goto L6;}
  B5:;
  i0 = l1;
  i1 = 1u;
  i0 &= i1;
  goto Bfunc;
  B2:;
  i0 = l1;
  i1 = 4u;
  i2 = 1060564u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = l1;
  i1 = 21u;
  i2 = 1060580u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l5;
  i1 = 4u;
  i2 = 1060596u;
  _ZN4core9panicking18panic_bounds_check17h55bf0d5c7419f67aE(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core7unicode9printable12is_printable17h481fab4e83051dc0E(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  i0 = p0;
  i1 = 65536u;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 131072u;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = 0u;
  l1 = i0;
  i0 = p0;
  i1 = 4294765749u;
  i0 += i1;
  i1 = 716213u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4294772194u;
  i0 += i1;
  i1 = 1506u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4294775839u;
  i0 += i1;
  i1 = 3103u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4294783326u;
  i0 += i1;
  i1 = 14u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 2097150u;
  i0 &= i1;
  i1 = 178206u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4294793506u;
  i0 += i1;
  i1 = 34u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4294789323u;
  i0 += i1;
  i1 = 11u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 4294049296u;
  i0 += i1;
  i1 = 196111u;
  i0 = i0 > i1;
  goto Bfunc;
  B2:;
  i0 = p0;
  i1 = 1059857u;
  i2 = 38u;
  i3 = 1059933u;
  i4 = 175u;
  i5 = 1060108u;
  i6 = 419u;
  i0 = _ZN4core7unicode9printable5check17hc49c8dda078b527eE(i0, i1, i2, i3, i4, i5, i6);
  l1 = i0;
  B1:;
  i0 = l1;
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = 1059176u;
  i2 = 41u;
  i3 = 1059258u;
  i4 = 290u;
  i5 = 1059548u;
  i6 = 309u;
  i0 = _ZN4core7unicode9printable5check17hc49c8dda078b527eE(i0, i1, i2, i3, i4, i5, i6);
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt3num53__LT_impl_u20_core__fmt__LowerHex_u20_for_u20_i32_GT_3fmt17h4b124e18148b69c3E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  i0 = g0;
  i1 = 128u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = 0u;
  p0 = i0;
  L0: 
    i0 = l2;
    i1 = p0;
    i0 += i1;
    i1 = 127u;
    i0 += i1;
    i1 = l3;
    i2 = 15u;
    i1 &= i2;
    l4 = i1;
    i2 = 48u;
    i1 |= i2;
    i2 = l4;
    i3 = 87u;
    i2 += i3;
    i3 = l4;
    i4 = 10u;
    i3 = i3 < i4;
    i1 = i3 ? i1 : i2;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4294967295u;
    i0 += i1;
    p0 = i0;
    i0 = l3;
    i1 = 4u;
    i0 >>= (i1 & 31);
    l3 = i0;
    if (i0) {goto L0;}
  i0 = p0;
  i1 = 128u;
  i0 += i1;
  l3 = i0;
  i1 = 129u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = l3;
  i1 = 128u;
  i2 = 1057800u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = p1;
  i1 = 1u;
  i2 = 1057816u;
  i3 = 2u;
  i4 = l2;
  i5 = p0;
  i4 += i5;
  i5 = 128u;
  i4 += i5;
  i5 = 0u;
  i6 = p0;
  i5 -= i6;
  i0 = _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(i0, i1, i2, i3, i4, i5);
  p0 = i0;
  i0 = l2;
  i1 = 128u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3num52__LT_impl_u20_core__str__FromStr_u20_for_u20_i32_GT_8from_str17h24ec4dabfaea63f0E(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p0;
  i1 = p1;
  i2 = p2;
  i3 = 10u;
  _ZN4core3num14from_str_radix17ha04c95ba4acb47c5E(i0, i1, i2, i3);
  FUNC_EPILOGUE;
}

static void _ZN4core3num52__LT_impl_u20_core__str__FromStr_u20_for_u20_u32_GT_8from_str17hee1e4ecf1e1de66dE(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l6 = 0;
  u64 l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  u64 j0, j1;
  i0 = p2;
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  goto Bfunc;
  B0:;
  i0 = p1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 43u;
  i0 = i0 != i1;
  if (i0) {goto B2;}
  i0 = p2;
  i1 = 4294967295u;
  i0 += i1;
  p2 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  i1 = 1u;
  i0 += i1;
  p1 = i0;
  B2:;
  i0 = 0u;
  l3 = i0;
  L6: 
    i0 = p2;
    i0 = !(i0);
    if (i0) {goto B3;}
    i0 = p1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 4294967248u;
    i0 += i1;
    l4 = i0;
    i1 = 9u;
    i0 = i0 > i1;
    if (i0) {goto B5;}
    i0 = l3;
    j0 = (u64)(i0);
    j1 = 10ull;
    j0 *= j1;
    l5 = j0;
    j1 = 32ull;
    j0 >>= (j1 & 63);
    i0 = (u32)(j0);
    if (i0) {goto B4;}
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    p1 = i0;
    i0 = p2;
    i1 = 4294967295u;
    i0 += i1;
    p2 = i0;
    j0 = l5;
    i0 = (u32)(j0);
    l6 = i0;
    i1 = l4;
    i0 += i1;
    l3 = i0;
    i1 = l6;
    i0 = i0 >= i1;
    if (i0) {goto L6;}
  i0 = p0;
  i1 = 2u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  goto Bfunc;
  B5:;
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  goto Bfunc;
  B4:;
  i0 = p0;
  i1 = 2u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  goto Bfunc;
  B3:;
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  goto Bfunc;
  B1:;
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 1), i1);
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 _ZN61__LT_core__num__ParseIntError_u20_as_u20_core__fmt__Debug_GT_3fmt17h121cef04e893d4c1E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1060644u;
  i2 = 13u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l3 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = l2;
  i1 = l3;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 1060612u;
  i2 = 4u;
  i3 = l2;
  i4 = 12u;
  i3 += i4;
  i4 = 1060660u;
  i0 = _ZN4core3fmt8builders11DebugStruct5field17h8526abf557e6a496E(i0, i1, i2, i3, i4);
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 5));
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  p0 = i0;
  i0 = 1u;
  p1 = i0;
  i0 = p0;
  if (i0) {goto B1;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i1 = 28u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = i32_load((&memory), (u64)(i0 + 12));
  p0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l3 = i0;
  i0 = p1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 4u;
  i0 &= i1;
  if (i0) {goto B2;}
  i0 = l3;
  i1 = 1057751u;
  i2 = 2u;
  i3 = p0;
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  p1 = i0;
  goto B1;
  B2:;
  i0 = l3;
  i1 = 1057750u;
  i2 = 1u;
  i3 = p0;
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  p1 = i0;
  B1:;
  i0 = l2;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  B0:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  i1 = 0u;
  i0 = i0 != i1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt3num3imp7fmt_u6417h1d17ceced9d6225fE(u64 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l6 = 0, l7 = 0, l8 = 0;
  u64 l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  u64 j0, j1, j2, j3;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = 39u;
  l4 = i0;
  j0 = p0;
  j1 = 10000ull;
  i0 = j0 >= j1;
  if (i0) {goto B1;}
  j0 = p0;
  l5 = j0;
  goto B0;
  B1:;
  i0 = 39u;
  l4 = i0;
  L2: 
    i0 = l3;
    i1 = 9u;
    i0 += i1;
    i1 = l4;
    i0 += i1;
    l6 = i0;
    i1 = 4294967292u;
    i0 += i1;
    j1 = p0;
    j2 = p0;
    j3 = 10000ull;
    j2 = DIV_U(j2, j3);
    l5 = j2;
    j3 = 10000ull;
    j2 *= j3;
    j1 -= j2;
    i1 = (u32)(j1);
    l7 = i1;
    i2 = 65535u;
    i1 &= i2;
    i2 = 100u;
    i1 = DIV_U(i1, i2);
    l8 = i1;
    i2 = 1u;
    i1 <<= (i2 & 31);
    i2 = 1057818u;
    i1 += i2;
    i1 = i32_load16_u((&memory), (u64)(i1));
    i32_store16((&memory), (u64)(i0), i1);
    i0 = l6;
    i1 = 4294967294u;
    i0 += i1;
    i1 = l7;
    i2 = l8;
    i3 = 100u;
    i2 *= i3;
    i1 -= i2;
    i2 = 65535u;
    i1 &= i2;
    i2 = 1u;
    i1 <<= (i2 & 31);
    i2 = 1057818u;
    i1 += i2;
    i1 = i32_load16_u((&memory), (u64)(i1));
    i32_store16((&memory), (u64)(i0), i1);
    i0 = l4;
    i1 = 4294967292u;
    i0 += i1;
    l4 = i0;
    j0 = p0;
    j1 = 99999999ull;
    i0 = j0 > j1;
    l6 = i0;
    j0 = l5;
    p0 = j0;
    i0 = l6;
    if (i0) {goto L2;}
  B0:;
  j0 = l5;
  i0 = (u32)(j0);
  l6 = i0;
  i1 = 99u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B3;}
  i0 = l3;
  i1 = 9u;
  i0 += i1;
  i1 = l4;
  i2 = 4294967294u;
  i1 += i2;
  l4 = i1;
  i0 += i1;
  j1 = l5;
  i1 = (u32)(j1);
  l6 = i1;
  i2 = l6;
  i3 = 65535u;
  i2 &= i3;
  i3 = 100u;
  i2 = DIV_U(i2, i3);
  l6 = i2;
  i3 = 100u;
  i2 *= i3;
  i1 -= i2;
  i2 = 65535u;
  i1 &= i2;
  i2 = 1u;
  i1 <<= (i2 & 31);
  i2 = 1057818u;
  i1 += i2;
  i1 = i32_load16_u((&memory), (u64)(i1));
  i32_store16((&memory), (u64)(i0), i1);
  B3:;
  i0 = l6;
  i1 = 10u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B5;}
  i0 = l3;
  i1 = 9u;
  i0 += i1;
  i1 = l4;
  i2 = 4294967294u;
  i1 += i2;
  l4 = i1;
  i0 += i1;
  i1 = l6;
  i2 = 1u;
  i1 <<= (i2 & 31);
  i2 = 1057818u;
  i1 += i2;
  i1 = i32_load16_u((&memory), (u64)(i1));
  i32_store16((&memory), (u64)(i0), i1);
  goto B4;
  B5:;
  i0 = l3;
  i1 = 9u;
  i0 += i1;
  i1 = l4;
  i2 = 4294967295u;
  i1 += i2;
  l4 = i1;
  i0 += i1;
  i1 = l6;
  i2 = 48u;
  i1 += i2;
  i32_store8((&memory), (u64)(i0), i1);
  B4:;
  i0 = p2;
  i1 = p1;
  i2 = 1057344u;
  i3 = 0u;
  i4 = l3;
  i5 = 9u;
  i4 += i5;
  i5 = l4;
  i4 += i5;
  i5 = 39u;
  i6 = l4;
  i5 -= i6;
  i0 = _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(i0, i1, i2, i3, i4, i5);
  l4 = i0;
  i0 = l3;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  i0 = l4;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt3num52__LT_impl_u20_core__fmt__UpperHex_u20_for_u20_i8_GT_3fmt17h768b96441edb650eE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  i0 = g0;
  i1 = 128u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  l3 = i0;
  i0 = 0u;
  p0 = i0;
  L0: 
    i0 = l2;
    i1 = p0;
    i0 += i1;
    i1 = 127u;
    i0 += i1;
    i1 = l3;
    i2 = 15u;
    i1 &= i2;
    l4 = i1;
    i2 = 48u;
    i1 |= i2;
    i2 = l4;
    i3 = 55u;
    i2 += i3;
    i3 = l4;
    i4 = 10u;
    i3 = i3 < i4;
    i1 = i3 ? i1 : i2;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4294967295u;
    i0 += i1;
    p0 = i0;
    i0 = l3;
    i1 = 4u;
    i0 >>= (i1 & 31);
    i1 = 15u;
    i0 &= i1;
    l3 = i0;
    if (i0) {goto L0;}
  i0 = p0;
  i1 = 128u;
  i0 += i1;
  l3 = i0;
  i1 = 129u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = l3;
  i1 = 128u;
  i2 = 1057800u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = p1;
  i1 = 1u;
  i2 = 1057816u;
  i3 = 2u;
  i4 = l2;
  i5 = p0;
  i4 += i5;
  i5 = 128u;
  i4 += i5;
  i5 = 0u;
  i6 = p0;
  i5 -= i6;
  i0 = _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(i0, i1, i2, i3, i4, i5);
  p0 = i0;
  i0 = l2;
  i1 = 128u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt3num53__LT_impl_u20_core__fmt__UpperHex_u20_for_u20_i32_GT_3fmt17hac44606703ee1b92E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  i0 = g0;
  i1 = 128u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = 0u;
  p0 = i0;
  L0: 
    i0 = l2;
    i1 = p0;
    i0 += i1;
    i1 = 127u;
    i0 += i1;
    i1 = l3;
    i2 = 15u;
    i1 &= i2;
    l4 = i1;
    i2 = 48u;
    i1 |= i2;
    i2 = l4;
    i3 = 55u;
    i2 += i3;
    i3 = l4;
    i4 = 10u;
    i3 = i3 < i4;
    i1 = i3 ? i1 : i2;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4294967295u;
    i0 += i1;
    p0 = i0;
    i0 = l3;
    i1 = 4u;
    i0 >>= (i1 & 31);
    l3 = i0;
    if (i0) {goto L0;}
  i0 = p0;
  i1 = 128u;
  i0 += i1;
  l3 = i0;
  i1 = 129u;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = l3;
  i1 = 128u;
  i2 = 1057800u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B1:;
  i0 = p1;
  i1 = 1u;
  i2 = 1057816u;
  i3 = 2u;
  i4 = l2;
  i5 = p0;
  i4 += i5;
  i5 = 128u;
  i4 += i5;
  i5 = 0u;
  i6 = p0;
  i5 -= i6;
  i0 = _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(i0, i1, i2, i3, i4, i5);
  p0 = i0;
  i0 = l2;
  i1 = 128u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN4core3fmt3num3imp52__LT_impl_u20_core__fmt__Display_u20_for_u20_i32_GT_3fmt17hcf6a92db823ff527E(u32 p0, u32 p1) {
  u64 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j0, j1, j2;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  j0 = (u64)(s64)(s32)(i0);
  l2 = j0;
  j1 = l2;
  j2 = 63ull;
  j1 = (u64)((s64)j1 >> (j2 & 63));
  l2 = j1;
  j0 += j1;
  j1 = l2;
  j0 ^= j1;
  i1 = p0;
  i2 = 4294967295u;
  i1 ^= i2;
  i2 = 31u;
  i1 >>= (i2 & 31);
  i2 = p1;
  i0 = _ZN4core3fmt3num3imp7fmt_u6417h1d17ceced9d6225fE(j0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN53__LT_core__fmt__Error_u20_as_u20_core__fmt__Debug_GT_3fmt17h0546d0fd69e4b730E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1060713u;
  i2 = 5u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h82db6cee448a2919E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  u64 j0, j1;
  i0 = g0;
  i1 = 128u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i1 = 16u;
  i0 &= i1;
  if (i0) {goto B4;}
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  l4 = i0;
  i0 = l3;
  i1 = 32u;
  i0 &= i1;
  if (i0) {goto B3;}
  i0 = l4;
  j0 = (u64)(i0);
  j1 = 255ull;
  j0 &= j1;
  i1 = 1u;
  i2 = p1;
  i0 = _ZN4core3fmt3num3imp7fmt_u6417h1d17ceced9d6225fE(j0, i1, i2);
  p0 = i0;
  goto B2;
  B4:;
  i0 = p0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  l4 = i0;
  i0 = 0u;
  p0 = i0;
  L5: 
    i0 = l2;
    i1 = p0;
    i0 += i1;
    i1 = 127u;
    i0 += i1;
    i1 = l4;
    i2 = 15u;
    i1 &= i2;
    l3 = i1;
    i2 = 48u;
    i1 |= i2;
    i2 = l3;
    i3 = 87u;
    i2 += i3;
    i3 = l3;
    i4 = 10u;
    i3 = i3 < i4;
    i1 = i3 ? i1 : i2;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4294967295u;
    i0 += i1;
    p0 = i0;
    i0 = l4;
    i1 = 4u;
    i0 >>= (i1 & 31);
    i1 = 15u;
    i0 &= i1;
    l4 = i0;
    if (i0) {goto L5;}
  i0 = p0;
  i1 = 128u;
  i0 += i1;
  l4 = i0;
  i1 = 129u;
  i0 = i0 >= i1;
  if (i0) {goto B1;}
  i0 = p1;
  i1 = 1u;
  i2 = 1057816u;
  i3 = 2u;
  i4 = l2;
  i5 = p0;
  i4 += i5;
  i5 = 128u;
  i4 += i5;
  i5 = 0u;
  i6 = p0;
  i5 -= i6;
  i0 = _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(i0, i1, i2, i3, i4, i5);
  p0 = i0;
  goto B2;
  B3:;
  i0 = 0u;
  p0 = i0;
  L6: 
    i0 = l2;
    i1 = p0;
    i0 += i1;
    i1 = 127u;
    i0 += i1;
    i1 = l4;
    i2 = 15u;
    i1 &= i2;
    l3 = i1;
    i2 = 48u;
    i1 |= i2;
    i2 = l3;
    i3 = 55u;
    i2 += i3;
    i3 = l3;
    i4 = 10u;
    i3 = i3 < i4;
    i1 = i3 ? i1 : i2;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = p0;
    i1 = 4294967295u;
    i0 += i1;
    p0 = i0;
    i0 = l4;
    i1 = 4u;
    i0 >>= (i1 & 31);
    i1 = 15u;
    i0 &= i1;
    l4 = i0;
    if (i0) {goto L6;}
  i0 = p0;
  i1 = 128u;
  i0 += i1;
  l4 = i0;
  i1 = 129u;
  i0 = i0 >= i1;
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 1u;
  i2 = 1057816u;
  i3 = 2u;
  i4 = l2;
  i5 = p0;
  i4 += i5;
  i5 = 128u;
  i4 += i5;
  i5 = 0u;
  i6 = p0;
  i5 -= i6;
  i0 = _ZN4core3fmt9Formatter12pad_integral17h398c22a6b8c672bbE(i0, i1, i2, i3, i4, i5);
  p0 = i0;
  B2:;
  i0 = l2;
  i1 = 128u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  goto Bfunc;
  B1:;
  i0 = l4;
  i1 = 128u;
  i2 = 1057800u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  B0:;
  i0 = l4;
  i1 = 128u;
  i2 = 1057800u;
  _ZN4core5slice22slice_index_order_fail17h6f8b3cb780da1131E(i0, i1, i2);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h8ebaddfa97032842E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = l2;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1 + 24));
  i2 = 1060705u;
  i3 = 4u;
  i4 = p1;
  i5 = 28u;
  i4 += i5;
  i4 = i32_load((&memory), (u64)(i4));
  i4 = i32_load((&memory), (u64)(i4 + 12));
  i1 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i4, i1, i2, i3);
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 9), i1);
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p0;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = l2;
  i2 = 12u;
  i1 += i2;
  i2 = 1057760u;
  i0 = _ZN4core3fmt8builders10DebugTuple5field17h16202dfa3a9387a4E(i0, i1, i2);
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  p1 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  p0 = i0;
  i0 = 1u;
  p1 = i0;
  i0 = p0;
  if (i0) {goto B3;}
  i0 = l3;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 9));
  i1 = 255u;
  i0 &= i1;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 4u;
  i0 &= i1;
  if (i0) {goto B4;}
  i0 = 1u;
  p1 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057756u;
  i2 = 1u;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  if (i0) {goto B3;}
  B4:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1057757u;
  i2 = 1u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  p1 = i0;
  B3:;
  i0 = l2;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  B2:;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  i1 = 0u;
  i0 = i0 != i1;
  p1 = i0;
  goto B0;
  B1:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1060709u;
  i2 = 4u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  p1 = i0;
  B0:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17hde16ba6a50b346e4E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i0 = _ZN4core3fmt3num52__LT_impl_u20_core__fmt__Debug_u20_for_u20_usize_GT_3fmt17hd9e5ee56a3abf985E(i0, i1);
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17he1c9497b0427386eE(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = i32_load8_u((&memory), (u64)(i0));
  switch (i0) {
    case 0: goto B3;
    case 1: goto B2;
    case 2: goto B1;
    case 3: goto B0;
    case 4: goto B4;
    default: goto B3;
  }
  B4:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1060621u;
  i2 = 4u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  goto Bfunc;
  B3:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1060616u;
  i2 = 5u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  goto Bfunc;
  B2:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1060693u;
  i2 = 12u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  goto Bfunc;
  B1:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1060685u;
  i2 = 8u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  goto Bfunc;
  B0:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1060676u;
  i2 = 9u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static u32 _ZN57__LT_core__str__Utf8Error_u20_as_u20_core__fmt__Debug_GT_3fmt17hf1ddee02a010aedaE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = 1060718u;
  i2 = 9u;
  i3 = p1;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  l3 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 5), i1);
  i0 = l2;
  i1 = l3;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 1060727u;
  i2 = 11u;
  i3 = l2;
  i4 = 12u;
  i3 += i4;
  i4 = 1060628u;
  i0 = _ZN4core3fmt8builders11DebugStruct5field17h8526abf557e6a496E(i0, i1, i2, i3, i4);
  i0 = l2;
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l2;
  i1 = 1060738u;
  i2 = 9u;
  i3 = l2;
  i4 = 12u;
  i3 += i4;
  i4 = 1060748u;
  i0 = _ZN4core3fmt8builders11DebugStruct5field17h8526abf557e6a496E(i0, i1, i2, i3, i4);
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 4));
  p1 = i0;
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 5));
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  p0 = i0;
  i0 = 1u;
  p1 = i0;
  i0 = p0;
  if (i0) {goto B1;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i1 = 28u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = i32_load((&memory), (u64)(i0 + 12));
  p0 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  l3 = i0;
  i0 = p1;
  i0 = i32_load8_u((&memory), (u64)(i0));
  i1 = 4u;
  i0 &= i1;
  if (i0) {goto B2;}
  i0 = l3;
  i1 = 1057751u;
  i2 = 2u;
  i3 = p0;
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  p1 = i0;
  goto B1;
  B2:;
  i0 = l3;
  i1 = 1057750u;
  i2 = 1u;
  i3 = p0;
  i0 = CALL_INDIRECT(T0, u32 (*)(u32, u32, u32), 8, i3, i0, i1, i2);
  p1 = i0;
  B1:;
  i0 = l2;
  i1 = p1;
  i32_store8((&memory), (u64)(i0 + 4), i1);
  B0:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  i1 = 255u;
  i0 &= i1;
  i1 = 0u;
  i0 = i0 != i1;
  FUNC_EPILOGUE;
  return i0;
}

static const u8 data_segment_data_0[] = {
  0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
  0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x63, 0x61, 0x6c, 0x6c, 
  0x65, 0x64, 0x20, 0x60, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x3a, 0x3a, 
  0x75, 0x6e, 0x77, 0x72, 0x61, 0x70, 0x28, 0x29, 0x60, 0x20, 0x6f, 0x6e, 
  0x20, 0x61, 0x6e, 0x20, 0x60, 0x45, 0x72, 0x72, 0x60, 0x20, 0x76, 0x61, 
  0x6c, 0x75, 0x65, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x4e, 0x61, 0x6d, 0x65, 
  0x3a, 0x20, 0x0a, 0x00, 0x5c, 0x00, 0x10, 0x00, 0x06, 0x00, 0x00, 0x00, 
  0x62, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x44, 0x65, 0x73, 0x63, 
  0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x00, 0x00, 0x00, 
  0x74, 0x00, 0x10, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x62, 0x00, 0x10, 0x00, 
  0x01, 0x00, 0x00, 0x00, 0x59, 0x6f, 0x75, 0x20, 0x69, 0x6e, 0x73, 0x70, 
  0x65, 0x63, 0x74, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x68, 0x61, 0x6e, 
  0x64, 0x69, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x0a, 0x94, 0x00, 0x10, 0x00, 
  0x1c, 0x00, 0x00, 0x00, 0x59, 0x6f, 0x75, 0x20, 0x61, 0x64, 0x6d, 0x69, 
  0x72, 0x65, 0x20, 0x69, 0x74, 0x73, 0x20, 0x62, 0x6c, 0x61, 0x64, 0x65, 
  0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x6e, 0x6f, 0x74, 0x65, 0x20, 0x73, 
  0x6f, 0x6d, 0x65, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x69, 0x6e, 0x74, 
  0x65, 0x72, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x0a, 0x00, 0x00, 
  0xb8, 0x00, 0x10, 0x00, 0x36, 0x00, 0x00, 0x00, 0x66, 0x61, 0x69, 0x6c, 
  0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x72, 0x65, 0x61, 0x64, 0x20, 0x69, 
  0x6e, 0x70, 0x75, 0x74, 0x2e, 0x77, 0x61, 0x73, 0x6d, 0x2e, 0x72, 0x73, 
  0x0d, 0x01, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 
  0x09, 0x00, 0x00, 0x00, 0x31, 0x2e, 0x20, 0x46, 0x6f, 0x72, 0x67, 0x65, 
  0x20, 0x61, 0x20, 0x77, 0x65, 0x61, 0x70, 0x6f, 0x6e, 0x0a, 0x00, 0x00, 
  0x24, 0x01, 0x10, 0x00, 0x12, 0x00, 0x00, 0x00, 0x32, 0x2e, 0x20, 0x53, 
  0x63, 0x72, 0x61, 0x70, 0x20, 0x61, 0x20, 0x77, 0x65, 0x61, 0x70, 0x6f, 
  0x6e, 0x0a, 0x00, 0x00, 0x40, 0x01, 0x10, 0x00, 0x12, 0x00, 0x00, 0x00, 
  0x33, 0x2e, 0x20, 0x49, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x20, 0x61, 
  0x20, 0x77, 0x65, 0x61, 0x70, 0x6f, 0x6e, 0x0a, 0x5c, 0x01, 0x10, 0x00, 
  0x14, 0x00, 0x00, 0x00, 0x34, 0x2e, 0x20, 0x56, 0x69, 0x65, 0x77, 0x20, 
  0x73, 0x74, 0x6f, 0x63, 0x6b, 0x0a, 0x00, 0x00, 0x78, 0x01, 0x10, 0x00, 
  0x0e, 0x00, 0x00, 0x00, 0x35, 0x2e, 0x20, 0x56, 0x69, 0x65, 0x77, 0x20, 
  0x6c, 0x6f, 0x67, 0x0a, 0x90, 0x01, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00, 
  0x36, 0x2e, 0x20, 0x45, 0x78, 0x69, 0x74, 0x0a, 0xa4, 0x01, 0x10, 0x00, 
  0x08, 0x00, 0x00, 0x00, 0x57, 0x68, 0x61, 0x74, 0x27, 0x73, 0x20, 0x74, 
  0x68, 0x65, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x79, 
  0x6f, 0x75, 0x72, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x77, 0x65, 0x61, 0x70, 
  0x6f, 0x6e, 0x3f, 0x0a, 0xb4, 0x01, 0x10, 0x00, 0x24, 0x00, 0x00, 0x00, 
  0x0d, 0x01, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 
  0x05, 0x00, 0x00, 0x00, 0x4e, 0x6f, 0x6e, 0x65, 0x0b, 0x00, 0x00, 0x00, 
  0x18, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 
  0x0d, 0x00, 0x00, 0x00, 0x44, 0x6f, 0x6e, 0x65, 0x21, 0x0a, 0x00, 0x00, 
  0x08, 0x02, 0x10, 0x00, 0x06, 0x00, 0x00, 0x00, 0x59, 0x6f, 0x75, 0x20, 
  0x66, 0x65, 0x65, 0x6c, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x73, 0x65, 0x6c, 
  0x66, 0x20, 0x75, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 
  0x73, 0x63, 0x72, 0x61, 0x70, 0x20, 0x74, 0x68, 0x65, 0x73, 0x65, 0x20, 
  0x6c, 0x65, 0x67, 0x65, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x61, 0x72, 
  0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x73, 0x2c, 0x20, 0x72, 0x75, 0x73, 
  0x74, 0x79, 0x20, 0x74, 0x68, 0x6f, 0x75, 0x67, 0x68, 0x20, 0x74, 0x68, 
  0x65, 0x79, 0x20, 0x6d, 0x61, 0x79, 0x20, 0x62, 0x65, 0x2e, 0x0a, 0x00, 
  0x18, 0x02, 0x10, 0x00, 0x57, 0x00, 0x00, 0x00, 0x57, 0x68, 0x69, 0x63, 
  0x68, 0x20, 0x77, 0x65, 0x61, 0x70, 0x6f, 0x6e, 0x20, 0x64, 0x6f, 0x20, 
  0x79, 0x6f, 0x75, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20, 0x74, 0x6f, 0x20, 
  0x69, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x3f, 0x0a, 0x00, 0x00, 0x00, 
  0x78, 0x02, 0x10, 0x00, 0x25, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x10, 0x00, 
  0x07, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
  0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x69, 0x6e, 0x70, 0x75, 
  0x74, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 
  0x69, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x10, 0x00, 
  0x07, 0x00, 0x00, 0x00, 0x6b, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
  0x45, 0x72, 0x72, 0x6f, 0x72, 0x3a, 0x20, 0x74, 0x6f, 0x6f, 0x20, 0x62, 
  0x69, 0x67, 0x21, 0x0a, 0xe8, 0x02, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00, 
  0x34, 0x30, 0x34, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x66, 0x6f, 0x75, 0x6e, 
  0x64, 0x0a, 0x00, 0x00, 0x00, 0x03, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x00, 
  0x0d, 0x01, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 
  0x0c, 0x00, 0x00, 0x00, 0x59, 0x6f, 0x75, 0x20, 0x72, 0x65, 0x63, 0x61, 
  0x6c, 0x6c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77, 0x65, 0x61, 0x70, 0x6f, 
  0x6e, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x73, 0x61, 0x77, 0x20, 0x6c, 0x61, 
  0x73, 0x74, 0x2e, 0x0a, 0x28, 0x03, 0x10, 0x00, 0x24, 0x00, 0x00, 0x00, 
  0xb8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x10, 0x00, 
  0x01, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 
  0x8e, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x3e, 0x20, 0x00, 0x00, 
  0x74, 0x03, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x10, 0x00, 
  0x07, 0x00, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
  0x65, 0x78, 0x63, 0x61, 0x6c, 0x69, 0x62, 0x75, 0x72, 0x2e, 0x74, 0x78, 
  0x74, 0x43, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x6f, 
  0x70, 0x65, 0x6e, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x3a, 0x20, 0x00, 0x00, 
  0x9d, 0x03, 0x10, 0x00, 0x15, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x10, 0x00, 
  0x07, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 
  0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x72, 0x65, 
  0x61, 0x64, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x66, 0x72, 0x6f, 0x6d, 
  0x20, 0x66, 0x69, 0x6c, 0x65, 0x3a, 0x20, 0x00, 0xcc, 0x03, 0x10, 0x00, 
  0x1f, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 
  0x9a, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x45, 0x78, 0x63, 0x61, 
  0x6c, 0x69, 0x62, 0x75, 0x72, 0x20, 0x00, 0x00, 0x04, 0x04, 0x10, 0x00, 
  0x0a, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 
  0x59, 0x6f, 0x75, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x20, 0x62, 0x6c, 
  0x61, 0x63, 0x6b, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x20, 0x77, 0x68, 0x6f, 
  0x20, 0x68, 0x61, 0x73, 0x20, 0x72, 0x65, 0x63, 0x65, 0x6e, 0x74, 0x6c, 
  0x79, 0x20, 0x62, 0x65, 0x65, 0x6e, 0x20, 0x65, 0x78, 0x69, 0x6c, 0x65, 
  0x64, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 
  0x68, 0x6f, 0x6d, 0x65, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x6c, 0x65, 
  0x61, 0x76, 0x65, 0x2c, 0x20, 0x72, 0x65, 0x6c, 0x75, 0x63, 0x74, 0x61, 
  0x6e, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x70, 0x61, 0x72, 0x74, 0x20, 0x77, 
  0x69, 0x74, 0x68, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x62, 0x75, 0x73, 
  0x74, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x73, 0x68, 0x6f, 0x70, 0x20, 0x77, 
  0x69, 0x74, 0x68, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x79, 0x6f, 0x75, 0x72, 
  0x20, 0x68, 0x61, 0x72, 0x64, 0x2d, 0x66, 0x6f, 0x72, 0x67, 0x65, 0x64, 
  0x20, 0x65, 0x71, 0x75, 0x69, 0x70, 0x6d, 0x65, 0x6e, 0x74, 0x2e, 0x0a, 
  0x2c, 0x04, 0x10, 0x00, 0x9c, 0x00, 0x00, 0x00, 0x41, 0x73, 0x20, 0x79, 
  0x6f, 0x75, 0x20, 0x74, 0x72, 0x61, 0x76, 0x65, 0x6c, 0x20, 0x61, 0x63, 
  0x72, 0x6f, 0x73, 0x73, 0x20, 0x64, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 
  0x20, 0x6c, 0x61, 0x6e, 0x64, 0x73, 0x2c, 0x20, 0x79, 0x6f, 0x75, 0x20, 
  0x73, 0x74, 0x75, 0x6d, 0x62, 0x6c, 0x65, 0x20, 0x75, 0x70, 0x6f, 0x6e, 
  0x20, 0x61, 0x20, 0x74, 0x6f, 0x77, 0x6e, 0x2e, 0x20, 0x49, 0x6e, 0x20, 
  0x69, 0x74, 0x2c, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x66, 0x69, 0x6e, 0x64, 
  0x20, 0x61, 0x6e, 0x20, 0x61, 0x62, 0x61, 0x6e, 0x64, 0x6f, 0x6e, 0x65, 
  0x64, 0x20, 0x61, 0x72, 0x6d, 0x6f, 0x72, 0x79, 0x2e, 0x20, 0x54, 0x68, 
  0x6f, 0x75, 0x67, 0x68, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x74, 0x68, 0x65, 
  0x20, 0x65, 0x71, 0x75, 0x69, 0x70, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x69, 
  0x73, 0x20, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x20, 0x6f, 0x76, 0x65, 
  0x72, 0x2c, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x64, 0x65, 0x63, 0x69, 0x64, 
  0x65, 0x20, 0x74, 0x6f, 0x20, 0x72, 0x65, 0x6e, 0x6e, 0x6f, 0x76, 0x61, 
  0x74, 0x65, 0x20, 0x69, 0x74, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x72, 0x65, 
  0x65, 0x73, 0x74, 0x61, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x20, 0x79, 0x6f, 
  0x75, 0x72, 0x20, 0x62, 0x75, 0x73, 0x74, 0x6c, 0x69, 0x6e, 0x67, 0x20, 
  0x62, 0x6c, 0x61, 0x63, 0x6b, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x69, 0x6e, 
  0x67, 0x20, 0x65, 0x6d, 0x70, 0x69, 0x72, 0x65, 0x2e, 0x0a, 0x00, 0x00, 
  0xd0, 0x04, 0x10, 0x00, 0xda, 0x00, 0x00, 0x00, 0x54, 0x68, 0x69, 0x73, 
  0x20, 0x69, 0x73, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x73, 0x74, 0x6f, 
  0x72, 0x79, 0x20, 0x6f, 0x66, 0x20, 0x68, 0x6f, 0x77, 0x20, 0x79, 0x6f, 
  0x75, 0x20, 0x77, 0x65, 0x6e, 0x74, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 
  0x61, 0x20, 0x73, 0x63, 0x6f, 0x72, 0x6e, 0x65, 0x64, 0x2c, 0x20, 0x70, 
  0x65, 0x6e, 0x6e, 0x69, 0x6c, 0x65, 0x73, 0x73, 0x20, 0x62, 0x6c, 0x61, 
  0x63, 0x6b, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x20, 0x74, 0x6f, 0x2c, 0x20, 
  0x77, 0x65, 0x6c, 0x6c, 0x2c, 0x20, 0x61, 0x20, 0x73, 0x63, 0x6f, 0x72, 
  0x6e, 0x65, 0x64, 0x2c, 0x20, 0x70, 0x65, 0x6e, 0x6e, 0x69, 0x6c, 0x65, 
  0x73, 0x73, 0x20, 0x62, 0x6c, 0x61, 0x63, 0x6b, 0x73, 0x6d, 0x69, 0x74, 
  0x68, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x61, 
  0x67, 0x2e, 0x0a, 0x00, 0xb4, 0x05, 0x10, 0x00, 0x7f, 0x00, 0x00, 0x00, 
  0x0d, 0x01, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 
  0x09, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 
  0xbb, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x76, 0x61, 
  0x6c, 0x69, 0x64, 0x20, 0x63, 0x68, 0x6f, 0x69, 0x63, 0x65, 0x21, 0x0a, 
  0x5c, 0x06, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00, 0x42, 0x79, 0x65, 0x21, 
  0x0a, 0x00, 0x00, 0x00, 0x74, 0x06, 0x10, 0x00, 0x05, 0x00, 0x00, 0x00, 
  0x11, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x12, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 
  0x15, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 
  0x17, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 
  0x1a, 0x00, 0x00, 0x00, 0x2f, 0x72, 0x75, 0x73, 0x74, 0x63, 0x2f, 0x63, 
  0x37, 0x30, 0x38, 0x37, 0x66, 0x65, 0x30, 0x30, 0x64, 0x32, 0x62, 0x61, 
  0x39, 0x31, 0x39, 0x64, 0x66, 0x31, 0x64, 0x38, 0x31, 0x33, 0x63, 0x30, 
  0x34, 0x30, 0x61, 0x35, 0x64, 0x34, 0x37, 0x65, 0x34, 0x33, 0x62, 0x30, 
  0x66, 0x65, 0x37, 0x2f, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 
  0x74, 0x64, 0x2f, 0x69, 0x6f, 0x2f, 0x6d, 0x6f, 0x64, 0x2e, 0x72, 0x73, 
  0xc4, 0x06, 0x10, 0x00, 0x44, 0x00, 0x00, 0x00, 0x55, 0x01, 0x00, 0x00, 
  0x1c, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x64, 
  0x69, 0x64, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 
  0x69, 0x6e, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x55, 0x54, 0x46, 
  0x2d, 0x38, 0x00, 0x00, 0xc4, 0x06, 0x10, 0x00, 0x44, 0x00, 0x00, 0x00, 
  0x87, 0x01, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0xc4, 0x06, 0x10, 0x00, 
  0x44, 0x00, 0x00, 0x00, 0x8b, 0x01, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 
  0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x61, 
  0x69, 0x6c, 0x65, 0x64, 0x3a, 0x20, 0x60, 0x28, 0x6c, 0x65, 0x66, 0x74, 
  0x20, 0x3d, 0x3d, 0x20, 0x72, 0x69, 0x67, 0x68, 0x74, 0x29, 0x60, 0x0a, 
  0x20, 0x20, 0x6c, 0x65, 0x66, 0x74, 0x3a, 0x20, 0x60, 0x60, 0x2c, 0x0a, 
  0x20, 0x72, 0x69, 0x67, 0x68, 0x74, 0x3a, 0x20, 0x60, 0x60, 0x3a, 0x20, 
  0x5c, 0x07, 0x10, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x89, 0x07, 0x10, 0x00, 
  0x0c, 0x00, 0x00, 0x00, 0x95, 0x07, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 
  0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 
  0x61, 0x6e, 0x64, 0x20, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x73, 
  0x6c, 0x69, 0x63, 0x65, 0x73, 0x20, 0x68, 0x61, 0x76, 0x65, 0x20, 0x64, 
  0x69, 0x66, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x65, 0x6e, 
  0x67, 0x74, 0x68, 0x73, 0xb0, 0x07, 0x10, 0x00, 0x34, 0x00, 0x00, 0x00, 
  0x2f, 0x72, 0x75, 0x73, 0x74, 0x63, 0x2f, 0x63, 0x37, 0x30, 0x38, 0x37, 
  0x66, 0x65, 0x30, 0x30, 0x64, 0x32, 0x62, 0x61, 0x39, 0x31, 0x39, 0x64, 
  0x66, 0x31, 0x64, 0x38, 0x31, 0x33, 0x63, 0x30, 0x34, 0x30, 0x61, 0x35, 
  0x64, 0x34, 0x37, 0x65, 0x34, 0x33, 0x62, 0x30, 0x66, 0x65, 0x37, 0x2f, 
  0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 0x2f, 
  0x6d, 0x61, 0x63, 0x72, 0x6f, 0x73, 0x2f, 0x6d, 0x6f, 0x64, 0x2e, 0x72, 
  0x73, 0x00, 0x00, 0x00, 0xec, 0x07, 0x10, 0x00, 0x49, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x2f, 0x72, 0x75, 0x73, 
  0x74, 0x63, 0x2f, 0x63, 0x37, 0x30, 0x38, 0x37, 0x66, 0x65, 0x30, 0x30, 
  0x64, 0x32, 0x62, 0x61, 0x39, 0x31, 0x39, 0x64, 0x66, 0x31, 0x64, 0x38, 
  0x31, 0x33, 0x63, 0x30, 0x34, 0x30, 0x61, 0x35, 0x64, 0x34, 0x37, 0x65, 
  0x34, 0x33, 0x62, 0x30, 0x66, 0x65, 0x37, 0x2f, 0x73, 0x72, 0x63, 0x2f, 
  0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x69, 0x6f, 0x2f, 0x62, 0x75, 
  0x66, 0x66, 0x65, 0x72, 0x65, 0x64, 0x2e, 0x72, 0x73, 0x00, 0x00, 0x00, 
  0x48, 0x08, 0x10, 0x00, 0x49, 0x00, 0x00, 0x00, 0x0c, 0x02, 0x00, 0x00, 
  0x15, 0x00, 0x00, 0x00, 0x48, 0x08, 0x10, 0x00, 0x49, 0x00, 0x00, 0x00, 
  0x0c, 0x02, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x66, 0x61, 0x69, 0x6c, 
  0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x77, 0x72, 0x69, 0x74, 0x65, 0x20, 
  0x74, 0x68, 0x65, 0x20, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x65, 0x64, 
  0x20, 0x64, 0x61, 0x74, 0x61, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64, 0x20, 
  0x60, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x3a, 0x75, 0x6e, 0x77, 
  0x72, 0x61, 0x70, 0x28, 0x29, 0x60, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 
  0x60, 0x4e, 0x6f, 0x6e, 0x65, 0x60, 0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 
  0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x29, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x2c, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x2f, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x32, 0x00, 0x00, 0x00, 0x2f, 0x72, 0x75, 0x73, 0x74, 0x63, 0x2f, 0x63, 
  0x37, 0x30, 0x38, 0x37, 0x66, 0x65, 0x30, 0x30, 0x64, 0x32, 0x62, 0x61, 
  0x39, 0x31, 0x39, 0x64, 0x66, 0x31, 0x64, 0x38, 0x31, 0x33, 0x63, 0x30, 
  0x34, 0x30, 0x61, 0x35, 0x64, 0x34, 0x37, 0x65, 0x34, 0x33, 0x62, 0x30, 
  0x66, 0x65, 0x37, 0x2f, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 
  0x6f, 0x72, 0x65, 0x2f, 0x6d, 0x61, 0x63, 0x72, 0x6f, 0x73, 0x2f, 0x6d, 
  0x6f, 0x64, 0x2e, 0x72, 0x73, 0x00, 0x00, 0x00, 0x58, 0x09, 0x10, 0x00, 
  0x49, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
  0x61, 0x6c, 0x72, 0x65, 0x61, 0x64, 0x79, 0x20, 0x62, 0x6f, 0x72, 0x72, 
  0x6f, 0x77, 0x65, 0x64, 0x2f, 0x72, 0x75, 0x73, 0x74, 0x63, 0x2f, 0x63, 
  0x37, 0x30, 0x38, 0x37, 0x66, 0x65, 0x30, 0x30, 0x64, 0x32, 0x62, 0x61, 
  0x39, 0x31, 0x39, 0x64, 0x66, 0x31, 0x64, 0x38, 0x31, 0x33, 0x63, 0x30, 
  0x34, 0x30, 0x61, 0x35, 0x64, 0x34, 0x37, 0x65, 0x34, 0x33, 0x62, 0x30, 
  0x66, 0x65, 0x37, 0x2f, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 
  0x6f, 0x72, 0x65, 0x2f, 0x63, 0x65, 0x6c, 0x6c, 0x2e, 0x72, 0x73, 0x00, 
  0xc4, 0x09, 0x10, 0x00, 0x43, 0x00, 0x00, 0x00, 0x6e, 0x03, 0x00, 0x00, 
  0x09, 0x00, 0x00, 0x00, 0x61, 0x6c, 0x72, 0x65, 0x61, 0x64, 0x79, 0x20, 
  0x6d, 0x75, 0x74, 0x61, 0x62, 0x6c, 0x79, 0x20, 0x62, 0x6f, 0x72, 0x72, 
  0x6f, 0x77, 0x65, 0x64, 0xc4, 0x09, 0x10, 0x00, 0x43, 0x00, 0x00, 0x00, 
  0x1e, 0x03, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x61, 0x73, 0x73, 0x65, 
  0x72, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 
  0x3a, 0x20, 0x60, 0x28, 0x6c, 0x65, 0x66, 0x74, 0x20, 0x3d, 0x3d, 0x20, 
  0x72, 0x69, 0x67, 0x68, 0x74, 0x29, 0x60, 0x0a, 0x20, 0x20, 0x6c, 0x65, 
  0x66, 0x74, 0x3a, 0x20, 0x60, 0x60, 0x2c, 0x0a, 0x20, 0x72, 0x69, 0x67, 
  0x68, 0x74, 0x3a, 0x20, 0x60, 0x60, 0x00, 0x00, 0x40, 0x0a, 0x10, 0x00, 
  0x2d, 0x00, 0x00, 0x00, 0x6d, 0x0a, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00, 
  0x79, 0x0a, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 
  0x60, 0x3a, 0x20, 0x00, 0x40, 0x0a, 0x10, 0x00, 0x2d, 0x00, 0x00, 0x00, 
  0x6d, 0x0a, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xa4, 0x0a, 0x10, 0x00, 
  0x03, 0x00, 0x00, 0x00, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64, 0x20, 0x60, 
  0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x3a, 0x75, 0x6e, 0x77, 0x72, 
  0x61, 0x70, 0x28, 0x29, 0x60, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 0x60, 
  0x4e, 0x6f, 0x6e, 0x65, 0x60, 0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
  0x34, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 
  0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64, 0x20, 0x60, 0x52, 0x65, 0x73, 0x75, 
  0x6c, 0x74, 0x3a, 0x3a, 0x75, 0x6e, 0x77, 0x72, 0x61, 0x70, 0x28, 0x29, 
  0x60, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x6e, 0x20, 0x60, 0x45, 0x72, 0x72, 
  0x60, 0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x00, 0x38, 0x00, 0x00, 0x00, 
  0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x0a, 0x00, 0x00, 0x00, 0x54, 0x72, 0x69, 0x65, 0x64, 0x20, 0x74, 0x6f, 
  0x20, 0x73, 0x68, 0x72, 0x69, 0x6e, 0x6b, 0x20, 0x74, 0x6f, 0x20, 0x61, 
  0x20, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x63, 0x61, 0x70, 0x61, 
  0x63, 0x69, 0x74, 0x79, 0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x73, 0x72, 0x63, 0x2f, 
  0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x74, 0x68, 0x72, 0x65, 0x61, 
  0x64, 0x2f, 0x6d, 0x6f, 0x64, 0x2e, 0x72, 0x73, 0x9c, 0x0b, 0x10, 0x00, 
  0x18, 0x00, 0x00, 0x00, 0x86, 0x03, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 
  0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 
  0x20, 0x70, 0x61, 0x72, 0x6b, 0x20, 0x73, 0x74, 0x61, 0x74, 0x65, 0x00, 
  0x9c, 0x0b, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 0x94, 0x03, 0x00, 0x00, 
  0x13, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x70, 0x61, 0x72, 0x6b, 
  0x20, 0x73, 0x74, 0x61, 0x74, 0x65, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x67, 
  0x65, 0x64, 0x20, 0x75, 0x6e, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 
  0x64, 0x6c, 0x79, 0x00, 0xf0, 0x0b, 0x10, 0x00, 0x1f, 0x00, 0x00, 0x00, 
  0x9c, 0x0b, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 0x91, 0x03, 0x00, 0x00, 
  0x0d, 0x00, 0x00, 0x00, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x74, 
  0x6f, 0x20, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x20, 0x75, 
  0x6e, 0x69, 0x71, 0x75, 0x65, 0x20, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 
  0x20, 0x49, 0x44, 0x3a, 0x20, 0x62, 0x69, 0x74, 0x73, 0x70, 0x61, 0x63, 
  0x65, 0x20, 0x65, 0x78, 0x68, 0x61, 0x75, 0x73, 0x74, 0x65, 0x64, 0x00, 
  0x9c, 0x0b, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 0x2a, 0x04, 0x00, 0x00, 
  0x11, 0x00, 0x00, 0x00, 0x9c, 0x0b, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 
  0x30, 0x04, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x74, 0x68, 0x72, 0x65, 
  0x61, 0x64, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x20, 0x6d, 0x61, 0x79, 0x20, 
  0x6e, 0x6f, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x20, 
  0x69, 0x6e, 0x74, 0x65, 0x72, 0x69, 0x6f, 0x72, 0x20, 0x6e, 0x75, 0x6c, 
  0x6c, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x00, 0x9c, 0x0b, 0x10, 0x00, 
  0x18, 0x00, 0x00, 0x00, 0x73, 0x04, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 
  0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 
  0x20, 0x73, 0x74, 0x61, 0x74, 0x65, 0x20, 0x69, 0x6e, 0x20, 0x75, 0x6e, 
  0x70, 0x61, 0x72, 0x6b, 0x9c, 0x0b, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 
  0xab, 0x04, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x9c, 0x0b, 0x10, 0x00, 
  0x18, 0x00, 0x00, 0x00, 0xb9, 0x04, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 
  0x22, 0x52, 0x55, 0x53, 0x54, 0x5f, 0x42, 0x41, 0x43, 0x4b, 0x54, 0x52, 
  0x41, 0x43, 0x45, 0x30, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 
  0x74, 0x64, 0x2f, 0x65, 0x6e, 0x76, 0x2e, 0x72, 0x73, 0x66, 0x61, 0x69, 
  0x6c, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x67, 0x65, 0x74, 0x20, 0x65, 
  0x6e, 0x76, 0x69, 0x72, 0x6f, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x76, 
  0x61, 0x72, 0x69, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x60, 0x00, 0x00, 0x00, 
  0x1d, 0x0d, 0x10, 0x00, 0x24, 0x00, 0x00, 0x00, 0xa4, 0x0a, 0x10, 0x00, 
  0x03, 0x00, 0x00, 0x00, 0x0c, 0x0d, 0x10, 0x00, 0x11, 0x00, 0x00, 0x00, 
  0xfb, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 
  0x0c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x00, 
  0x3c, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 
  0x3b, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 
  0xfc, 0x0c, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x61, 0x74, 0x61, 
  0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x64, 0x20, 0x63, 0x6f, 
  0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x61, 0x20, 0x6e, 0x75, 0x6c, 
  0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 
  0x73, 0x74, 0x64, 0x2f, 0x66, 0x66, 0x69, 0x2f, 0x63, 0x5f, 0x73, 0x74, 
  0x72, 0x2e, 0x72, 0x73, 0xb5, 0x0d, 0x10, 0x00, 0x17, 0x00, 0x00, 0x00, 
  0x9f, 0x04, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x73, 0x72, 0x63, 0x2f, 
  0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x69, 0x6f, 0x2f, 0x62, 0x75, 
  0x66, 0x66, 0x65, 0x72, 0x65, 0x64, 0x2e, 0x72, 0x73, 0x00, 0x00, 0x00, 
  0xdc, 0x0d, 0x10, 0x00, 0x19, 0x00, 0x00, 0x00, 0x39, 0x01, 0x00, 0x00, 
  0x0d, 0x00, 0x00, 0x00, 0xdc, 0x0d, 0x10, 0x00, 0x19, 0x00, 0x00, 0x00, 
  0x0c, 0x02, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0xdc, 0x0d, 0x10, 0x00, 
  0x19, 0x00, 0x00, 0x00, 0x0c, 0x02, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 
  0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x77, 0x72, 
  0x69, 0x74, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x75, 0x66, 0x66, 
  0x65, 0x72, 0x65, 0x64, 0x20, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 
  0xdc, 0x0d, 0x10, 0x00, 0x19, 0x00, 0x00, 0x00, 0x46, 0x02, 0x00, 0x00, 
  0x09, 0x00, 0x00, 0x00, 0xdc, 0x0d, 0x10, 0x00, 0x19, 0x00, 0x00, 0x00, 
  0xfd, 0x03, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x75, 0x6e, 0x65, 0x78, 
  0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x20, 0x65, 0x6e, 0x64, 0x20, 0x6f, 
  0x66, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 
  0x6f, 0x73, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x6f, 0x70, 0x65, 0x72, 
  0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x72, 
  0x75, 0x70, 0x74, 0x65, 0x64, 0x77, 0x72, 0x69, 0x74, 0x65, 0x20, 0x7a, 
  0x65, 0x72, 0x6f, 0x74, 0x69, 0x6d, 0x65, 0x64, 0x20, 0x6f, 0x75, 0x74, 
  0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x64, 0x61, 0x74, 0x61, 
  0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x69, 0x6e, 0x70, 0x75, 
  0x74, 0x20, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x6f, 
  0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x77, 0x6f, 0x75, 
  0x6c, 0x64, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x6e, 0x74, 0x69, 
  0x74, 0x79, 0x20, 0x61, 0x6c, 0x72, 0x65, 0x61, 0x64, 0x79, 0x20, 0x65, 
  0x78, 0x69, 0x73, 0x74, 0x73, 0x62, 0x72, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 
  0x70, 0x69, 0x70, 0x65, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x20, 
  0x6e, 0x6f, 0x74, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 
  0x65, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x20, 0x69, 0x6e, 0x20, 
  0x75, 0x73, 0x65, 0x6e, 0x6f, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 
  0x63, 0x74, 0x65, 0x64, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 
  0x6f, 0x6e, 0x20, 0x61, 0x62, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x63, 0x6f, 
  0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 0x73, 
  0x65, 0x74, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 
  0x20, 0x72, 0x65, 0x66, 0x75, 0x73, 0x65, 0x64, 0x70, 0x65, 0x72, 0x6d, 
  0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x64, 0x65, 0x6e, 0x69, 0x65, 
  0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x20, 0x6e, 0x6f, 0x74, 0x20, 
  0x66, 0x6f, 0x75, 0x6e, 0x64, 0x4b, 0x69, 0x6e, 0x64, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
  0x3e, 0x00, 0x00, 0x00, 0x4f, 0x73, 0x63, 0x6f, 0x64, 0x65, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x3f, 0x00, 0x00, 0x00, 0x6b, 0x69, 0x6e, 0x64, 0x6d, 0x65, 0x73, 0x73, 
  0x61, 0x67, 0x65, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x94, 0x0a, 0x10, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x20, 0x28, 0x6f, 0x73, 0x20, 0x65, 0x72, 0x72, 
  0x6f, 0x72, 0x20, 0x29, 0x94, 0x0a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0xe8, 0x0f, 0x10, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x10, 0x00, 
  0x01, 0x00, 0x00, 0x00, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 
  0x74, 0x64, 0x2f, 0x69, 0x6f, 0x2f, 0x69, 0x6d, 0x70, 0x6c, 0x73, 0x2e, 
  0x72, 0x73, 0x00, 0x00, 0x0c, 0x10, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 
  0xdd, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x66, 0x61, 0x69, 0x6c, 
  0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x77, 0x72, 0x69, 0x74, 0x65, 0x20, 
  0x77, 0x68, 0x6f, 0x6c, 0x65, 0x20, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 
  0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20, 0x61, 0x63, 0x63, 0x65, 0x73, 
  0x73, 0x20, 0x73, 0x74, 0x64, 0x69, 0x6e, 0x20, 0x64, 0x75, 0x72, 0x69, 
  0x6e, 0x67, 0x20, 0x73, 0x68, 0x75, 0x74, 0x64, 0x6f, 0x77, 0x6e, 0x73, 
  0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x69, 0x6f, 
  0x2f, 0x73, 0x74, 0x64, 0x69, 0x6f, 0x2e, 0x72, 0x73, 0x00, 0x00, 0x00, 
  0x73, 0x10, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 
  0x19, 0x00, 0x00, 0x00, 0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20, 0x61, 
  0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x73, 0x74, 0x64, 0x6f, 0x75, 0x74, 
  0x20, 0x64, 0x75, 0x72, 0x69, 0x6e, 0x67, 0x20, 0x73, 0x68, 0x75, 0x74, 
  0x64, 0x6f, 0x77, 0x6e, 0x73, 0x10, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 
  0xe7, 0x01, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x66, 0x61, 0x69, 0x6c, 
  0x65, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x20, 
  0x74, 0x6f, 0x20, 0x3a, 0x20, 0x00, 0x00, 0x00, 0xd0, 0x10, 0x10, 0x00, 
  0x13, 0x00, 0x00, 0x00, 0xe3, 0x10, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 
  0x73, 0x10, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 0x36, 0x03, 0x00, 0x00, 
  0x09, 0x00, 0x00, 0x00, 0x73, 0x74, 0x64, 0x6f, 0x75, 0x74, 0x73, 0x72, 
  0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x69, 0x6f, 0x2f, 
  0x6d, 0x6f, 0x64, 0x2e, 0x72, 0x73, 0x00, 0x00, 0x0e, 0x11, 0x10, 0x00, 
  0x14, 0x00, 0x00, 0x00, 0x55, 0x01, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 
  0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x64, 0x69, 0x64, 0x20, 0x6e, 
  0x6f, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x20, 0x76, 
  0x61, 0x6c, 0x69, 0x64, 0x20, 0x55, 0x54, 0x46, 0x2d, 0x38, 0x00, 0x00, 
  0x0e, 0x11, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0x70, 0x04, 0x00, 0x00, 
  0x19, 0x00, 0x00, 0x00, 0x0e, 0x11, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 
  0x5c, 0x05, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 
  0x0c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 
  0x43, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x72, 0x6d, 
  0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x00, 
  0x41, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x45, 0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00, 
  0x0e, 0x11, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0xb0, 0x06, 0x00, 0x00, 
  0x2c, 0x00, 0x00, 0x00, 0x61, 0x74, 0x74, 0x65, 0x6d, 0x70, 0x74, 0x65, 
  0x64, 0x20, 0x74, 0x6f, 0x20, 0x75, 0x73, 0x65, 0x20, 0x61, 0x20, 0x63, 
  0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x76, 0x61, 0x72, 
  0x69, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x74, 
  0x77, 0x6f, 0x20, 0x6d, 0x75, 0x74, 0x65, 0x78, 0x65, 0x73, 0x73, 0x72, 
  0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x73, 0x79, 0x6e, 
  0x63, 0x2f, 0x63, 0x6f, 0x6e, 0x64, 0x76, 0x61, 0x72, 0x2e, 0x72, 0x73, 
  0xfe, 0x11, 0x10, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x3f, 0x02, 0x00, 0x00, 
  0x12, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00, 
  0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x73, 
  0x79, 0x6e, 0x63, 0x2f, 0x6f, 0x6e, 0x63, 0x65, 0x2e, 0x72, 0x73, 0x00, 
  0x3c, 0x12, 0x10, 0x00, 0x17, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 
  0x29, 0x00, 0x00, 0x00, 0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6f, 
  0x6e, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x3a, 0x20, 0x73, 0x74, 
  0x61, 0x74, 0x65, 0x5f, 0x61, 0x6e, 0x64, 0x5f, 0x71, 0x75, 0x65, 0x75, 
  0x65, 0x20, 0x26, 0x20, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x4d, 0x41, 
  0x53, 0x4b, 0x20, 0x3d, 0x3d, 0x20, 0x52, 0x55, 0x4e, 0x4e, 0x49, 0x4e, 
  0x47, 0x00, 0x00, 0x00, 0x3c, 0x12, 0x10, 0x00, 0x17, 0x00, 0x00, 0x00, 
  0xa7, 0x01, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x4f, 0x6e, 0x63, 0x65, 
  0x20, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x20, 0x68, 0x61, 
  0x73, 0x20, 0x70, 0x72, 0x65, 0x76, 0x69, 0x6f, 0x75, 0x73, 0x6c, 0x79, 
  0x20, 0x62, 0x65, 0x65, 0x6e, 0x20, 0x70, 0x6f, 0x69, 0x73, 0x6f, 0x6e, 
  0x65, 0x64, 0x00, 0x00, 0x3c, 0x12, 0x10, 0x00, 0x17, 0x00, 0x00, 0x00, 
  0x8b, 0x01, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x3c, 0x12, 0x10, 0x00, 
  0x17, 0x00, 0x00, 0x00, 0xe8, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
  0x3c, 0x12, 0x10, 0x00, 0x17, 0x00, 0x00, 0x00, 0xf4, 0x01, 0x00, 0x00, 
  0x1e, 0x00, 0x00, 0x00, 0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6f, 
  0x6e, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x3a, 0x20, 0x71, 0x75, 
  0x65, 0x75, 0x65, 0x20, 0x21, 0x3d, 0x20, 0x44, 0x4f, 0x4e, 0x45, 0x73, 
  0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x73, 0x79, 
  0x73, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x61, 0x74, 0x5f, 
  0x65, 0x78, 0x69, 0x74, 0x5f, 0x69, 0x6d, 0x70, 0x2e, 0x72, 0x73, 0x00, 
  0x2b, 0x13, 0x10, 0x00, 0x24, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 
  0x0d, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x20, 0x62, 0x61, 
  0x63, 0x6b, 0x74, 0x72, 0x61, 0x63, 0x65, 0x3a, 0x0a, 0x00, 0x00, 0x00, 
  0x60, 0x13, 0x10, 0x00, 0x11, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 
  0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x4b, 0x00, 0x00, 0x00, 
  0x4c, 0x00, 0x00, 0x00, 0x6e, 0x6f, 0x74, 0x65, 0x3a, 0x20, 0x53, 0x6f, 
  0x6d, 0x65, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x20, 0x61, 
  0x72, 0x65, 0x20, 0x6f, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x64, 0x2c, 0x20, 
  0x72, 0x75, 0x6e, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x60, 0x52, 0x55, 
  0x53, 0x54, 0x5f, 0x42, 0x41, 0x43, 0x4b, 0x54, 0x52, 0x41, 0x43, 0x45, 
  0x3d, 0x66, 0x75, 0x6c, 0x6c, 0x60, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 
  0x20, 0x76, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x65, 0x20, 0x62, 0x61, 0x63, 
  0x6b, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x0a, 0x90, 0x13, 0x10, 0x00, 
  0x58, 0x00, 0x00, 0x00, 0x66, 0x75, 0x6c, 0x6c, 0x3c, 0x75, 0x6e, 0x6b, 
  0x6e, 0x6f, 0x77, 0x6e, 0x3e, 0x5c, 0x78, 0x00, 0xfd, 0x13, 0x10, 0x00, 
  0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 
  0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 
  0x50, 0x6f, 0x69, 0x73, 0x6f, 0x6e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x20, 
  0x7b, 0x20, 0x69, 0x6e, 0x6e, 0x65, 0x72, 0x3a, 0x20, 0x2e, 0x2e, 0x20, 
  0x7d, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 
  0x73, 0x79, 0x73, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x74, 
  0x68, 0x72, 0x65, 0x61, 0x64, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x2e, 0x72, 
  0x73, 0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 
  0x61, 0x69, 0x6c, 0x65, 0x64, 0x3a, 0x20, 0x63, 0x2e, 0x62, 0x6f, 0x72, 
  0x72, 0x6f, 0x77, 0x28, 0x29, 0x2e, 0x69, 0x73, 0x5f, 0x6e, 0x6f, 0x6e, 
  0x65, 0x28, 0x29, 0x00, 0x41, 0x14, 0x10, 0x00, 0x24, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x66, 0x61, 0x74, 0x61, 
  0x6c, 0x20, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x65, 0x72, 
  0x72, 0x6f, 0x72, 0x3a, 0x20, 0x0a, 0x00, 0x00, 0x9c, 0x14, 0x10, 0x00, 
  0x15, 0x00, 0x00, 0x00, 0xb1, 0x14, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x4d, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x00, 0x00, 0x6d, 0x65, 0x6d, 0x6f, 
  0x72, 0x79, 0x20, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 
  0x6e, 0x20, 0x6f, 0x66, 0x20, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 
  0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x00, 0x00, 0xe4, 0x14, 0x10, 0x00, 
  0x15, 0x00, 0x00, 0x00, 0xf9, 0x14, 0x10, 0x00, 0x0d, 0x00, 0x00, 0x00, 
  0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x70, 
  0x61, 0x6e, 0x69, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x72, 0x73, 0x00, 
  0x18, 0x15, 0x10, 0x00, 0x17, 0x00, 0x00, 0x00, 0xb4, 0x00, 0x00, 0x00, 
  0x14, 0x00, 0x00, 0x00, 0x42, 0x6f, 0x78, 0x3c, 0x41, 0x6e, 0x79, 0x3e, 
  0x3c, 0x75, 0x6e, 0x6e, 0x61, 0x6d, 0x65, 0x64, 0x3e, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
  0x4f, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x51, 0x00, 0x00, 0x00, 
  0x52, 0x00, 0x00, 0x00, 0x53, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x56, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0x00, 
  0x58, 0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x00, 0x00, 
  0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x68, 0x72, 0x65, 
  0x61, 0x64, 0x20, 0x27, 0x27, 0x20, 0x70, 0x61, 0x6e, 0x69, 0x63, 0x6b, 
  0x65, 0x64, 0x20, 0x61, 0x74, 0x20, 0x27, 0x27, 0x2c, 0x20, 0x00, 0x00, 
  0xa4, 0x15, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00, 0xac, 0x15, 0x10, 0x00, 
  0x0f, 0x00, 0x00, 0x00, 0xbb, 0x15, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 
  0xb1, 0x14, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x6e, 0x6f, 0x74, 0x65, 
  0x3a, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x60, 
  0x52, 0x55, 0x53, 0x54, 0x5f, 0x42, 0x41, 0x43, 0x4b, 0x54, 0x52, 0x41, 
  0x43, 0x45, 0x3d, 0x31, 0x60, 0x20, 0x65, 0x6e, 0x76, 0x69, 0x72, 0x6f, 
  0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x76, 0x61, 0x72, 0x69, 0x61, 0x62, 
  0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 
  0x79, 0x20, 0x61, 0x20, 0x62, 0x61, 0x63, 0x6b, 0x74, 0x72, 0x61, 0x63, 
  0x65, 0x0a, 0x00, 0x00, 0xe0, 0x15, 0x10, 0x00, 0x4e, 0x00, 0x00, 0x00, 
  0x18, 0x15, 0x10, 0x00, 0x17, 0x00, 0x00, 0x00, 0xa1, 0x01, 0x00, 0x00, 
  0x0f, 0x00, 0x00, 0x00, 0x18, 0x15, 0x10, 0x00, 0x17, 0x00, 0x00, 0x00, 
  0xa2, 0x01, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 
  0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x00, 
  0x5e, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x5f, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 
  0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 
  0x61, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x62, 0x00, 0x00, 0x00, 0x74, 0x68, 0x72, 0x65, 
  0x61, 0x64, 0x20, 0x70, 0x61, 0x6e, 0x69, 0x63, 0x6b, 0x65, 0x64, 0x20, 
  0x77, 0x68, 0x69, 0x6c, 0x65, 0x20, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 
  0x73, 0x69, 0x6e, 0x67, 0x20, 0x70, 0x61, 0x6e, 0x69, 0x63, 0x2e, 0x20, 
  0x61, 0x62, 0x6f, 0x72, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x0a, 0x00, 0x00, 
  0xa0, 0x16, 0x10, 0x00, 0x32, 0x00, 0x00, 0x00, 0x74, 0x68, 0x72, 0x65, 
  0x61, 0x64, 0x20, 0x70, 0x61, 0x6e, 0x69, 0x63, 0x6b, 0x65, 0x64, 0x20, 
  0x77, 0x68, 0x69, 0x6c, 0x65, 0x20, 0x70, 0x61, 0x6e, 0x69, 0x63, 0x6b, 
  0x69, 0x6e, 0x67, 0x2e, 0x20, 0x61, 0x62, 0x6f, 0x72, 0x74, 0x69, 0x6e, 
  0x67, 0x2e, 0x0a, 0x00, 0xdc, 0x16, 0x10, 0x00, 0x2b, 0x00, 0x00, 0x00, 
  0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x69, 0x6e, 
  0x69, 0x74, 0x69, 0x61, 0x74, 0x65, 0x20, 0x70, 0x61, 0x6e, 0x69, 0x63, 
  0x2c, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x20, 0x10, 0x17, 0x10, 0x00, 
  0x20, 0x00, 0x00, 0x00, 0x4e, 0x75, 0x6c, 0x45, 0x72, 0x72, 0x6f, 0x72, 
  0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x63, 0x00, 0x00, 0x00, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x43, 0x75, 0x73, 
  0x74, 0x6f, 0x6d, 0x00, 0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 
  0x55, 0x6e, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x45, 0x6f, 
  0x66, 0x4f, 0x74, 0x68, 0x65, 0x72, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x72, 
  0x75, 0x70, 0x74, 0x65, 0x64, 0x57, 0x72, 0x69, 0x74, 0x65, 0x5a, 0x65, 
  0x72, 0x6f, 0x54, 0x69, 0x6d, 0x65, 0x64, 0x4f, 0x75, 0x74, 0x49, 0x6e, 
  0x76, 0x61, 0x6c, 0x69, 0x64, 0x44, 0x61, 0x74, 0x61, 0x49, 0x6e, 0x76, 
  0x61, 0x6c, 0x69, 0x64, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x57, 0x6f, 0x75, 
  0x6c, 0x64, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x41, 0x6c, 0x72, 0x65, 0x61, 
  0x64, 0x79, 0x45, 0x78, 0x69, 0x73, 0x74, 0x73, 0x42, 0x72, 0x6f, 0x6b, 
  0x65, 0x6e, 0x50, 0x69, 0x70, 0x65, 0x41, 0x64, 0x64, 0x72, 0x4e, 0x6f, 
  0x74, 0x41, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x41, 0x64, 
  0x64, 0x72, 0x49, 0x6e, 0x55, 0x73, 0x65, 0x4e, 0x6f, 0x74, 0x43, 0x6f, 
  0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 
  0x63, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x62, 0x6f, 0x72, 0x74, 0x65, 0x64, 
  0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 
  0x73, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 
  0x6e, 0x52, 0x65, 0x66, 0x75, 0x73, 0x65, 0x64, 0x50, 0x65, 0x72, 0x6d, 
  0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x44, 0x65, 0x6e, 0x69, 0x65, 0x64, 
  0x4e, 0x6f, 0x74, 0x46, 0x6f, 0x75, 0x6e, 0x64, 0x63, 0x61, 0x6e, 0x27, 
  0x74, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x77, 0x69, 0x74, 0x68, 
  0x20, 0x77, 0x65, 0x62, 0x20, 0x61, 0x73, 0x73, 0x65, 0x6d, 0x62, 0x6c, 
  0x79, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 
  0x73, 0x79, 0x73, 0x2f, 0x77, 0x61, 0x73, 0x69, 0x2f, 0x2e, 0x2e, 0x2f, 
  0x77, 0x61, 0x73, 0x6d, 0x2f, 0x63, 0x6f, 0x6e, 0x64, 0x76, 0x61, 0x72, 
  0x2e, 0x72, 0x73, 0x00, 0x6d, 0x18, 0x10, 0x00, 0x26, 0x00, 0x00, 0x00, 
  0x15, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x66, 0x61, 0x69, 0x6c, 
  0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x69, 0x6e, 0x64, 0x20, 0x61, 
  0x20, 0x70, 0x72, 0x65, 0x6f, 0x70, 0x65, 0x6e, 0x65, 0x64, 0x20, 0x66, 
  0x69, 0x6c, 0x65, 0x20, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 
  0x6f, 0x72, 0x20, 0x74, 0x68, 0x72, 0x6f, 0x75, 0x67, 0x68, 0x20, 0x77, 
  0x68, 0x69, 0x63, 0x68, 0x20, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 
  0x62, 0x65, 0x20, 0x6f, 0x70, 0x65, 0x6e, 0x65, 0x64, 0x00, 0x00, 0x00, 
  0xa4, 0x18, 0x10, 0x00, 0x39, 0x00, 0x00, 0x00, 0xdd, 0x18, 0x10, 0x00, 
  0x10, 0x00, 0x00, 0x00, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x20, 0x6d, 0x75, 
  0x73, 0x74, 0x20, 0x62, 0x65, 0x20, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x61, 
  0x64, 0x76, 0x61, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x20, 0x49, 0x6f, 0x53, 
  0x6c, 0x69, 0x63, 0x65, 0x20, 0x62, 0x65, 0x79, 0x6f, 0x6e, 0x64, 0x20, 
  0x69, 0x74, 0x73, 0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x73, 0x72, 
  0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x73, 0x79, 0x73, 
  0x2f, 0x77, 0x61, 0x73, 0x69, 0x2f, 0x69, 0x6f, 0x2e, 0x72, 0x73, 0x00, 
  0x36, 0x19, 0x10, 0x00, 0x19, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 
  0x0d, 0x00, 0x00, 0x00, 0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20, 0x72, 
  0x65, 0x63, 0x75, 0x72, 0x73, 0x69, 0x76, 0x65, 0x6c, 0x79, 0x20, 0x61, 
  0x63, 0x71, 0x75, 0x69, 0x72, 0x65, 0x20, 0x6d, 0x75, 0x74, 0x65, 0x78, 
  0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x73, 
  0x79, 0x73, 0x2f, 0x77, 0x61, 0x73, 0x69, 0x2f, 0x2e, 0x2e, 0x2f, 0x77, 
  0x61, 0x73, 0x6d, 0x2f, 0x6d, 0x75, 0x74, 0x65, 0x78, 0x2e, 0x72, 0x73, 
  0x80, 0x19, 0x10, 0x00, 0x24, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 
  0x09, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x65, 0x72, 0x72, 0x6f, 0x72, 
  0x5f, 0x72, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x73, 0x72, 
  0x63, 0x2f, 0x6c, 0x69, 0x62, 0x73, 0x74, 0x64, 0x2f, 0x73, 0x79, 0x73, 
  0x2f, 0x77, 0x61, 0x73, 0x69, 0x2f, 0x6f, 0x73, 0x2e, 0x72, 0x73, 0x00, 
  0xc6, 0x19, 0x10, 0x00, 0x19, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 
  0x0d, 0x00, 0x00, 0x00, 0xc6, 0x19, 0x10, 0x00, 0x19, 0x00, 0x00, 0x00, 
  0x25, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x72, 0x77, 0x6c, 0x6f, 
  0x63, 0x6b, 0x20, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x20, 0x66, 0x6f, 
  0x72, 0x20, 0x77, 0x72, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 
  0x00, 0x1a, 0x10, 0x00, 0x19, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x65, 0x72, 
  0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x73, 0x75, 
  0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x20, 0x6f, 0x6e, 0x20, 0x77, 
  0x61, 0x73, 0x6d, 0x20, 0x79, 0x65, 0x74, 0x2e, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x12, 0x44, 0x3b, 0x02, 0x3f, 0x2c, 
  0x47, 0x14, 0x3d, 0x33, 0x30, 0x0a, 0x1b, 0x06, 0x46, 0x4b, 0x45, 0x37, 
  0x0f, 0x49, 0x0e, 0x17, 0x03, 0x40, 0x1d, 0x3c, 0x2b, 0x36, 0x1f, 0x4a, 
  0x2d, 0x1c, 0x01, 0x20, 0x25, 0x29, 0x21, 0x08, 0x0c, 0x15, 0x16, 0x22, 
  0x2e, 0x10, 0x38, 0x3e, 0x0b, 0x34, 0x31, 0x18, 0x2f, 0x41, 0x09, 0x39, 
  0x11, 0x23, 0x43, 0x32, 0x42, 0x3a, 0x05, 0x04, 0x26, 0x28, 0x27, 0x0d, 
  0x2a, 0x1e, 0x35, 0x07, 0x1a, 0x48, 0x13, 0x24, 0x4c, 0xff, 0x00, 0x00, 
  0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x00, 0x49, 0x6c, 0x6c, 0x65, 
  0x67, 0x61, 0x6c, 0x20, 0x62, 0x79, 0x74, 0x65, 0x20, 0x73, 0x65, 0x71, 
  0x75, 0x65, 0x6e, 0x63, 0x65, 0x00, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 
  0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x00, 0x52, 0x65, 0x73, 0x75, 0x6c, 
  0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x72, 0x65, 0x70, 0x72, 0x65, 0x73, 
  0x65, 0x6e, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x00, 0x4e, 0x6f, 0x74, 0x20, 
  0x61, 0x20, 0x74, 0x74, 0x79, 0x00, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 
  0x73, 0x69, 0x6f, 0x6e, 0x20, 0x64, 0x65, 0x6e, 0x69, 0x65, 0x64, 0x00, 
  0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6e, 0x6f, 
  0x74, 0x20, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x64, 0x00, 
  0x4e, 0x6f, 0x20, 0x73, 0x75, 0x63, 0x68, 0x20, 0x66, 0x69, 0x6c, 0x65, 
  0x20, 0x6f, 0x72, 0x20, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 
  0x79, 0x00, 0x4e, 0x6f, 0x20, 0x73, 0x75, 0x63, 0x68, 0x20, 0x70, 0x72, 
  0x6f, 0x63, 0x65, 0x73, 0x73, 0x00, 0x46, 0x69, 0x6c, 0x65, 0x20, 0x65, 
  0x78, 0x69, 0x73, 0x74, 0x73, 0x00, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x20, 
  0x74, 0x6f, 0x6f, 0x20, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x20, 0x66, 0x6f, 
  0x72, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x74, 0x79, 0x70, 0x65, 0x00, 
  0x4e, 0x6f, 0x20, 0x73, 0x70, 0x61, 0x63, 0x65, 0x20, 0x6c, 0x65, 0x66, 
  0x74, 0x20, 0x6f, 0x6e, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x00, 
  0x4f, 0x75, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 
  0x79, 0x00, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x62, 
  0x75, 0x73, 0x79, 0x00, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x72, 0x75, 0x70, 
  0x74, 0x65, 0x64, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20, 0x63, 
  0x61, 0x6c, 0x6c, 0x00, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 
  0x20, 0x74, 0x65, 0x6d, 0x70, 0x6f, 0x72, 0x61, 0x72, 0x69, 0x6c, 0x79, 
  0x20, 0x75, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 
  0x00, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x73, 0x65, 0x65, 
  0x6b, 0x00, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x2d, 0x64, 0x65, 0x76, 0x69, 
  0x63, 0x65, 0x20, 0x6c, 0x69, 0x6e, 0x6b, 0x00, 0x52, 0x65, 0x61, 0x64, 
  0x2d, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x20, 0x73, 
  0x79, 0x73, 0x74, 0x65, 0x6d, 0x00, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 
  0x6f, 0x72, 0x79, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x65, 0x6d, 0x70, 0x74, 
  0x79, 0x00, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 
  0x20, 0x72, 0x65, 0x73, 0x65, 0x74, 0x20, 0x62, 0x79, 0x20, 0x70, 0x65, 
  0x65, 0x72, 0x00, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 
  0x20, 0x74, 0x69, 0x6d, 0x65, 0x64, 0x20, 0x6f, 0x75, 0x74, 0x00, 0x43, 
  0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 
  0x66, 0x75, 0x73, 0x65, 0x64, 0x00, 0x48, 0x6f, 0x73, 0x74, 0x20, 0x69, 
  0x73, 0x20, 0x75, 0x6e, 0x72, 0x65, 0x61, 0x63, 0x68, 0x61, 0x62, 0x6c, 
  0x65, 0x00, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x20, 0x69, 0x6e, 
  0x20, 0x75, 0x73, 0x65, 0x00, 0x42, 0x72, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 
  0x70, 0x69, 0x70, 0x65, 0x00, 0x49, 0x2f, 0x4f, 0x20, 0x65, 0x72, 0x72, 
  0x6f, 0x72, 0x00, 0x4e, 0x6f, 0x20, 0x73, 0x75, 0x63, 0x68, 0x20, 0x64, 
  0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x6f, 0x72, 0x20, 0x61, 0x64, 0x64, 
  0x72, 0x65, 0x73, 0x73, 0x00, 0x4e, 0x6f, 0x20, 0x73, 0x75, 0x63, 0x68, 
  0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x00, 0x4e, 0x6f, 0x74, 0x20, 
  0x61, 0x20, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x00, 
  0x49, 0x73, 0x20, 0x61, 0x20, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 
  0x72, 0x79, 0x00, 0x54, 0x65, 0x78, 0x74, 0x20, 0x66, 0x69, 0x6c, 0x65, 
  0x20, 0x62, 0x75, 0x73, 0x79, 0x00, 0x45, 0x78, 0x65, 0x63, 0x20, 0x66, 
  0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x00, 
  0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x61, 0x72, 0x67, 0x75, 
  0x6d, 0x65, 0x6e, 0x74, 0x00, 0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 
  0x74, 0x20, 0x6c, 0x69, 0x73, 0x74, 0x20, 0x74, 0x6f, 0x6f, 0x20, 0x6c, 
  0x6f, 0x6e, 0x67, 0x00, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 
  0x20, 0x6c, 0x69, 0x6e, 0x6b, 0x20, 0x6c, 0x6f, 0x6f, 0x70, 0x00, 0x46, 
  0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x20, 0x74, 0x6f, 0x6f, 0x20, 
  0x6c, 0x6f, 0x6e, 0x67, 0x00, 0x54, 0x6f, 0x6f, 0x20, 0x6d, 0x61, 0x6e, 
  0x79, 0x20, 0x6f, 0x70, 0x65, 0x6e, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x73, 
  0x20, 0x69, 0x6e, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x00, 0x4e, 
  0x6f, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x20, 0x64, 0x65, 0x73, 0x63, 0x72, 
  0x69, 0x70, 0x74, 0x6f, 0x72, 0x73, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6c, 
  0x61, 0x62, 0x6c, 0x65, 0x00, 0x42, 0x61, 0x64, 0x20, 0x66, 0x69, 0x6c, 
  0x65, 0x20, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 
  0x00, 0x4e, 0x6f, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x70, 0x72, 
  0x6f, 0x63, 0x65, 0x73, 0x73, 0x00, 0x42, 0x61, 0x64, 0x20, 0x61, 0x64, 
  0x64, 0x72, 0x65, 0x73, 0x73, 0x00, 0x46, 0x69, 0x6c, 0x65, 0x20, 0x74, 
  0x6f, 0x6f, 0x20, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x00, 0x54, 0x6f, 0x6f, 
  0x20, 0x6d, 0x61, 0x6e, 0x79, 0x20, 0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x00, 
  0x4e, 0x6f, 0x20, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x20, 0x61, 0x76, 0x61, 
  0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x00, 0x52, 0x65, 0x73, 0x6f, 0x75, 
  0x72, 0x63, 0x65, 0x20, 0x64, 0x65, 0x61, 0x64, 0x6c, 0x6f, 0x63, 0x6b, 
  0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x63, 0x63, 0x75, 0x72, 
  0x00, 0x53, 0x74, 0x61, 0x74, 0x65, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x72, 
  0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x61, 0x62, 0x6c, 0x65, 0x00, 0x50, 
  0x72, 0x65, 0x76, 0x69, 0x6f, 0x75, 0x73, 0x20, 0x6f, 0x77, 0x6e, 0x65, 
  0x72, 0x20, 0x64, 0x69, 0x65, 0x64, 0x00, 0x4f, 0x70, 0x65, 0x72, 0x61, 
  0x74, 0x69, 0x6f, 0x6e, 0x20, 0x63, 0x61, 0x6e, 0x63, 0x65, 0x6c, 0x65, 
  0x64, 0x00, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6e, 
  0x6f, 0x74, 0x20, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 
  0x65, 0x64, 0x00, 0x4e, 0x6f, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 
  0x65, 0x20, 0x6f, 0x66, 0x20, 0x64, 0x65, 0x73, 0x69, 0x72, 0x65, 0x64, 
  0x20, 0x74, 0x79, 0x70, 0x65, 0x00, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 
  0x66, 0x69, 0x65, 0x72, 0x20, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x64, 
  0x00, 0x4c, 0x69, 0x6e, 0x6b, 0x20, 0x68, 0x61, 0x73, 0x20, 0x62, 0x65, 
  0x65, 0x6e, 0x20, 0x73, 0x65, 0x76, 0x65, 0x72, 0x65, 0x64, 0x00, 0x50, 
  0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x20, 0x65, 0x72, 0x72, 0x6f, 
  0x72, 0x00, 0x42, 0x61, 0x64, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 
  0x65, 0x00, 0x4e, 0x6f, 0x74, 0x20, 0x61, 0x20, 0x73, 0x6f, 0x63, 0x6b, 
  0x65, 0x74, 0x00, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 
  0x6f, 0x6e, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x20, 0x72, 
  0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x00, 0x4d, 0x65, 0x73, 0x73, 
  0x61, 0x67, 0x65, 0x20, 0x74, 0x6f, 0x6f, 0x20, 0x6c, 0x61, 0x72, 0x67, 
  0x65, 0x00, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x20, 0x77, 
  0x72, 0x6f, 0x6e, 0x67, 0x20, 0x74, 0x79, 0x70, 0x65, 0x20, 0x66, 0x6f, 
  0x72, 0x20, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x00, 0x50, 0x72, 0x6f, 
  0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x61, 0x76, 
  0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x00, 0x50, 0x72, 0x6f, 0x74, 
  0x6f, 0x63, 0x6f, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x73, 0x75, 0x70, 
  0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x00, 0x4e, 0x6f, 0x74, 0x20, 0x73, 
  0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x00, 0x41, 0x64, 0x64, 
  0x72, 0x65, 0x73, 0x73, 0x20, 0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x20, 
  0x6e, 0x6f, 0x74, 0x20, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 
  0x64, 0x20, 0x62, 0x79, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 
  0x6c, 0x00, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x20, 0x6e, 0x6f, 
  0x74, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x00, 
  0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x69, 0x73, 0x20, 0x64, 
  0x6f, 0x77, 0x6e, 0x00, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 
  0x75, 0x6e, 0x72, 0x65, 0x61, 0x63, 0x68, 0x61, 0x62, 0x6c, 0x65, 0x00, 
  0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x72, 
  0x65, 0x73, 0x65, 0x74, 0x20, 0x62, 0x79, 0x20, 0x6e, 0x65, 0x74, 0x77, 
  0x6f, 0x72, 0x6b, 0x00, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 
  0x6f, 0x6e, 0x20, 0x61, 0x62, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x00, 0x4e, 
  0x6f, 0x20, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x20, 0x73, 0x70, 0x61, 
  0x63, 0x65, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 
  0x00, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x20, 0x69, 0x73, 0x20, 0x63, 
  0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65, 0x64, 0x00, 0x53, 0x6f, 0x63, 
  0x6b, 0x65, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x6e, 
  0x65, 0x63, 0x74, 0x65, 0x64, 0x00, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 
  0x69, 0x6f, 0x6e, 0x20, 0x61, 0x6c, 0x72, 0x65, 0x61, 0x64, 0x79, 0x20, 
  0x69, 0x6e, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x00, 
  0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x69, 0x6e, 
  0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x00, 0x53, 0x74, 
  0x61, 0x6c, 0x65, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x20, 0x68, 0x61, 0x6e, 
  0x64, 0x6c, 0x65, 0x00, 0x51, 0x75, 0x6f, 0x74, 0x61, 0x20, 0x65, 0x78, 
  0x63, 0x65, 0x65, 0x64, 0x65, 0x64, 0x00, 0x4d, 0x75, 0x6c, 0x74, 0x69, 
  0x68, 0x6f, 0x70, 0x20, 0x61, 0x74, 0x74, 0x65, 0x6d, 0x70, 0x74, 0x65, 
  0x64, 0x00, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 
  0x65, 0x73, 0x20, 0x69, 0x6e, 0x73, 0x75, 0x66, 0x66, 0x69, 0x63, 0x69, 
  0x65, 0x6e, 0x74, 0x00, 0x4e, 0x6f, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 
  0x20, 0x69, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 
  0x00, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 
  0x69, 0x00, 0x00, 0x00, 0x2f, 0x72, 0x75, 0x73, 0x74, 0x63, 0x2f, 0x63, 
  0x37, 0x30, 0x38, 0x37, 0x66, 0x65, 0x30, 0x30, 0x64, 0x32, 0x62, 0x61, 
  0x39, 0x31, 0x39, 0x64, 0x66, 0x31, 0x64, 0x38, 0x31, 0x33, 0x63, 0x30, 
  0x34, 0x30, 0x61, 0x35, 0x64, 0x34, 0x37, 0x65, 0x34, 0x33, 0x62, 0x30, 
  0x66, 0x65, 0x37, 0x2f, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 
  0x6f, 0x72, 0x65, 0x2f, 0x66, 0x6d, 0x74, 0x2f, 0x6d, 0x6f, 0x64, 0x2e, 
  0x72, 0x73, 0x00, 0x00, 0xe0, 0x20, 0x10, 0x00, 0x46, 0x00, 0x00, 0x00, 
  0x68, 0x01, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x6a, 0x00, 0x00, 0x00, 
  0x61, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x74, 0x69, 0x6e, 0x67, 
  0x20, 0x74, 0x72, 0x61, 0x69, 0x74, 0x20, 0x69, 0x6d, 0x70, 0x6c, 0x65, 
  0x6d, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 
  0x74, 0x75, 0x72, 0x6e, 0x65, 0x64, 0x20, 0x61, 0x6e, 0x20, 0x65, 0x72, 
  0x72, 0x6f, 0x72, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x61, 0x6c, 
  0x6c, 0x6f, 0x63, 0x2f, 0x66, 0x6d, 0x74, 0x2e, 0x72, 0x73, 0x00, 0x00, 
  0x7b, 0x21, 0x10, 0x00, 0x13, 0x00, 0x00, 0x00, 0x4a, 0x02, 0x00, 0x00, 
  0x05, 0x00, 0x00, 0x00, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x61, 
  0x6c, 0x6c, 0x6f, 0x63, 0x2f, 0x72, 0x61, 0x77, 0x5f, 0x76, 0x65, 0x63, 
  0x2e, 0x72, 0x73, 0x63, 0x61, 0x70, 0x61, 0x63, 0x69, 0x74, 0x79, 0x20, 
  0x6f, 0x76, 0x65, 0x72, 0x66, 0x6c, 0x6f, 0x77, 0xa0, 0x21, 0x10, 0x00, 
  0x17, 0x00, 0x00, 0x00, 0x6e, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
  0x29, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x61, 0x6c, 0x6c, 0x6f, 
  0x63, 0x2f, 0x76, 0x65, 0x63, 0x2e, 0x72, 0x73, 0x29, 0x20, 0x73, 0x68, 
  0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x3c, 0x3d, 0x20, 0x6c, 
  0x65, 0x6e, 0x20, 0x28, 0x69, 0x73, 0x20, 0x65, 0x6e, 0x64, 0x20, 0x64, 
  0x72, 0x61, 0x69, 0x6e, 0x20, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x20, 0x28, 
  0x69, 0x73, 0x20, 0x00, 0x03, 0x22, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 
  0xec, 0x21, 0x10, 0x00, 0x17, 0x00, 0x00, 0x00, 0xd8, 0x21, 0x10, 0x00, 
  0x01, 0x00, 0x00, 0x00, 0xd9, 0x21, 0x10, 0x00, 0x13, 0x00, 0x00, 0x00, 
  0x33, 0x05, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x60, 0x00, 0x66, 0x72, 
  0x6f, 0x6d, 0x5f, 0x73, 0x74, 0x72, 0x5f, 0x72, 0x61, 0x64, 0x69, 0x78, 
  0x5f, 0x69, 0x6e, 0x74, 0x3a, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x6c, 
  0x69, 0x65, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x61, 
  0x6e, 0x67, 0x65, 0x20, 0x60, 0x5b, 0x32, 0x2c, 0x20, 0x33, 0x36, 0x5d, 
  0x60, 0x20, 0x2d, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x00, 0x00, 
  0x42, 0x22, 0x10, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x73, 0x72, 0x63, 0x2f, 
  0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x6e, 0x75, 0x6d, 0x2f, 
  0x6d, 0x6f, 0x64, 0x2e, 0x72, 0x73, 0x00, 0x00, 0x88, 0x22, 0x10, 0x00, 
  0x16, 0x00, 0x00, 0x00, 0xac, 0x13, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
  0x2e, 0x2e, 0x00, 0x00, 0xb0, 0x22, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 
  0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 0x2f, 
  0x61, 0x73, 0x63, 0x69, 0x69, 0x2e, 0x72, 0x73, 0xbc, 0x22, 0x10, 0x00, 
  0x14, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 
  0x42, 0x6f, 0x72, 0x72, 0x6f, 0x77, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x42, 
  0x6f, 0x72, 0x72, 0x6f, 0x77, 0x4d, 0x75, 0x74, 0x45, 0x72, 0x72, 0x6f, 
  0x72, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64, 0x20, 0x60, 0x4f, 0x70, 0x74, 
  0x69, 0x6f, 0x6e, 0x3a, 0x3a, 0x75, 0x6e, 0x77, 0x72, 0x61, 0x70, 0x28, 
  0x29, 0x60, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 0x60, 0x4e, 0x6f, 0x6e, 
  0x65, 0x60, 0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x40, 0x22, 0x10, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x3a, 0x20, 0x00, 0x00, 0x40, 0x22, 0x10, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x2c, 0x23, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 
  0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
  0x71, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x40, 0x22, 0x10, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x50, 0x23, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 
  0x50, 0x23, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x69, 0x6e, 0x64, 0x65, 
  0x78, 0x20, 0x6f, 0x75, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x62, 0x6f, 0x75, 
  0x6e, 0x64, 0x73, 0x3a, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x65, 0x6e, 
  0x20, 0x69, 0x73, 0x20, 0x20, 0x62, 0x75, 0x74, 0x20, 0x74, 0x68, 0x65, 
  0x20, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x20, 0x69, 0x73, 0x20, 0x00, 0x00, 
  0x6c, 0x23, 0x10, 0x00, 0x20, 0x00, 0x00, 0x00, 0x8c, 0x23, 0x10, 0x00, 
  0x12, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x72, 0x00, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 
  0x74, 0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x2c, 
  0x0a, 0x2c, 0x20, 0x20, 0x7b, 0x20, 0x7d, 0x20, 0x7d, 0x28, 0x0a, 0x28, 
  0x2c, 0x29, 0x0a, 0x5b, 0x70, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x75, 0x00, 0x00, 0x00, 0x5d, 0x73, 0x72, 0x63, 
  0x2f, 0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x66, 0x6d, 0x74, 
  0x2f, 0x6e, 0x75, 0x6d, 0x2e, 0x72, 0x73, 0x00, 0xf1, 0x23, 0x10, 0x00, 
  0x16, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 
  0x30, 0x78, 0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34, 
  0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x39, 0x31, 0x30, 
  0x31, 0x31, 0x31, 0x32, 0x31, 0x33, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36, 
  0x31, 0x37, 0x31, 0x38, 0x31, 0x39, 0x32, 0x30, 0x32, 0x31, 0x32, 0x32, 
  0x32, 0x33, 0x32, 0x34, 0x32, 0x35, 0x32, 0x36, 0x32, 0x37, 0x32, 0x38, 
  0x32, 0x39, 0x33, 0x30, 0x33, 0x31, 0x33, 0x32, 0x33, 0x33, 0x33, 0x34, 
  0x33, 0x35, 0x33, 0x36, 0x33, 0x37, 0x33, 0x38, 0x33, 0x39, 0x34, 0x30, 
  0x34, 0x31, 0x34, 0x32, 0x34, 0x33, 0x34, 0x34, 0x34, 0x35, 0x34, 0x36, 
  0x34, 0x37, 0x34, 0x38, 0x34, 0x39, 0x35, 0x30, 0x35, 0x31, 0x35, 0x32, 
  0x35, 0x33, 0x35, 0x34, 0x35, 0x35, 0x35, 0x36, 0x35, 0x37, 0x35, 0x38, 
  0x35, 0x39, 0x36, 0x30, 0x36, 0x31, 0x36, 0x32, 0x36, 0x33, 0x36, 0x34, 
  0x36, 0x35, 0x36, 0x36, 0x36, 0x37, 0x36, 0x38, 0x36, 0x39, 0x37, 0x30, 
  0x37, 0x31, 0x37, 0x32, 0x37, 0x33, 0x37, 0x34, 0x37, 0x35, 0x37, 0x36, 
  0x37, 0x37, 0x37, 0x38, 0x37, 0x39, 0x38, 0x30, 0x38, 0x31, 0x38, 0x32, 
  0x38, 0x33, 0x38, 0x34, 0x38, 0x35, 0x38, 0x36, 0x38, 0x37, 0x38, 0x38, 
  0x38, 0x39, 0x39, 0x30, 0x39, 0x31, 0x39, 0x32, 0x39, 0x33, 0x39, 0x34, 
  0x39, 0x35, 0x39, 0x36, 0x39, 0x37, 0x39, 0x38, 0x39, 0x39, 0x00, 0x00, 
  0x70, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x76, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 
  0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 0x2f, 
  0x66, 0x6d, 0x74, 0x2f, 0x6d, 0x6f, 0x64, 0x2e, 0x72, 0x73, 0x00, 0x00, 
  0xfc, 0x24, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 0x4c, 0x04, 0x00, 0x00, 
  0x11, 0x00, 0x00, 0x00, 0xfc, 0x24, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 
  0x56, 0x04, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x73, 0x72, 0x63, 0x2f, 
  0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x73, 0x6c, 0x69, 0x63, 
  0x65, 0x2f, 0x6d, 0x65, 0x6d, 0x63, 0x68, 0x72, 0x2e, 0x72, 0x73, 0x00, 
  0x34, 0x25, 0x10, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 
  0x05, 0x00, 0x00, 0x00, 0x34, 0x25, 0x10, 0x00, 0x1b, 0x00, 0x00, 0x00, 
  0x69, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x34, 0x25, 0x10, 0x00, 
  0x1b, 0x00, 0x00, 0x00, 0x83, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
  0x69, 0x6e, 0x64, 0x65, 0x78, 0x20, 0x20, 0x6f, 0x75, 0x74, 0x20, 0x6f, 
  0x66, 0x20, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 
  0x73, 0x6c, 0x69, 0x63, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x6c, 0x65, 0x6e, 
  0x67, 0x74, 0x68, 0x20, 0x80, 0x25, 0x10, 0x00, 0x06, 0x00, 0x00, 0x00, 
  0x86, 0x25, 0x10, 0x00, 0x22, 0x00, 0x00, 0x00, 0x73, 0x6c, 0x69, 0x63, 
  0x65, 0x20, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x20, 0x73, 0x74, 0x61, 0x72, 
  0x74, 0x73, 0x20, 0x61, 0x74, 0x20, 0x20, 0x62, 0x75, 0x74, 0x20, 0x65, 
  0x6e, 0x64, 0x73, 0x20, 0x61, 0x74, 0x20, 0x00, 0xb8, 0x25, 0x10, 0x00, 
  0x16, 0x00, 0x00, 0x00, 0xce, 0x25, 0x10, 0x00, 0x0d, 0x00, 0x00, 0x00, 
  0x61, 0x74, 0x74, 0x65, 0x6d, 0x70, 0x74, 0x65, 0x64, 0x20, 0x74, 0x6f, 
  0x20, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x20, 0x73, 0x6c, 0x69, 0x63, 0x65, 
  0x20, 0x75, 0x70, 0x20, 0x74, 0x6f, 0x20, 0x6d, 0x61, 0x78, 0x69, 0x6d, 
  0x75, 0x6d, 0x20, 0x75, 0x73, 0x69, 0x7a, 0x65, 0x73, 0x72, 0x63, 0x2f, 
  0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x73, 0x74, 0x72, 0x2f, 
  0x70, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e, 0x2e, 0x72, 0x73, 0x00, 0x00, 
  0x18, 0x26, 0x10, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00, 
  0x26, 0x00, 0x00, 0x00, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 
  0x6f, 0x72, 0x65, 0x2f, 0x73, 0x74, 0x72, 0x2f, 0x6c, 0x6f, 0x73, 0x73, 
  0x79, 0x2e, 0x72, 0x73, 0x44, 0x26, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 
  0x80, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x44, 0x26, 0x10, 0x00, 
  0x18, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 
  0x44, 0x26, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00, 
  0x1d, 0x00, 0x00, 0x00, 0x44, 0x26, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 
  0x72, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x44, 0x26, 0x10, 0x00, 
  0x18, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 
  0x44, 0x26, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 
  0x21, 0x00, 0x00, 0x00, 0x44, 0x26, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 
  0x58, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x61, 0x73, 0x73, 0x65, 
  0x72, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 
  0x3a, 0x20, 0x62, 0x72, 0x6f, 0x6b, 0x65, 0x6e, 0x2e, 0x69, 0x73, 0x5f, 
  0x65, 0x6d, 0x70, 0x74, 0x79, 0x28, 0x29, 0x00, 0x44, 0x26, 0x10, 0x00, 
  0x18, 0x00, 0x00, 0x00, 0x9d, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 
  0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 0x2f, 
  0x73, 0x74, 0x72, 0x2f, 0x6d, 0x6f, 0x64, 0x2e, 0x72, 0x73, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 
  0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 
  0x80, 0x07, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x27, 0x10, 0x00, 
  0x16, 0x00, 0x00, 0x00, 0xc3, 0x07, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 
  0x00, 0x27, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 
  0x2f, 0x00, 0x00, 0x00, 0x5b, 0x2e, 0x2e, 0x2e, 0x5d, 0x62, 0x79, 0x74, 
  0x65, 0x20, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x20, 0x20, 0x69, 0x73, 0x20, 
  0x6f, 0x75, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x62, 0x6f, 0x75, 0x6e, 0x64, 
  0x73, 0x20, 0x6f, 0x66, 0x20, 0x60, 0x00, 0x00, 0x4d, 0x28, 0x10, 0x00, 
  0x0b, 0x00, 0x00, 0x00, 0x58, 0x28, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 
  0x40, 0x22, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x62, 0x65, 0x67, 0x69, 
  0x6e, 0x20, 0x3c, 0x3d, 0x20, 0x65, 0x6e, 0x64, 0x20, 0x28, 0x20, 0x3c, 
  0x3d, 0x20, 0x29, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x20, 0x73, 0x6c, 0x69, 
  0x63, 0x69, 0x6e, 0x67, 0x20, 0x60, 0x00, 0x00, 0x88, 0x28, 0x10, 0x00, 
  0x0e, 0x00, 0x00, 0x00, 0x96, 0x28, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x9a, 0x28, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00, 0x40, 0x22, 0x10, 0x00, 
  0x01, 0x00, 0x00, 0x00, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 
  0x61, 0x20, 0x63, 0x68, 0x61, 0x72, 0x20, 0x62, 0x6f, 0x75, 0x6e, 0x64, 
  0x61, 0x72, 0x79, 0x3b, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x69, 
  0x6e, 0x73, 0x69, 0x64, 0x65, 0x20, 0x20, 0x28, 0x62, 0x79, 0x74, 0x65, 
  0x73, 0x20, 0x29, 0x20, 0x6f, 0x66, 0x20, 0x60, 0x4d, 0x28, 0x10, 0x00, 
  0x0b, 0x00, 0x00, 0x00, 0xcc, 0x28, 0x10, 0x00, 0x26, 0x00, 0x00, 0x00, 
  0xf2, 0x28, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00, 0xfa, 0x28, 0x10, 0x00, 
  0x06, 0x00, 0x00, 0x00, 0x40, 0x22, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 
  0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 0x2f, 
  0x75, 0x6e, 0x69, 0x63, 0x6f, 0x64, 0x65, 0x2f, 0x70, 0x72, 0x69, 0x6e, 
  0x74, 0x61, 0x62, 0x6c, 0x65, 0x2e, 0x72, 0x73, 0x28, 0x29, 0x10, 0x00, 
  0x20, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 
  0x28, 0x29, 0x10, 0x00, 0x20, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x05, 0x05, 0x06, 0x06, 0x03, 
  0x07, 0x06, 0x08, 0x08, 0x09, 0x11, 0x0a, 0x1c, 0x0b, 0x19, 0x0c, 0x14, 
  0x0d, 0x10, 0x0e, 0x0d, 0x0f, 0x04, 0x10, 0x03, 0x12, 0x12, 0x13, 0x09, 
  0x16, 0x01, 0x17, 0x05, 0x18, 0x02, 0x19, 0x03, 0x1a, 0x07, 0x1c, 0x02, 
  0x1d, 0x01, 0x1f, 0x16, 0x20, 0x03, 0x2b, 0x03, 0x2c, 0x02, 0x2d, 0x0b, 
  0x2e, 0x01, 0x30, 0x03, 0x31, 0x02, 0x32, 0x01, 0xa7, 0x02, 0xa9, 0x02, 
  0xaa, 0x04, 0xab, 0x08, 0xfa, 0x02, 0xfb, 0x05, 0xfd, 0x04, 0xfe, 0x03, 
  0xff, 0x09, 0xad, 0x78, 0x79, 0x8b, 0x8d, 0xa2, 0x30, 0x57, 0x58, 0x8b, 
  0x8c, 0x90, 0x1c, 0x1d, 0xdd, 0x0e, 0x0f, 0x4b, 0x4c, 0xfb, 0xfc, 0x2e, 
  0x2f, 0x3f, 0x5c, 0x5d, 0x5f, 0xb5, 0xe2, 0x84, 0x8d, 0x8e, 0x91, 0x92, 
  0xa9, 0xb1, 0xba, 0xbb, 0xc5, 0xc6, 0xc9, 0xca, 0xde, 0xe4, 0xe5, 0xff, 
  0x00, 0x04, 0x11, 0x12, 0x29, 0x31, 0x34, 0x37, 0x3a, 0x3b, 0x3d, 0x49, 
  0x4a, 0x5d, 0x84, 0x8e, 0x92, 0xa9, 0xb1, 0xb4, 0xba, 0xbb, 0xc6, 0xca, 
  0xce, 0xcf, 0xe4, 0xe5, 0x00, 0x04, 0x0d, 0x0e, 0x11, 0x12, 0x29, 0x31, 
  0x34, 0x3a, 0x3b, 0x45, 0x46, 0x49, 0x4a, 0x5e, 0x64, 0x65, 0x84, 0x91, 
  0x9b, 0x9d, 0xc9, 0xce, 0xcf, 0x0d, 0x11, 0x29, 0x45, 0x49, 0x57, 0x64, 
  0x65, 0x8d, 0x91, 0xa9, 0xb4, 0xba, 0xbb, 0xc5, 0xc9, 0xdf, 0xe4, 0xe5, 
  0xf0, 0x0d, 0x11, 0x45, 0x49, 0x64, 0x65, 0x80, 0x84, 0xb2, 0xbc, 0xbe, 
  0xbf, 0xd5, 0xd7, 0xf0, 0xf1, 0x83, 0x85, 0x8b, 0xa4, 0xa6, 0xbe, 0xbf, 
  0xc5, 0xc7, 0xce, 0xcf, 0xda, 0xdb, 0x48, 0x98, 0xbd, 0xcd, 0xc6, 0xce, 
  0xcf, 0x49, 0x4e, 0x4f, 0x57, 0x59, 0x5e, 0x5f, 0x89, 0x8e, 0x8f, 0xb1, 
  0xb6, 0xb7, 0xbf, 0xc1, 0xc6, 0xc7, 0xd7, 0x11, 0x16, 0x17, 0x5b, 0x5c, 
  0xf6, 0xf7, 0xfe, 0xff, 0x80, 0x0d, 0x6d, 0x71, 0xde, 0xdf, 0x0e, 0x0f, 
  0x1f, 0x6e, 0x6f, 0x1c, 0x1d, 0x5f, 0x7d, 0x7e, 0xae, 0xaf, 0xbb, 0xbc, 
  0xfa, 0x16, 0x17, 0x1e, 0x1f, 0x46, 0x47, 0x4e, 0x4f, 0x58, 0x5a, 0x5c, 
  0x5e, 0x7e, 0x7f, 0xb5, 0xc5, 0xd4, 0xd5, 0xdc, 0xf0, 0xf1, 0xf5, 0x72, 
  0x73, 0x8f, 0x74, 0x75, 0x96, 0x2f, 0x5f, 0x26, 0x2e, 0x2f, 0xa7, 0xaf, 
  0xb7, 0xbf, 0xc7, 0xcf, 0xd7, 0xdf, 0x9a, 0x40, 0x97, 0x98, 0x30, 0x8f, 
  0x1f, 0xc0, 0xc1, 0xce, 0xff, 0x4e, 0x4f, 0x5a, 0x5b, 0x07, 0x08, 0x0f, 
  0x10, 0x27, 0x2f, 0xee, 0xef, 0x6e, 0x6f, 0x37, 0x3d, 0x3f, 0x42, 0x45, 
  0x90, 0x91, 0xfe, 0xff, 0x53, 0x67, 0x75, 0xc8, 0xc9, 0xd0, 0xd1, 0xd8, 
  0xd9, 0xe7, 0xfe, 0xff, 0x00, 0x20, 0x5f, 0x22, 0x82, 0xdf, 0x04, 0x82, 
  0x44, 0x08, 0x1b, 0x04, 0x06, 0x11, 0x81, 0xac, 0x0e, 0x80, 0xab, 0x35, 
  0x28, 0x0b, 0x80, 0xe0, 0x03, 0x19, 0x08, 0x01, 0x04, 0x2f, 0x04, 0x34, 
  0x04, 0x07, 0x03, 0x01, 0x07, 0x06, 0x07, 0x11, 0x0a, 0x50, 0x0f, 0x12, 
  0x07, 0x55, 0x07, 0x03, 0x04, 0x1c, 0x0a, 0x09, 0x03, 0x08, 0x03, 0x07, 
  0x03, 0x02, 0x03, 0x03, 0x03, 0x0c, 0x04, 0x05, 0x03, 0x0b, 0x06, 0x01, 
  0x0e, 0x15, 0x05, 0x3a, 0x03, 0x11, 0x07, 0x06, 0x05, 0x10, 0x07, 0x57, 
  0x07, 0x02, 0x07, 0x15, 0x0d, 0x50, 0x04, 0x43, 0x03, 0x2d, 0x03, 0x01, 
  0x04, 0x11, 0x06, 0x0f, 0x0c, 0x3a, 0x04, 0x1d, 0x25, 0x5f, 0x20, 0x6d, 
  0x04, 0x6a, 0x25, 0x80, 0xc8, 0x05, 0x82, 0xb0, 0x03, 0x1a, 0x06, 0x82, 
  0xfd, 0x03, 0x59, 0x07, 0x15, 0x0b, 0x17, 0x09, 0x14, 0x0c, 0x14, 0x0c, 
  0x6a, 0x06, 0x0a, 0x06, 0x1a, 0x06, 0x59, 0x07, 0x2b, 0x05, 0x46, 0x0a, 
  0x2c, 0x04, 0x0c, 0x04, 0x01, 0x03, 0x31, 0x0b, 0x2c, 0x04, 0x1a, 0x06, 
  0x0b, 0x03, 0x80, 0xac, 0x06, 0x0a, 0x06, 0x21, 0x3f, 0x4c, 0x04, 0x2d, 
  0x03, 0x74, 0x08, 0x3c, 0x03, 0x0f, 0x03, 0x3c, 0x07, 0x38, 0x08, 0x2b, 
  0x05, 0x82, 0xff, 0x11, 0x18, 0x08, 0x2f, 0x11, 0x2d, 0x03, 0x20, 0x10, 
  0x21, 0x0f, 0x80, 0x8c, 0x04, 0x82, 0x97, 0x19, 0x0b, 0x15, 0x88, 0x94, 
  0x05, 0x2f, 0x05, 0x3b, 0x07, 0x02, 0x0e, 0x18, 0x09, 0x80, 0xb3, 0x2d, 
  0x74, 0x0c, 0x80, 0xd6, 0x1a, 0x0c, 0x05, 0x80, 0xff, 0x05, 0x80, 0xdf, 
  0x0c, 0xee, 0x0d, 0x03, 0x84, 0x8d, 0x03, 0x37, 0x09, 0x81, 0x5c, 0x14, 
  0x80, 0xb8, 0x08, 0x80, 0xcb, 0x2a, 0x38, 0x03, 0x0a, 0x06, 0x38, 0x08, 
  0x46, 0x08, 0x0c, 0x06, 0x74, 0x0b, 0x1e, 0x03, 0x5a, 0x04, 0x59, 0x09, 
  0x80, 0x83, 0x18, 0x1c, 0x0a, 0x16, 0x09, 0x4c, 0x04, 0x80, 0x8a, 0x06, 
  0xab, 0xa4, 0x0c, 0x17, 0x04, 0x31, 0xa1, 0x04, 0x81, 0xda, 0x26, 0x07, 
  0x0c, 0x05, 0x05, 0x80, 0xa5, 0x11, 0x81, 0x6d, 0x10, 0x78, 0x28, 0x2a, 
  0x06, 0x4c, 0x04, 0x80, 0x8d, 0x04, 0x80, 0xbe, 0x03, 0x1b, 0x03, 0x0f, 
  0x0d, 0x00, 0x06, 0x01, 0x01, 0x03, 0x01, 0x04, 0x02, 0x08, 0x08, 0x09, 
  0x02, 0x0a, 0x05, 0x0b, 0x02, 0x0e, 0x04, 0x10, 0x01, 0x11, 0x02, 0x12, 
  0x05, 0x13, 0x11, 0x14, 0x01, 0x15, 0x02, 0x17, 0x02, 0x19, 0x0d, 0x1c, 
  0x05, 0x1d, 0x08, 0x24, 0x01, 0x6a, 0x03, 0x6b, 0x02, 0xbc, 0x02, 0xd1, 
  0x02, 0xd4, 0x0c, 0xd5, 0x09, 0xd6, 0x02, 0xd7, 0x02, 0xda, 0x01, 0xe0, 
  0x05, 0xe1, 0x02, 0xe8, 0x02, 0xee, 0x20, 0xf0, 0x04, 0xf8, 0x02, 0xf9, 
  0x02, 0xfa, 0x02, 0xfb, 0x01, 0x0c, 0x27, 0x3b, 0x3e, 0x4e, 0x4f, 0x8f, 
  0x9e, 0x9e, 0x9f, 0x06, 0x07, 0x09, 0x36, 0x3d, 0x3e, 0x56, 0xf3, 0xd0, 
  0xd1, 0x04, 0x14, 0x18, 0x36, 0x37, 0x56, 0x57, 0x7f, 0xaa, 0xae, 0xaf, 
  0xbd, 0x35, 0xe0, 0x12, 0x87, 0x89, 0x8e, 0x9e, 0x04, 0x0d, 0x0e, 0x11, 
  0x12, 0x29, 0x31, 0x34, 0x3a, 0x45, 0x46, 0x49, 0x4a, 0x4e, 0x4f, 0x64, 
  0x65, 0x5c, 0xb6, 0xb7, 0x1b, 0x1c, 0x07, 0x08, 0x0a, 0x0b, 0x14, 0x17, 
  0x36, 0x39, 0x3a, 0xa8, 0xa9, 0xd8, 0xd9, 0x09, 0x37, 0x90, 0x91, 0xa8, 
  0x07, 0x0a, 0x3b, 0x3e, 0x66, 0x69, 0x8f, 0x92, 0x6f, 0x5f, 0xee, 0xef, 
  0x5a, 0x62, 0x9a, 0x9b, 0x27, 0x28, 0x55, 0x9d, 0xa0, 0xa1, 0xa3, 0xa4, 
  0xa7, 0xa8, 0xad, 0xba, 0xbc, 0xc4, 0x06, 0x0b, 0x0c, 0x15, 0x1d, 0x3a, 
  0x3f, 0x45, 0x51, 0xa6, 0xa7, 0xcc, 0xcd, 0xa0, 0x07, 0x19, 0x1a, 0x22, 
  0x25, 0x3e, 0x3f, 0xc5, 0xc6, 0x04, 0x20, 0x23, 0x25, 0x26, 0x28, 0x33, 
  0x38, 0x3a, 0x48, 0x4a, 0x4c, 0x50, 0x53, 0x55, 0x56, 0x58, 0x5a, 0x5c, 
  0x5e, 0x60, 0x63, 0x65, 0x66, 0x6b, 0x73, 0x78, 0x7d, 0x7f, 0x8a, 0xa4, 
  0xaa, 0xaf, 0xb0, 0xc0, 0xd0, 0xae, 0xaf, 0x79, 0xcc, 0x6e, 0x6f, 0x93, 
  0x5e, 0x22, 0x7b, 0x05, 0x03, 0x04, 0x2d, 0x03, 0x66, 0x03, 0x01, 0x2f, 
  0x2e, 0x80, 0x82, 0x1d, 0x03, 0x31, 0x0f, 0x1c, 0x04, 0x24, 0x09, 0x1e, 
  0x05, 0x2b, 0x05, 0x44, 0x04, 0x0e, 0x2a, 0x80, 0xaa, 0x06, 0x24, 0x04, 
  0x24, 0x04, 0x28, 0x08, 0x34, 0x0b, 0x01, 0x80, 0x90, 0x81, 0x37, 0x09, 
  0x16, 0x0a, 0x08, 0x80, 0x98, 0x39, 0x03, 0x63, 0x08, 0x09, 0x30, 0x16, 
  0x05, 0x21, 0x03, 0x1b, 0x05, 0x01, 0x40, 0x38, 0x04, 0x4b, 0x05, 0x2f, 
  0x04, 0x0a, 0x07, 0x09, 0x07, 0x40, 0x20, 0x27, 0x04, 0x0c, 0x09, 0x36, 
  0x03, 0x3a, 0x05, 0x1a, 0x07, 0x04, 0x0c, 0x07, 0x50, 0x49, 0x37, 0x33, 
  0x0d, 0x33, 0x07, 0x2e, 0x08, 0x0a, 0x81, 0x26, 0x52, 0x4e, 0x28, 0x08, 
  0x2a, 0x56, 0x1c, 0x14, 0x17, 0x09, 0x4e, 0x04, 0x1e, 0x0f, 0x43, 0x0e, 
  0x19, 0x07, 0x0a, 0x06, 0x48, 0x08, 0x27, 0x09, 0x75, 0x0b, 0x3f, 0x41, 
  0x2a, 0x06, 0x3b, 0x05, 0x0a, 0x06, 0x51, 0x06, 0x01, 0x05, 0x10, 0x03, 
  0x05, 0x80, 0x8b, 0x62, 0x1e, 0x48, 0x08, 0x0a, 0x80, 0xa6, 0x5e, 0x22, 
  0x45, 0x0b, 0x0a, 0x06, 0x0d, 0x13, 0x39, 0x07, 0x0a, 0x36, 0x2c, 0x04, 
  0x10, 0x80, 0xc0, 0x3c, 0x64, 0x53, 0x0c, 0x48, 0x09, 0x0a, 0x46, 0x45, 
  0x1b, 0x48, 0x08, 0x53, 0x1d, 0x39, 0x81, 0x07, 0x46, 0x0a, 0x1d, 0x03, 
  0x47, 0x49, 0x37, 0x03, 0x0e, 0x08, 0x0a, 0x06, 0x39, 0x07, 0x0a, 0x81, 
  0x36, 0x19, 0x80, 0xb7, 0x01, 0x0f, 0x32, 0x0d, 0x83, 0x9b, 0x66, 0x75, 
  0x0b, 0x80, 0xc4, 0x8a, 0xbc, 0x84, 0x2f, 0x8f, 0xd1, 0x82, 0x47, 0xa1, 
  0xb9, 0x82, 0x39, 0x07, 0x2a, 0x04, 0x02, 0x60, 0x26, 0x0a, 0x46, 0x0a, 
  0x28, 0x05, 0x13, 0x82, 0xb0, 0x5b, 0x65, 0x4b, 0x04, 0x39, 0x07, 0x11, 
  0x40, 0x05, 0x0b, 0x02, 0x0e, 0x97, 0xf8, 0x08, 0x84, 0xd6, 0x2a, 0x09, 
  0xa2, 0xf7, 0x81, 0x1f, 0x31, 0x03, 0x11, 0x04, 0x08, 0x81, 0x8c, 0x89, 
  0x04, 0x6b, 0x05, 0x0d, 0x03, 0x09, 0x07, 0x10, 0x93, 0x60, 0x80, 0xf6, 
  0x0a, 0x73, 0x08, 0x6e, 0x17, 0x46, 0x80, 0x9a, 0x14, 0x0c, 0x57, 0x09, 
  0x19, 0x80, 0x87, 0x81, 0x47, 0x03, 0x85, 0x42, 0x0f, 0x15, 0x85, 0x50, 
  0x2b, 0x80, 0xd5, 0x2d, 0x03, 0x1a, 0x04, 0x02, 0x81, 0x70, 0x3a, 0x05, 
  0x01, 0x85, 0x00, 0x80, 0xd7, 0x29, 0x4c, 0x04, 0x0a, 0x04, 0x02, 0x83, 
  0x11, 0x44, 0x4c, 0x3d, 0x80, 0xc2, 0x3c, 0x06, 0x01, 0x04, 0x55, 0x05, 
  0x1b, 0x34, 0x02, 0x81, 0x0e, 0x2c, 0x04, 0x64, 0x0c, 0x56, 0x0a, 0x80, 
  0xae, 0x38, 0x1d, 0x0d, 0x2c, 0x04, 0x09, 0x07, 0x02, 0x0e, 0x06, 0x80, 
  0x9a, 0x83, 0xd8, 0x08, 0x0d, 0x03, 0x0d, 0x03, 0x74, 0x0c, 0x59, 0x07, 
  0x0c, 0x14, 0x0c, 0x04, 0x38, 0x08, 0x0a, 0x06, 0x28, 0x08, 0x22, 0x4e, 
  0x81, 0x54, 0x0c, 0x15, 0x03, 0x03, 0x05, 0x07, 0x09, 0x19, 0x07, 0x07, 
  0x09, 0x03, 0x0d, 0x07, 0x29, 0x80, 0xcb, 0x25, 0x0a, 0x84, 0x06, 0x73, 
  0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x75, 
  0x6e, 0x69, 0x63, 0x6f, 0x64, 0x65, 0x2f, 0x75, 0x6e, 0x69, 0x63, 0x6f, 
  0x64, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x72, 0x73, 0x00, 0x00, 
  0xaf, 0x2e, 0x10, 0x00, 0x23, 0x00, 0x00, 0x00, 0x4b, 0x00, 0x00, 0x00, 
  0x28, 0x00, 0x00, 0x00, 0xaf, 0x2e, 0x10, 0x00, 0x23, 0x00, 0x00, 0x00, 
  0x57, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0xaf, 0x2e, 0x10, 0x00, 
  0x23, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 
  0x6b, 0x69, 0x6e, 0x64, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x5a, 0x65, 0x72, 
  0x6f, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x50, 0x61, 0x72, 0x73, 
  0x65, 0x49, 0x6e, 0x74, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x00, 0x00, 0x00, 
  0x70, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x7a, 0x00, 0x00, 0x00, 0x55, 0x6e, 0x64, 0x65, 0x72, 0x66, 0x6c, 0x6f, 
  0x77, 0x4f, 0x76, 0x65, 0x72, 0x66, 0x6c, 0x6f, 0x77, 0x49, 0x6e, 0x76, 
  0x61, 0x6c, 0x69, 0x64, 0x44, 0x69, 0x67, 0x69, 0x74, 0x53, 0x6f, 0x6d, 
  0x65, 0x4e, 0x6f, 0x6e, 0x65, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x55, 0x74, 
  0x66, 0x38, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x76, 0x61, 0x6c, 0x69, 0x64, 
  0x5f, 0x75, 0x70, 0x5f, 0x74, 0x6f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x5f, 
  0x6c, 0x65, 0x6e, 0x00, 0x70, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
  0x04, 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 
  0x83, 0x04, 0x20, 0x00, 0x91, 0x05, 0x60, 0x00, 0x5d, 0x13, 0xa0, 0x00, 
  0x12, 0x17, 0xa0, 0x1e, 0x0c, 0x20, 0xe0, 0x1e, 0xef, 0x2c, 0x20, 0x2b, 
  0x2a, 0x30, 0xa0, 0x2b, 0x6f, 0xa6, 0x60, 0x2c, 0x02, 0xa8, 0xe0, 0x2c, 
  0x1e, 0xfb, 0xe0, 0x2d, 0x00, 0xfe, 0xa0, 0x35, 0x9e, 0xff, 0xe0, 0x35, 
  0xfd, 0x01, 0x61, 0x36, 0x01, 0x0a, 0xa1, 0x36, 0x24, 0x0d, 0x61, 0x37, 
  0xab, 0x0e, 0xe1, 0x38, 0x2f, 0x18, 0x21, 0x39, 0x30, 0x1c, 0x61, 0x46, 
  0xf3, 0x1e, 0xa1, 0x4a, 0xf0, 0x6a, 0x61, 0x4e, 0x4f, 0x6f, 0xa1, 0x4e, 
  0x9d, 0xbc, 0x21, 0x4f, 0x65, 0xd1, 0xe1, 0x4f, 0x00, 0xda, 0x21, 0x50, 
  0x00, 0xe0, 0xe1, 0x51, 0x30, 0xe1, 0x61, 0x53, 0xec, 0xe2, 0xa1, 0x54, 
  0xd0, 0xe8, 0xe1, 0x54, 0x20, 0x00, 0x2e, 0x55, 0xf0, 0x01, 0xbf, 0x55, 
  0x00, 0x70, 0x00, 0x07, 0x00, 0x2d, 0x01, 0x01, 0x01, 0x02, 0x01, 0x02, 
  0x01, 0x01, 0x48, 0x0b, 0x30, 0x15, 0x10, 0x01, 0x65, 0x07, 0x02, 0x06, 
  0x02, 0x02, 0x01, 0x04, 0x23, 0x01, 0x1e, 0x1b, 0x5b, 0x0b, 0x3a, 0x09, 
  0x09, 0x01, 0x18, 0x04, 0x01, 0x09, 0x01, 0x03, 0x01, 0x05, 0x2b, 0x03, 
  0x77, 0x0f, 0x01, 0x20, 0x37, 0x01, 0x01, 0x01, 0x04, 0x08, 0x04, 0x01, 
  0x03, 0x07, 0x0a, 0x02, 0x1d, 0x01, 0x3a, 0x01, 0x01, 0x01, 0x02, 0x04, 
  0x08, 0x01, 0x09, 0x01, 0x0a, 0x02, 0x1a, 0x01, 0x02, 0x02, 0x39, 0x01, 
  0x04, 0x02, 0x04, 0x02, 0x02, 0x03, 0x03, 0x01, 0x1e, 0x02, 0x03, 0x01, 
  0x0b, 0x02, 0x39, 0x01, 0x04, 0x05, 0x01, 0x02, 0x04, 0x01, 0x14, 0x02, 
  0x16, 0x06, 0x01, 0x01, 0x3a, 0x01, 0x01, 0x02, 0x01, 0x04, 0x08, 0x01, 
  0x07, 0x03, 0x0a, 0x02, 0x1e, 0x01, 0x3b, 0x01, 0x01, 0x01, 0x0c, 0x01, 
  0x09, 0x01, 0x28, 0x01, 0x03, 0x01, 0x39, 0x03, 0x05, 0x03, 0x01, 0x04, 
  0x07, 0x02, 0x0b, 0x02, 0x1d, 0x01, 0x3a, 0x01, 0x02, 0x01, 0x02, 0x01, 
  0x03, 0x01, 0x05, 0x02, 0x07, 0x02, 0x0b, 0x02, 0x1c, 0x02, 0x39, 0x02, 
  0x01, 0x01, 0x02, 0x04, 0x08, 0x01, 0x09, 0x01, 0x0a, 0x02, 0x1d, 0x01, 
  0x48, 0x01, 0x04, 0x01, 0x02, 0x03, 0x01, 0x01, 0x08, 0x01, 0x51, 0x01, 
  0x02, 0x07, 0x0c, 0x08, 0x62, 0x01, 0x02, 0x09, 0x0b, 0x06, 0x4a, 0x02, 
  0x1b, 0x01, 0x01, 0x01, 0x01, 0x01, 0x37, 0x0e, 0x01, 0x05, 0x01, 0x02, 
  0x05, 0x0b, 0x01, 0x24, 0x09, 0x01, 0x66, 0x04, 0x01, 0x06, 0x01, 0x02, 
  0x02, 0x02, 0x19, 0x02, 0x04, 0x03, 0x10, 0x04, 0x0d, 0x01, 0x02, 0x02, 
  0x06, 0x01, 0x0f, 0x01, 0x00, 0x03, 0x00, 0x03, 0x1d, 0x03, 0x1d, 0x02, 
  0x1e, 0x02, 0x40, 0x02, 0x01, 0x07, 0x08, 0x01, 0x02, 0x0b, 0x09, 0x01, 
  0x2d, 0x03, 0x77, 0x02, 0x22, 0x01, 0x76, 0x03, 0x04, 0x02, 0x09, 0x01, 
  0x06, 0x03, 0xdb, 0x02, 0x02, 0x01, 0x3a, 0x01, 0x01, 0x07, 0x01, 0x01, 
  0x01, 0x01, 0x02, 0x08, 0x06, 0x0a, 0x02, 0x01, 0x30, 0x11, 0x3f, 0x04, 
  0x30, 0x07, 0x01, 0x01, 0x05, 0x01, 0x28, 0x09, 0x0c, 0x02, 0x20, 0x04, 
  0x02, 0x02, 0x01, 0x03, 0x38, 0x01, 0x01, 0x02, 0x03, 0x01, 0x01, 0x03, 
  0x3a, 0x08, 0x02, 0x02, 0x98, 0x03, 0x01, 0x0d, 0x01, 0x07, 0x04, 0x01, 
  0x06, 0x01, 0x03, 0x02, 0xc6, 0x3a, 0x01, 0x05, 0x00, 0x01, 0xc3, 0x21, 
  0x00, 0x03, 0x8d, 0x01, 0x60, 0x20, 0x00, 0x06, 0x69, 0x02, 0x00, 0x04, 
  0x01, 0x0a, 0x20, 0x02, 0x50, 0x02, 0x00, 0x01, 0x03, 0x01, 0x04, 0x01, 
  0x19, 0x02, 0x05, 0x01, 0x97, 0x02, 0x1a, 0x12, 0x0d, 0x01, 0x26, 0x08, 
  0x19, 0x0b, 0x2e, 0x03, 0x30, 0x01, 0x02, 0x04, 0x02, 0x02, 0x27, 0x01, 
  0x43, 0x06, 0x02, 0x02, 0x02, 0x02, 0x0c, 0x01, 0x08, 0x01, 0x2f, 0x01, 
  0x33, 0x01, 0x01, 0x03, 0x02, 0x02, 0x05, 0x02, 0x01, 0x01, 0x2a, 0x02, 
  0x08, 0x01, 0xee, 0x01, 0x02, 0x01, 0x04, 0x01, 0x00, 0x01, 0x00, 0x10, 
  0x10, 0x10, 0x00, 0x02, 0x00, 0x01, 0xe2, 0x01, 0x95, 0x05, 0x00, 0x03, 
  0x01, 0x02, 0x05, 0x04, 0x28, 0x03, 0x04, 0x01, 0xa5, 0x02, 0x00, 0x04, 
  0x00, 0x02, 0x99, 0x0b, 0xb0, 0x01, 0x36, 0x0f, 0x38, 0x03, 0x31, 0x04, 
  0x02, 0x02, 0x45, 0x03, 0x24, 0x05, 0x01, 0x08, 0x3e, 0x01, 0x0c, 0x02, 
  0x34, 0x09, 0x0a, 0x04, 0x02, 0x01, 0x5f, 0x03, 0x02, 0x01, 0x01, 0x02, 
  0x06, 0x01, 0xa0, 0x01, 0x03, 0x08, 0x15, 0x02, 0x39, 0x02, 0x01, 0x01, 
  0x01, 0x01, 0x16, 0x01, 0x0e, 0x07, 0x03, 0x05, 0xc3, 0x08, 0x02, 0x03, 
  0x01, 0x01, 0x17, 0x01, 0x51, 0x01, 0x02, 0x06, 0x01, 0x01, 0x02, 0x01, 
  0x01, 0x02, 0x01, 0x02, 0xeb, 0x01, 0x02, 0x04, 0x06, 0x02, 0x01, 0x02, 
  0x1b, 0x02, 0x55, 0x08, 0x02, 0x01, 0x01, 0x02, 0x6a, 0x01, 0x01, 0x01, 
  0x02, 0x06, 0x01, 0x01, 0x65, 0x03, 0x02, 0x04, 0x01, 0x05, 0x00, 0x09, 
  0x01, 0x02, 0xf5, 0x01, 0x0a, 0x02, 0x01, 0x01, 0x04, 0x01, 0x90, 0x04, 
  0x02, 0x02, 0x04, 0x01, 0x20, 0x0a, 0x28, 0x06, 0x02, 0x04, 0x08, 0x01, 
  0x09, 0x06, 0x02, 0x03, 0x2e, 0x0d, 0x01, 0x02, 0x00, 0x07, 0x01, 0x06, 
  0x01, 0x01, 0x52, 0x16, 0x02, 0x07, 0x01, 0x02, 0x01, 0x02, 0x7a, 0x06, 
  0x03, 0x01, 0x01, 0x02, 0x01, 0x07, 0x01, 0x01, 0x48, 0x02, 0x03, 0x01, 
  0x01, 0x01, 0x00, 0x02, 0x00, 0x05, 0x3b, 0x07, 0x00, 0x01, 0x3f, 0x04, 
  0x51, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0x03, 0x04, 0x05, 0x08, 0x08, 
  0x02, 0x07, 0x1e, 0x04, 0x94, 0x03, 0x00, 0x37, 0x04, 0x32, 0x08, 0x01, 
  0x0e, 0x01, 0x16, 0x05, 0x01, 0x0f, 0x00, 0x07, 0x01, 0x11, 0x02, 0x07, 
  0x01, 0x02, 0x01, 0x05, 0x00, 0x07, 0x00, 0x04, 0x00, 0x07, 0x6d, 0x07, 
  0x00, 0x60, 0x80, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x80, 0x16, 0x00, 0x00, 
  0x00, 0x20, 0x20, 0x01, 0x00, 0x30, 0x60, 0x01, 0x01, 0x30, 0x71, 0x02, 
  0x09, 0x05, 0x12, 0x01, 0x64, 0x01, 0x1a, 0x01, 0x00, 0x01, 0x00, 0x0b, 
  0x1d, 0x02, 0x05, 0x01, 0x2f, 0x01, 0x00, 0x01, 0x00, 
};

static const u8 data_segment_data_1[] = {
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
};

static const u8 data_segment_data_2[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  
};

static void init_memory(void) {
  wasm_rt_allocate_memory((&memory), 17, 65536);
  memcpy(&(memory.data[1048576u]), data_segment_data_0, 13041);
  memcpy(&(memory.data[1061624u]), data_segment_data_1, 9);
  memcpy(&(memory.data[1061640u]), data_segment_data_2, 648);
}

static void init_table(void) {
  uint32_t offset;
  wasm_rt_allocate_table((&T0), 124, 124);
  offset = 1u;
  T0.data[offset + 0] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17hc62cda27386bedf7E)};
  T0.data[offset + 1] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN60__LT_alloc__string__String_u20_as_u20_core__fmt__Display_GT_3fmt17h88e8485f1d902f65E)};
  T0.data[offset + 2] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN4core3fmt3num3imp52__LT_impl_u20_core__fmt__Display_u20_for_u20_u32_GT_3fmt17haffb72d949b13748E)};
  T0.data[offset + 3] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17h017dd7820235afadE)};
  T0.data[offset + 4] = (wasm_rt_elem_t){func_types[2], (wasm_rt_anyfunc_t)(&_ZN4wasm4main17h0fcb4ec8ced93f5dE)};
  T0.data[offset + 5] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h0b50dd8d2a848e35E)};
  T0.data[offset + 6] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN58__LT_std__io__error__Error_u20_as_u20_core__fmt__Debug_GT_3fmt17he9ea5949f4a2990eE)};
  T0.data[offset + 7] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h2536ad9e9e2aef4bE)};
  T0.data[offset + 8] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN61__LT_core__num__ParseIntError_u20_as_u20_core__fmt__Debug_GT_3fmt17h121cef04e893d4c1E)};
  T0.data[offset + 9] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN57__LT_core__str__Utf8Error_u20_as_u20_core__fmt__Debug_GT_3fmt17hf1ddee02a010aedaE)};
  T0.data[offset + 10] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h6f88c2a73a2f75e3E)};
  T0.data[offset + 11] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN46__LT_wasm__NewSword_u20_as_u20_wasm__Sword_GT_7inspect17hf7461e527deeaef1E)};
  T0.data[offset + 12] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN46__LT_wasm__NewSword_u20_as_u20_wasm__Sword_GT_7display17h4e2aee64bd382a71E)};
  T0.data[offset + 13] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h817fb0c7ec85b37eE)};
  T0.data[offset + 14] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN48__LT_wasm__RustySword_u20_as_u20_wasm__Sword_GT_7inspect17h0a0fbb6cb6fae517E)};
  T0.data[offset + 15] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN48__LT_wasm__RustySword_u20_as_u20_wasm__Sword_GT_7display17hfb31197012fa7bd0E)};
  T0.data[offset + 16] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17hd3f3959f4c97243cE)};
  T0.data[offset + 17] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN3std5error5Error5cause17h42b6be22af74ab4cE)};
  T0.data[offset + 18] = (wasm_rt_elem_t){func_types[4], (wasm_rt_anyfunc_t)(&_ZN3std5error5Error7type_id17hd7db71e5437d290fE)};
  T0.data[offset + 19] = (wasm_rt_elem_t){func_types[7], (wasm_rt_anyfunc_t)(&_ZN3std5error5Error9backtrace17hb542ab28ea02206fE)};
  T0.data[offset + 20] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN243__LT_std__error___LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__boxed__Box_LT_dyn_u20_std__error__Error_u2b_core__marker__Sync_u2b_core__marker__Send_GT__GT___from__StringError_u20_as_u20_std__error__Error_GT_11description17h29c39b0cc2d10c9fE)};
  T0.data[offset + 21] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN244__LT_std__error___LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__boxed__Box_LT_dyn_u20_std__error__Error_u2b_core__marker__Sync_u2b_core__marker__Send_GT__GT___from__StringError_u20_as_u20_core__fmt__Display_GT_3fmt17h36f89103f15672f6E)};
  T0.data[offset + 22] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN242__LT_std__error___LT_impl_u20_core__convert__From_LT_alloc__string__String_GT__u20_for_u20_alloc__boxed__Box_LT_dyn_u20_std__error__Error_u2b_core__marker__Sync_u2b_core__marker__Send_GT__GT___from__StringError_u20_as_u20_core__fmt__Debug_GT_3fmt17hd9db4bd6825b019cE)};
  T0.data[offset + 23] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h8527075be1a03755E)};
  T0.data[offset + 24] = (wasm_rt_elem_t){func_types[7], (wasm_rt_anyfunc_t)(&_ZN3std2rt10lang_start28__u7b__u7b_closure_u7d__u7d_17h38b7bbbd60866851E)};
  T0.data[offset + 25] = (wasm_rt_elem_t){func_types[7], (wasm_rt_anyfunc_t)(&_ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h1734dabf5e32b98aE)};
  T0.data[offset + 26] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN59__LT_core__fmt__Arguments_u20_as_u20_core__fmt__Display_GT_3fmt17h25afdf22ace19a57E)};
  T0.data[offset + 27] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17he7c55c53190843baE)};
  T0.data[offset + 28] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN45__LT__RF_T_u20_as_u20_core__fmt__UpperHex_GT_3fmt17h7be854885e27c6ffE)};
  T0.data[offset + 29] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h0154d9e42860dd53E)};
  T0.data[offset + 30] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN60__LT_std__io__error__Error_u20_as_u20_core__fmt__Display_GT_3fmt17h12ea3a633b564efaE)};
  T0.data[offset + 31] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN55__LT_std__path__Display_u20_as_u20_core__fmt__Debug_GT_3fmt17hfa561203d2c037b8E)};
  T0.data[offset + 32] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17h30c05985b633232cE)};
  T0.data[offset + 33] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN4core3fmt3num3imp52__LT_impl_u20_core__fmt__Display_u20_for_u20_i32_GT_3fmt17hcf6a92db823ff527E)};
  T0.data[offset + 34] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN60__LT_alloc__string__String_u20_as_u20_core__fmt__Display_GT_3fmt17h88e8485f1d902f65E_1)};
  T0.data[offset + 35] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN61__LT_std__ffi__c_str__CString_u20_as_u20_core__fmt__Debug_GT_3fmt17h76df9c6c5e27e8efE)};
  T0.data[offset + 36] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN3std5alloc24default_alloc_error_hook17h676e6a95f439f851E)};
  T0.data[offset + 37] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17hb42a3b6b7f8cdfc5E)};
  T0.data[offset + 38] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN91__LT_std__sys_common__backtrace___print__DisplayBacktrace_u20_as_u20_core__fmt__Display_GT_3fmt17h25daba2a18d6a743E)};
  T0.data[offset + 39] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h02dece875a093ec5E)};
  T0.data[offset + 40] = (wasm_rt_elem_t){func_types[8], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h17594c444a344b88E)};
  T0.data[offset + 41] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17hd2e1f2321b48f67eE)};
  T0.data[offset + 42] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17h64f54daf655ce739E)};
  T0.data[offset + 43] = (wasm_rt_elem_t){func_types[8], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h43a4a1478c7fe4a7E)};
  T0.data[offset + 44] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17h1148e112010023a0E)};
  T0.data[offset + 45] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17hdd5646de992e1c42E)};
  T0.data[offset + 46] = (wasm_rt_elem_t){func_types[8], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h2ccf06e1a3fafb6aE)};
  T0.data[offset + 47] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17h847b5ed38de6fefaE)};
  T0.data[offset + 48] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17h3b7bf02809848e00E)};
  T0.data[offset + 49] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h2e0883158ff4bc71E)};
  T0.data[offset + 50] = (wasm_rt_elem_t){func_types[4], (wasm_rt_anyfunc_t)(&_ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h029516de738f74ddE)};
  T0.data[offset + 51] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN63__LT_core__cell__BorrowMutError_u20_as_u20_core__fmt__Debug_GT_3fmt17h888db12a3966bea9E)};
  T0.data[offset + 52] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h12fdb55a43c98e2eE)};
  T0.data[offset + 53] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN62__LT_std__ffi__c_str__NulError_u20_as_u20_core__fmt__Debug_GT_3fmt17h7aebd1ccdb940e5aE)};
  T0.data[offset + 54] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN60__LT_core__cell__BorrowError_u20_as_u20_core__fmt__Debug_GT_3fmt17hdfa14f22cbd9ae5fE)};
  T0.data[offset + 55] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h049ce136079928c5E)};
  T0.data[offset + 56] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN82__LT_std__sys_common__poison__PoisonError_LT_T_GT__u20_as_u20_core__fmt__Debug_GT_3fmt17h16f30397faa9688eE)};
  T0.data[offset + 57] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h1bc2903d971cdafdE)};
  T0.data[offset + 58] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN3std5error5Error5cause17h4f470d68a88d26ceE)};
  T0.data[offset + 59] = (wasm_rt_elem_t){func_types[4], (wasm_rt_anyfunc_t)(&_ZN3std5error5Error7type_id17h57e588fb6656ec7eE)};
  T0.data[offset + 60] = (wasm_rt_elem_t){func_types[7], (wasm_rt_anyfunc_t)(&_ZN3std5error5Error9backtrace17he16cc217c1a2f33bE)};
  T0.data[offset + 61] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN62__LT_std__io__error__ErrorKind_u20_as_u20_core__fmt__Debug_GT_3fmt17h3ea22aa413b60deaE)};
  T0.data[offset + 62] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN4core3fmt3num50__LT_impl_u20_core__fmt__Debug_u20_for_u20_i32_GT_3fmt17h1f2c474a10b11f09E)};
  T0.data[offset + 63] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN58__LT_alloc__string__String_u20_as_u20_core__fmt__Debug_GT_3fmt17h2cea2baa4dfef855E)};
  T0.data[offset + 64] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h4fb62c5b377abd3dE)};
  T0.data[offset + 65] = (wasm_rt_elem_t){func_types[8], (wasm_rt_anyfunc_t)(&_ZN80__LT_std__io__Write__write_fmt__Adaptor_LT_T_GT__u20_as_u20_core__fmt__Write_GT_9write_str17hfba8d08e2a0d6be2E)};
  T0.data[offset + 66] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN4core3fmt5Write10write_char17h0b163bb0f36a33d5E)};
  T0.data[offset + 67] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN4core3fmt5Write9write_fmt17h0c6297cc94671fdbE)};
  T0.data[offset + 68] = (wasm_rt_elem_t){func_types[8], (wasm_rt_anyfunc_t)(&_ZN80__LT_std__io__Write__write_fmt__Adaptor_LT_T_GT__u20_as_u20_core__fmt__Write_GT_9write_str17habbf305c93d57a52E)};
  T0.data[offset + 69] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN4core3fmt5Write10write_char17hd5e375ed7cc26f67E)};
  T0.data[offset + 70] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN4core3fmt5Write9write_fmt17hef4ec0875f790078E)};
  T0.data[offset + 71] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN3std4sync4once4Once9call_once28__u7b__u7b_closure_u7d__u7d_17ha8365db8fceb4f2cE)};
  T0.data[offset + 72] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h2bc8b0235c26cfedE)};
  T0.data[offset + 73] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h357736d8dd8f427cE)};
  T0.data[offset + 74] = (wasm_rt_elem_t){func_types[8], (wasm_rt_anyfunc_t)(&_ZN3std10sys_common9backtrace10_print_fmt28__u7b__u7b_closure_u7d__u7d_17ha62efdc37013783cE)};
  T0.data[offset + 75] = (wasm_rt_elem_t){func_types[8], (wasm_rt_anyfunc_t)(&_ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h717d1eb4223145c5E)};
  T0.data[offset + 76] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17h458ee20a9f44d36bE)};
  T0.data[offset + 77] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ops8function6FnOnce40call_once_u7b__u7b_vtable_shim_u7d__u7d_17hfef0f420f30980acE)};
  T0.data[offset + 78] = (wasm_rt_elem_t){func_types[5], (wasm_rt_anyfunc_t)(&_ZN60__LT_std__io__stdio__StderrRaw_u20_as_u20_std__io__Write_GT_5write17hf7531ab2fbcf77b3E)};
  T0.data[offset + 79] = (wasm_rt_elem_t){func_types[5], (wasm_rt_anyfunc_t)(&_ZN3std2io5Write14write_vectored17hcfbf4a1d27a1ae81E)};
  T0.data[offset + 80] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN59__LT_std__process__ChildStdin_u20_as_u20_std__io__Write_GT_5flush17h3236cbe8e09377f1E)};
  T0.data[offset + 81] = (wasm_rt_elem_t){func_types[5], (wasm_rt_anyfunc_t)(&_ZN3std2io5Write9write_all17h3c6b69cf0d5dfa52E)};
  T0.data[offset + 82] = (wasm_rt_elem_t){func_types[5], (wasm_rt_anyfunc_t)(&_ZN3std2io5Write18write_all_vectored17h31bcf0c43c76d367E)};
  T0.data[offset + 83] = (wasm_rt_elem_t){func_types[6], (wasm_rt_anyfunc_t)(&_ZN3std2io5Write9write_fmt17h61c08c303399aa39E)};
  T0.data[offset + 84] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17had9a6dbef51e0932E)};
  T0.data[offset + 85] = (wasm_rt_elem_t){func_types[5], (wasm_rt_anyfunc_t)(&_ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_5write17h1f75c072454a7cb2E)};
  T0.data[offset + 86] = (wasm_rt_elem_t){func_types[5], (wasm_rt_anyfunc_t)(&_ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_14write_vectored17hdc4c24efc025d6a0E)};
  T0.data[offset + 87] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_5flush17h9425a9f607fd3865E)};
  T0.data[offset + 88] = (wasm_rt_elem_t){func_types[5], (wasm_rt_anyfunc_t)(&_ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_9write_all17hce2c6010f31eb804E)};
  T0.data[offset + 89] = (wasm_rt_elem_t){func_types[5], (wasm_rt_anyfunc_t)(&_ZN3std2io5Write18write_all_vectored17hbfa4a88028508b9dE)};
  T0.data[offset + 90] = (wasm_rt_elem_t){func_types[6], (wasm_rt_anyfunc_t)(&_ZN3std2io5impls71__LT_impl_u20_std__io__Write_u20_for_u20_alloc__boxed__Box_LT_W_GT__GT_9write_fmt17h1cfe94106c0e4d55E)};
  T0.data[offset + 91] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17hfd7be1f615408ba6E)};
  T0.data[offset + 92] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN90__LT_std__panicking__begin_panic_handler__PanicPayload_u20_as_u20_core__panic__BoxMeUp_GT_8take_box17h2d26e4289e9e0f5bE)};
  T0.data[offset + 93] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN90__LT_std__panicking__begin_panic_handler__PanicPayload_u20_as_u20_core__panic__BoxMeUp_GT_3get17haebaf56b59d9f0f7E)};
  T0.data[offset + 94] = (wasm_rt_elem_t){func_types[4], (wasm_rt_anyfunc_t)(&_ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h0190c02ab65d56acE)};
  T0.data[offset + 95] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN91__LT_std__panicking__begin_panic__PanicPayload_LT_A_GT__u20_as_u20_core__panic__BoxMeUp_GT_8take_box17h00afc1f3240f4984E)};
  T0.data[offset + 96] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_ZN91__LT_std__panicking__begin_panic__PanicPayload_LT_A_GT__u20_as_u20_core__panic__BoxMeUp_GT_3get17hf7b2418ff47c602eE)};
  T0.data[offset + 97] = (wasm_rt_elem_t){func_types[4], (wasm_rt_anyfunc_t)(&_ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h1036ec8cc0ac4000E)};
  T0.data[offset + 98] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h7b30a097e07ac9d4E)};
  T0.data[offset + 99] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17hed958284c2b6c751E)};
  T0.data[offset + 100] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h33fbe4fe765398d6E)};
  T0.data[offset + 101] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h402ec9c621dc0a64E)};
  T0.data[offset + 102] = (wasm_rt_elem_t){func_types[8], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h0d968c1939c85c57E)};
  T0.data[offset + 103] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17he835ee2740080451E)};
  T0.data[offset + 104] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17hd12a4d5c4ea306b5E)};
  T0.data[offset + 105] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN53__LT_core__fmt__Error_u20_as_u20_core__fmt__Debug_GT_3fmt17h0546d0fd69e4b730E)};
  T0.data[offset + 106] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17ha84d8cd9be8910c1E)};
  T0.data[offset + 107] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN71__LT_core__ops__range__Range_LT_Idx_GT__u20_as_u20_core__fmt__Debug_GT_3fmt17h560d60a49501f432E)};
  T0.data[offset + 108] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN41__LT_char_u20_as_u20_core__fmt__Debug_GT_3fmt17hb09a68fda0268a45E)};
  T0.data[offset + 109] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN4core3ops8function6FnOnce9call_once17h0c772a731295e95aE)};
  T0.data[offset + 110] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17hb3a7d31ca8f59d32E)};
  T0.data[offset + 111] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3ptr13drop_in_place17h01fc6f5e51d8edbeE)};
  T0.data[offset + 112] = (wasm_rt_elem_t){func_types[4], (wasm_rt_anyfunc_t)(&_ZN36__LT_T_u20_as_u20_core__any__Any_GT_7type_id17h21038e7fd8af2881E)};
  T0.data[offset + 113] = (wasm_rt_elem_t){func_types[8], (wasm_rt_anyfunc_t)(&_ZN68__LT_core__fmt__builders__PadAdapter_u20_as_u20_core__fmt__Write_GT_9write_str17hb63bd9b52d2ea355E)};
  T0.data[offset + 114] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN4core3fmt5Write10write_char17h2e3be12005dd62ddE)};
  T0.data[offset + 115] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN4core3fmt5Write9write_fmt17h0c139c28d79b9a60E)};
  T0.data[offset + 116] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h82db6cee448a2919E)};
  T0.data[offset + 117] = (wasm_rt_elem_t){func_types[8], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_str17h079bfd1e4c225fd5E)};
  T0.data[offset + 118] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_10write_char17h6458f56299ed9010E)};
  T0.data[offset + 119] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN50__LT__RF_mut_u20_W_u20_as_u20_core__fmt__Write_GT_9write_fmt17h8b43657baa867c64E)};
  T0.data[offset + 120] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17hde16ba6a50b346e4E)};
  T0.data[offset + 121] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17he1c9497b0427386eE)};
  T0.data[offset + 122] = (wasm_rt_elem_t){func_types[3], (wasm_rt_anyfunc_t)(&_ZN42__LT__RF_T_u20_as_u20_core__fmt__Debug_GT_3fmt17h8ebaddfa97032842E)};
}

/* export: 'memory' */
wasm_rt_memory_t (*WASM_RT_ADD_PREFIX(Z_memory));
/* export: '_start' */
void (*WASM_RT_ADD_PREFIX(Z__startZ_vv))(void);
/* export: '__original_main' */
u32 (*WASM_RT_ADD_PREFIX(Z___original_mainZ_iv))(void);
/* export: 'main' */
u32 (*WASM_RT_ADD_PREFIX(Z_mainZ_iii))(u32, u32);
/* export: '__data_end' */
u32 (*WASM_RT_ADD_PREFIX(Z___data_endZ_i));
/* export: '__heap_base' */
u32 (*WASM_RT_ADD_PREFIX(Z___heap_baseZ_i));

static void init_exports(void) {
  /* export: 'memory' */
  WASM_RT_ADD_PREFIX(Z_memory) = (&memory);
  /* export: '_start' */
  WASM_RT_ADD_PREFIX(Z__startZ_vv) = (&_start);
  /* export: '__original_main' */
  WASM_RT_ADD_PREFIX(Z___original_mainZ_iv) = (&__original_main);
  /* export: 'main' */
  WASM_RT_ADD_PREFIX(Z_mainZ_iii) = (&main);
  /* export: '__data_end' */
  WASM_RT_ADD_PREFIX(Z___data_endZ_i) = (&__data_end);
  /* export: '__heap_base' */
  WASM_RT_ADD_PREFIX(Z___heap_baseZ_i) = (&__heap_base);
}

void WASM_RT_ADD_PREFIX(init)(void) {
  init_func_types();
  init_globals();
  init_memory();
  init_table();
  init_exports();
}
