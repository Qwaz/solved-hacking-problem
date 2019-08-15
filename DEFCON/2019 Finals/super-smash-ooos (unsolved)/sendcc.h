#ifndef SENDCC_H_GENERATED_
#define SENDCC_H_GENERATED_
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "wasm-rt.h"

#ifndef WASM_RT_MODULE_PREFIX
#define WASM_RT_MODULE_PREFIX
#endif

#define WASM_RT_PASTE_(x, y) x ## y
#define WASM_RT_PASTE(x, y) WASM_RT_PASTE_(x, y)
#define WASM_RT_ADD_PREFIX(x) WASM_RT_PASTE(WASM_RT_MODULE_PREFIX, x)

/* TODO(binji): only use stdint.h types in header */
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;
typedef float f32;
typedef double f64;

extern void WASM_RT_ADD_PREFIX(init)(void);

/* import: 'env' 'abortStackOverflow' */
extern void (*Z_envZ_abortStackOverflowZ_vi)(u32);
/* import: 'env' 'nullFunc_ii' */
extern void (*Z_envZ_nullFunc_iiZ_vi)(u32);
/* import: 'env' 'nullFunc_iidiiii' */
extern void (*Z_envZ_nullFunc_iidiiiiZ_vi)(u32);
/* import: 'env' 'nullFunc_iii' */
extern void (*Z_envZ_nullFunc_iiiZ_vi)(u32);
/* import: 'env' 'nullFunc_iiii' */
extern void (*Z_envZ_nullFunc_iiiiZ_vi)(u32);
/* import: 'env' 'nullFunc_iiiii' */
extern void (*Z_envZ_nullFunc_iiiiiZ_vi)(u32);
/* import: 'env' 'nullFunc_iiiiid' */
extern void (*Z_envZ_nullFunc_iiiiidZ_vi)(u32);
/* import: 'env' 'nullFunc_iiiiii' */
extern void (*Z_envZ_nullFunc_iiiiiiZ_vi)(u32);
/* import: 'env' 'nullFunc_iiiiiid' */
extern void (*Z_envZ_nullFunc_iiiiiidZ_vi)(u32);
/* import: 'env' 'nullFunc_iiiiiii' */
extern void (*Z_envZ_nullFunc_iiiiiiiZ_vi)(u32);
/* import: 'env' 'nullFunc_iiiiiiii' */
extern void (*Z_envZ_nullFunc_iiiiiiiiZ_vi)(u32);
/* import: 'env' 'nullFunc_iiiiiiiii' */
extern void (*Z_envZ_nullFunc_iiiiiiiiiZ_vi)(u32);
/* import: 'env' 'nullFunc_iiiiij' */
extern void (*Z_envZ_nullFunc_iiiiijZ_vi)(u32);
/* import: 'env' 'nullFunc_jiji' */
extern void (*Z_envZ_nullFunc_jijiZ_vi)(u32);
/* import: 'env' 'nullFunc_v' */
extern void (*Z_envZ_nullFunc_vZ_vi)(u32);
/* import: 'env' 'nullFunc_vi' */
extern void (*Z_envZ_nullFunc_viZ_vi)(u32);
/* import: 'env' 'nullFunc_vii' */
extern void (*Z_envZ_nullFunc_viiZ_vi)(u32);
/* import: 'env' 'nullFunc_viii' */
extern void (*Z_envZ_nullFunc_viiiZ_vi)(u32);
/* import: 'env' 'nullFunc_viiii' */
extern void (*Z_envZ_nullFunc_viiiiZ_vi)(u32);
/* import: 'env' 'nullFunc_viiiii' */
extern void (*Z_envZ_nullFunc_viiiiiZ_vi)(u32);
/* import: 'env' 'nullFunc_viiiiii' */
extern void (*Z_envZ_nullFunc_viiiiiiZ_vi)(u32);
/* import: 'env' 'jsCall_ii' */
extern u32 (*Z_envZ_jsCall_iiZ_iii)(u32, u32);
/* import: 'env' 'jsCall_iidiiii' */
extern u32 (*Z_envZ_jsCall_iidiiiiZ_iiidiiii)(u32, u32, f64, u32, u32, u32, u32);
/* import: 'env' 'jsCall_iii' */
extern u32 (*Z_envZ_jsCall_iiiZ_iiii)(u32, u32, u32);
/* import: 'env' 'jsCall_iiii' */
extern u32 (*Z_envZ_jsCall_iiiiZ_iiiii)(u32, u32, u32, u32);
/* import: 'env' 'jsCall_iiiii' */
extern u32 (*Z_envZ_jsCall_iiiiiZ_iiiiii)(u32, u32, u32, u32, u32);
/* import: 'env' 'jsCall_iiiiid' */
extern u32 (*Z_envZ_jsCall_iiiiidZ_iiiiiid)(u32, u32, u32, u32, u32, f64);
/* import: 'env' 'jsCall_iiiiii' */
extern u32 (*Z_envZ_jsCall_iiiiiiZ_iiiiiii)(u32, u32, u32, u32, u32, u32);
/* import: 'env' 'jsCall_iiiiiid' */
extern u32 (*Z_envZ_jsCall_iiiiiidZ_iiiiiiid)(u32, u32, u32, u32, u32, u32, f64);
/* import: 'env' 'jsCall_iiiiiii' */
extern u32 (*Z_envZ_jsCall_iiiiiiiZ_iiiiiiii)(u32, u32, u32, u32, u32, u32, u32);
/* import: 'env' 'jsCall_iiiiiiii' */
extern u32 (*Z_envZ_jsCall_iiiiiiiiZ_iiiiiiiii)(u32, u32, u32, u32, u32, u32, u32, u32);
/* import: 'env' 'jsCall_iiiiiiiii' */
extern u32 (*Z_envZ_jsCall_iiiiiiiiiZ_iiiiiiiiii)(u32, u32, u32, u32, u32, u32, u32, u32, u32);
/* import: 'env' 'jsCall_v' */
extern void (*Z_envZ_jsCall_vZ_vi)(u32);
/* import: 'env' 'jsCall_vi' */
extern void (*Z_envZ_jsCall_viZ_vii)(u32, u32);
/* import: 'env' 'jsCall_vii' */
extern void (*Z_envZ_jsCall_viiZ_viii)(u32, u32, u32);
/* import: 'env' 'jsCall_viii' */
extern void (*Z_envZ_jsCall_viiiZ_viiii)(u32, u32, u32, u32);
/* import: 'env' 'jsCall_viiii' */
extern void (*Z_envZ_jsCall_viiiiZ_viiiii)(u32, u32, u32, u32, u32);
/* import: 'env' 'jsCall_viiiii' */
extern void (*Z_envZ_jsCall_viiiiiZ_viiiiii)(u32, u32, u32, u32, u32, u32);
/* import: 'env' 'jsCall_viiiiii' */
extern void (*Z_envZ_jsCall_viiiiiiZ_viiiiiii)(u32, u32, u32, u32, u32, u32, u32);
/* import: 'env' '___assert_fail' */
extern void (*Z_envZ____assert_failZ_viiii)(u32, u32, u32, u32);
/* import: 'env' '___buildEnvironment' */
extern void (*Z_envZ____buildEnvironmentZ_vi)(u32);
/* import: 'env' '___cxa_allocate_exception' */
extern u32 (*Z_envZ____cxa_allocate_exceptionZ_ii)(u32);
/* import: 'env' '___cxa_begin_catch' */
extern u32 (*Z_envZ____cxa_begin_catchZ_ii)(u32);
/* import: 'env' '___cxa_pure_virtual' */
extern void (*Z_envZ____cxa_pure_virtualZ_vv)(void);
/* import: 'env' '___cxa_throw' */
extern void (*Z_envZ____cxa_throwZ_viii)(u32, u32, u32);
/* import: 'env' '___lock' */
extern void (*Z_envZ____lockZ_vi)(u32);
/* import: 'env' '___map_file' */
extern u32 (*Z_envZ____map_fileZ_iii)(u32, u32);
/* import: 'env' '___setErrNo' */
extern void (*Z_envZ____setErrNoZ_vi)(u32);
/* import: 'env' '___syscall102' */
extern u32 (*Z_envZ____syscall102Z_iii)(u32, u32);
/* import: 'env' '___syscall140' */
extern u32 (*Z_envZ____syscall140Z_iii)(u32, u32);
/* import: 'env' '___syscall142' */
extern u32 (*Z_envZ____syscall142Z_iii)(u32, u32);
/* import: 'env' '___syscall146' */
extern u32 (*Z_envZ____syscall146Z_iii)(u32, u32);
/* import: 'env' '___syscall221' */
extern u32 (*Z_envZ____syscall221Z_iii)(u32, u32);
/* import: 'env' '___syscall54' */
extern u32 (*Z_envZ____syscall54Z_iii)(u32, u32);
/* import: 'env' '___syscall6' */
extern u32 (*Z_envZ____syscall6Z_iii)(u32, u32);
/* import: 'env' '___syscall91' */
extern u32 (*Z_envZ____syscall91Z_iii)(u32, u32);
/* import: 'env' '___unlock' */
extern void (*Z_envZ____unlockZ_vi)(u32);
/* import: 'env' '__embind_register_bool' */
extern void (*Z_envZ___embind_register_boolZ_viiiii)(u32, u32, u32, u32, u32);
/* import: 'env' '__embind_register_class' */
extern void (*Z_envZ___embind_register_classZ_viiiiiiiiiiiii)(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);
/* import: 'env' '__embind_register_class_constructor' */
extern void (*Z_envZ___embind_register_class_constructorZ_viiiiii)(u32, u32, u32, u32, u32, u32);
/* import: 'env' '__embind_register_class_function' */
extern void (*Z_envZ___embind_register_class_functionZ_viiiiiiii)(u32, u32, u32, u32, u32, u32, u32, u32);
/* import: 'env' '__embind_register_class_property' */
extern void (*Z_envZ___embind_register_class_propertyZ_viiiiiiiiii)(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);
/* import: 'env' '__embind_register_emval' */
extern void (*Z_envZ___embind_register_emvalZ_vii)(u32, u32);
/* import: 'env' '__embind_register_float' */
extern void (*Z_envZ___embind_register_floatZ_viii)(u32, u32, u32);
/* import: 'env' '__embind_register_integer' */
extern void (*Z_envZ___embind_register_integerZ_viiiii)(u32, u32, u32, u32, u32);
/* import: 'env' '__embind_register_memory_view' */
extern void (*Z_envZ___embind_register_memory_viewZ_viii)(u32, u32, u32);
/* import: 'env' '__embind_register_std_string' */
extern void (*Z_envZ___embind_register_std_stringZ_vii)(u32, u32);
/* import: 'env' '__embind_register_std_wstring' */
extern void (*Z_envZ___embind_register_std_wstringZ_viii)(u32, u32, u32);
/* import: 'env' '__embind_register_void' */
extern void (*Z_envZ___embind_register_voidZ_vii)(u32, u32);
/* import: 'env' '__emval_call_method' */
extern f64 (*Z_envZ___emval_call_methodZ_diiiii)(u32, u32, u32, u32, u32);
/* import: 'env' '__emval_decref' */
extern void (*Z_envZ___emval_decrefZ_vi)(u32);
/* import: 'env' '__emval_get_global' */
extern u32 (*Z_envZ___emval_get_globalZ_ii)(u32);
/* import: 'env' '__emval_get_method_caller' */
extern u32 (*Z_envZ___emval_get_method_callerZ_iii)(u32, u32);
/* import: 'env' '__emval_incref' */
extern void (*Z_envZ___emval_increfZ_vi)(u32);
/* import: 'env' '__emval_new_cstring' */
extern u32 (*Z_envZ___emval_new_cstringZ_ii)(u32);
/* import: 'env' '__emval_run_destructors' */
extern void (*Z_envZ___emval_run_destructorsZ_vi)(u32);
/* import: 'env' '__emval_take_value' */
extern u32 (*Z_envZ___emval_take_valueZ_iii)(u32, u32);
/* import: 'env' '_abort' */
extern void (*Z_envZ__abortZ_vv)(void);
/* import: 'env' '_emscripten_cancel_main_loop' */
extern void (*Z_envZ__emscripten_cancel_main_loopZ_vv)(void);
/* import: 'env' '_emscripten_get_heap_size' */
extern u32 (*Z_envZ__emscripten_get_heap_sizeZ_iv)(void);
/* import: 'env' '_emscripten_memcpy_big' */
extern u32 (*Z_envZ__emscripten_memcpy_bigZ_iiii)(u32, u32, u32);
/* import: 'env' '_emscripten_resize_heap' */
extern u32 (*Z_envZ__emscripten_resize_heapZ_ii)(u32);
/* import: 'env' '_emscripten_set_main_loop' */
extern void (*Z_envZ__emscripten_set_main_loopZ_viii)(u32, u32, u32);
/* import: 'env' '_getenv' */
extern u32 (*Z_envZ__getenvZ_ii)(u32);
/* import: 'env' '_llvm_stackrestore' */
extern void (*Z_envZ__llvm_stackrestoreZ_vi)(u32);
/* import: 'env' '_llvm_stacksave' */
extern u32 (*Z_envZ__llvm_stacksaveZ_iv)(void);
/* import: 'env' '_llvm_trap' */
extern void (*Z_envZ__llvm_trapZ_vv)(void);
/* import: 'env' '_localtime' */
extern u32 (*Z_envZ__localtimeZ_ii)(u32);
/* import: 'env' '_pthread_cond_wait' */
extern u32 (*Z_envZ__pthread_cond_waitZ_iii)(u32, u32);
/* import: 'env' '_strftime' */
extern u32 (*Z_envZ__strftimeZ_iiiii)(u32, u32, u32, u32);
/* import: 'env' '_strftime_l' */
extern u32 (*Z_envZ__strftime_lZ_iiiiii)(u32, u32, u32, u32, u32);
/* import: 'env' '_time' */
extern u32 (*Z_envZ__timeZ_ii)(u32);
/* import: 'env' '_usleep' */
extern u32 (*Z_envZ__usleepZ_ii)(u32);
/* import: 'env' 'abortOnCannotGrowMemory' */
extern u32 (*Z_envZ_abortOnCannotGrowMemoryZ_ii)(u32);
/* import: 'env' 'setTempRet0' */
extern void (*Z_envZ_setTempRet0Z_vi)(u32);
/* import: 'env' 'jsCall_iiiiij' */
extern u32 (*Z_envZ_jsCall_iiiiijZ_iiiiiiii)(u32, u32, u32, u32, u32, u32, u32);
/* import: 'env' 'getTempRet0' */
extern u32 (*Z_envZ_getTempRet0Z_iv)(void);
/* import: 'env' 'jsCall_jiji' */
extern u32 (*Z_envZ_jsCall_jijiZ_iiiiii)(u32, u32, u32, u32, u32);
/* import: 'env' '__memory_base' */
extern u32 (*Z_envZ___memory_baseZ_i);
/* import: 'env' '__table_base' */
extern u32 (*Z_envZ___table_baseZ_i);
/* import: 'env' 'tempDoublePtr' */
extern u32 (*Z_envZ_tempDoublePtrZ_i);
/* import: 'env' 'DYNAMICTOP_PTR' */
extern u32 (*Z_envZ_DYNAMICTOP_PTRZ_i);
/* import: 'global' 'NaN' */
extern f64 (*Z_globalZ_NaNZ_d);
/* import: 'global' 'Infinity' */
extern f64 (*Z_globalZ_InfinityZ_d);
/* import: 'env' 'memory' */
extern wasm_rt_memory_t (*Z_envZ_memory);
/* import: 'env' 'table' */
extern wasm_rt_table_t (*Z_envZ_table);

/* export: '___cxa_can_catch' */
extern u32 (*WASM_RT_ADD_PREFIX(Z____cxa_can_catchZ_iiii))(u32, u32, u32);
/* export: '___cxa_is_pointer_type' */
extern u32 (*WASM_RT_ADD_PREFIX(Z____cxa_is_pointer_typeZ_ii))(u32);
/* export: '___errno_location' */
extern u32 (*WASM_RT_ADD_PREFIX(Z____errno_locationZ_iv))(void);
/* export: '___getTypeName' */
extern u32 (*WASM_RT_ADD_PREFIX(Z____getTypeNameZ_ii))(u32);
/* export: '__get_daylight' */
extern u32 (*WASM_RT_ADD_PREFIX(Z___get_daylightZ_iv))(void);
/* export: '__get_environ' */
extern u32 (*WASM_RT_ADD_PREFIX(Z___get_environZ_iv))(void);
/* export: '__get_timezone' */
extern u32 (*WASM_RT_ADD_PREFIX(Z___get_timezoneZ_iv))(void);
/* export: '__get_tzname' */
extern u32 (*WASM_RT_ADD_PREFIX(Z___get_tznameZ_iv))(void);
/* export: '_fflush' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__fflushZ_ii))(u32);
/* export: '_free' */
extern void (*WASM_RT_ADD_PREFIX(Z__freeZ_vi))(u32);
/* export: '_htonl' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__htonlZ_ii))(u32);
/* export: '_htons' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__htonsZ_ii))(u32);
/* export: '_llvm_bswap_i16' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__llvm_bswap_i16Z_ii))(u32);
/* export: '_llvm_bswap_i32' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__llvm_bswap_i32Z_ii))(u32);
/* export: '_main' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__mainZ_iv))(void);
/* export: '_malloc' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__mallocZ_ii))(u32);
/* export: '_memcpy' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__memcpyZ_iiii))(u32, u32, u32);
/* export: '_memmove' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__memmoveZ_iiii))(u32, u32, u32);
/* export: '_memset' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__memsetZ_iiii))(u32, u32, u32);
/* export: '_ntohs' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__ntohsZ_ii))(u32);
/* export: '_pthread_cond_broadcast' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__pthread_cond_broadcastZ_ii))(u32);
/* export: '_sbrk' */
extern u32 (*WASM_RT_ADD_PREFIX(Z__sbrkZ_ii))(u32);
/* export: 'dynCall_ii' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiZ_iii))(u32, u32);
/* export: 'dynCall_iidiiii' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iidiiiiZ_iiidiiii))(u32, u32, f64, u32, u32, u32, u32);
/* export: 'dynCall_iii' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiiZ_iiii))(u32, u32, u32);
/* export: 'dynCall_iiii' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiiiZ_iiiii))(u32, u32, u32, u32);
/* export: 'dynCall_iiiii' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiiiiZ_iiiiii))(u32, u32, u32, u32, u32);
/* export: 'dynCall_iiiiid' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiiiidZ_iiiiiid))(u32, u32, u32, u32, u32, f64);
/* export: 'dynCall_iiiiii' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiiiiiZ_iiiiiii))(u32, u32, u32, u32, u32, u32);
/* export: 'dynCall_iiiiiid' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiiiiidZ_iiiiiiid))(u32, u32, u32, u32, u32, u32, f64);
/* export: 'dynCall_iiiiiii' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiiiiiiZ_iiiiiiii))(u32, u32, u32, u32, u32, u32, u32);
/* export: 'dynCall_iiiiiiii' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiiiiiiiZ_iiiiiiiii))(u32, u32, u32, u32, u32, u32, u32, u32);
/* export: 'dynCall_iiiiiiiii' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiiiiiiiiZ_iiiiiiiiii))(u32, u32, u32, u32, u32, u32, u32, u32, u32);
/* export: 'dynCall_iiiiij' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_iiiiijZ_iiiiiiii))(u32, u32, u32, u32, u32, u32, u32);
/* export: 'dynCall_jiji' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_dynCall_jijiZ_iiiiii))(u32, u32, u32, u32, u32);
/* export: 'dynCall_v' */
extern void (*WASM_RT_ADD_PREFIX(Z_dynCall_vZ_vi))(u32);
/* export: 'dynCall_vi' */
extern void (*WASM_RT_ADD_PREFIX(Z_dynCall_viZ_vii))(u32, u32);
/* export: 'dynCall_vii' */
extern void (*WASM_RT_ADD_PREFIX(Z_dynCall_viiZ_viii))(u32, u32, u32);
/* export: 'dynCall_viii' */
extern void (*WASM_RT_ADD_PREFIX(Z_dynCall_viiiZ_viiii))(u32, u32, u32, u32);
/* export: 'dynCall_viiii' */
extern void (*WASM_RT_ADD_PREFIX(Z_dynCall_viiiiZ_viiiii))(u32, u32, u32, u32, u32);
/* export: 'dynCall_viiiii' */
extern void (*WASM_RT_ADD_PREFIX(Z_dynCall_viiiiiZ_viiiiii))(u32, u32, u32, u32, u32, u32);
/* export: 'dynCall_viiiiii' */
extern void (*WASM_RT_ADD_PREFIX(Z_dynCall_viiiiiiZ_viiiiiii))(u32, u32, u32, u32, u32, u32, u32);
/* export: 'establishStackSpace' */
extern void (*WASM_RT_ADD_PREFIX(Z_establishStackSpaceZ_vii))(u32, u32);
/* export: 'globalCtors' */
extern void (*WASM_RT_ADD_PREFIX(Z_globalCtorsZ_vv))(void);
/* export: 'stackAlloc' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_stackAllocZ_ii))(u32);
/* export: 'stackRestore' */
extern void (*WASM_RT_ADD_PREFIX(Z_stackRestoreZ_vi))(u32);
/* export: 'stackSave' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_stackSaveZ_iv))(void);
#ifdef __cplusplus
}
#endif

#endif  /* SENDCC_H_GENERATED_ */
