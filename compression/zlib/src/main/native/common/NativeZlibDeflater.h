/* DO NOT EDIT THIS FILE - it is machine generated */
//actually it's not, it was initially though
//easier to make this by hand lol
#include <jni.h>

#ifndef _Included_net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater
#define _Included_net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater
 * Method:    load
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater_load
  (JNIEnv *, jclass);

/*
 * Class:     net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater
 * Method:    allocateCtx
 * Signature: (III)J
 */
JNIEXPORT jlong JNICALL Java_net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater_allocateCtx
  (JNIEnv *, jclass, jint, jint, jint);

/*
 * Class:     net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater
 * Method:    releaseCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater_releaseCtx
  (JNIEnv *, jclass, jlong);

/*
 * Class:     net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater
 * Method:    doFullDeflate
 * Signature: (JIJI)Z
 */
JNIEXPORT jboolean JNICALL Java_net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater_doFullDeflate
  (JNIEnv *, jobject, jlong, jint, jlong, jint);

/*
 * Class:     net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater
 * Method:    doUpdate
 * Signature: (JIJIZ)V
 */
JNIEXPORT void JNICALL Java_net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater_doUpdate
  (JNIEnv *, jobject, jlong, jint, jlong, jint, jboolean);

/*
 * Class:     net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater
 * Method:    doFinish
 * Signature: (JIJI)Z
 */
JNIEXPORT jboolean JNICALL Java_net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater_doFinish
  (JNIEnv *, jobject, jlong, jint, jlong, jint);

/*
 * Class:     net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater
 * Method:    doReset
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater_doReset
  (JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif

#endif //_Included_net_daporkchop_lib_compression_zlib_natives_NativeZlibDeflater
