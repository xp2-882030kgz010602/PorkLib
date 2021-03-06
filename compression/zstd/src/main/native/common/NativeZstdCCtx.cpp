#include <common.h>
#include "NativeZstdCCtx.h"

#include <lib-zstd/lib/zstd.h>
#include <lib-zstd/lib/common/zstd_errors.h>

__attribute__((visibility("default"))) jlong JNICALL Java_net_daporkchop_lib_compression_zstd_natives_NativeZstdCCtx_allocateCtx
        (JNIEnv* env, jclass cla)   {
    return (jlong) ZSTD_createCCtx();
}

__attribute__((visibility("default"))) void JNICALL Java_net_daporkchop_lib_compression_zstd_natives_NativeZstdCCtx_releaseCtx
        (JNIEnv* env, jclass cla, jlong ctx)   {
    auto ret = ZSTD_freeCCtx((ZSTD_CCtx*) ctx);

    if (ZSTD_isError(ret))  {
        throwException(env, ZSTD_getErrorName(ret), (jlong) ret);
        return;
    }
}

__attribute__((visibility("default"))) jint JNICALL Java_net_daporkchop_lib_compression_zstd_natives_NativeZstdCCtx_doCompressNoDict
        (JNIEnv* env, jobject obj, jlong ctx, jlong srcAddr, jint srcSize, jlong dstAddr, jint dstSize, jint compressionLevel)   {
    auto ret = ZSTD_compressCCtx((ZSTD_CCtx*) ctx, (void*) dstAddr, dstSize, (void*) srcAddr, srcSize, compressionLevel);

    if (ZSTD_isError(ret))  {
        if (ZSTD_getErrorCode(ret) == ZSTD_error_dstSize_tooSmall) {
            return -1;
        } else {
            throwException(env, ZSTD_getErrorName(ret), (jlong) ret);
            return 0;
        }
    }

    return (jint) ret;
}

__attribute__((visibility("default"))) jint JNICALL Java_net_daporkchop_lib_compression_zstd_natives_NativeZstdCCtx_doCompressRawDict
        (JNIEnv* env, jobject obj, jlong ctx, jlong srcAddr, jint srcSize, jlong dstAddr, jint dstSize, jlong dictAddr, jint dictSize, jint compressionLevel)   {
    auto ret = ZSTD_compress_usingDict((ZSTD_CCtx*) ctx, (void*) dstAddr, dstSize, (void*) srcAddr, srcSize, (void*) dictAddr, dictSize, compressionLevel);

    if (ZSTD_isError(ret))  {
        if (ZSTD_getErrorCode(ret) == ZSTD_error_dstSize_tooSmall) {
            return -1;
        } else {
            throwException(env, ZSTD_getErrorName(ret), (jlong) ret);
            return 0;
        }
    }

    return (jint) ret;
}

__attribute__((visibility("default"))) jint JNICALL Java_net_daporkchop_lib_compression_zstd_natives_NativeZstdCCtx_doCompressCDict
        (JNIEnv* env, jobject obj, jlong ctx, jlong srcAddr, jint srcSize, jlong dstAddr, jint dstSize, jlong dictAddr)   {
    auto ret = ZSTD_compress_usingCDict((ZSTD_CCtx*) ctx, (void*) dstAddr, dstSize, (void*) srcAddr, srcSize, (ZSTD_CDict*) dictAddr);

    if (ZSTD_isError(ret))  {
        if (ZSTD_getErrorCode(ret) == ZSTD_error_dstSize_tooSmall) {
            return -1;
        } else {
            throwException(env, ZSTD_getErrorName(ret), (jlong) ret);
            return 0;
        }
    }

    return (jint) ret;
}
