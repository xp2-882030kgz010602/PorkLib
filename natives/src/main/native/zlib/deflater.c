#include "../common.h"
#include "net_daporkchop_lib_natives_zlib_NativeDeflater.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include <stdio.h>

typedef struct {
    z_stream stream;
    jlong srcAddr;
    jlong srcLen;
    jlong dstAddr;
    jlong dstLen;
    jlong readBytes;
    jlong writtenBytes;
} context_t;

static jfieldID ctxID;

void JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_load(JNIEnv* env, jclass cla)  {
    ctxID = env->GetFieldID(cla, "ctx", "J");
}

jlong JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_init(JNIEnv* env, jclass cla, jint level, jboolean nowrap)   {
    context_t* context = (context_t*) malloc(sizeof(context_t));
    memset(context, 0, sizeof(context_t));
    int ret = deflateInit(&context->stream, level);

    if (ret != Z_OK)    {
        free(context);
        throwException(env, "Couldn't init deflater!", ret);
    }

    return (jlong) context;
}

void JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_end(JNIEnv* env, jclass cla, jlong ctx)  {
    context_t* context = (context_t*) ctx;
    int ret = deflateEnd(&context->stream);
    free(context);

    if (ret != Z_OK)    {
        throwException(env, "Couldn't end deflater!", ret);
    }
}

void JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_input(JNIEnv* env, jobject obj, jlong srcAddr, jlong srcLen) {
    context_t* context = (context_t*) env->GetLongField(obj, ctxID);

    context->srcAddr = srcAddr;
    context->srcLen = srcLen;
}

void JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_output(JNIEnv* env, jobject obj, jlong dstAddr, jlong dstLen)    {
    context_t* context = (context_t*) env->GetLongField(obj, ctxID);

    context->dstAddr = dstAddr;
    context->dstLen = dstLen;
}

void JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_deflateFinish(JNIEnv* env, jobject obj)    {
    context_t* context = (context_t*) env->GetLongField(obj, ctxID);

    jlong srcLen       = context->srcLen;
    jlong dstLen       = context->dstLen;
    jlong readBytes    = 0;
    jlong writtenBytes = 0;

    while (srcLen - readBytes)  {
        context->stream.next_in  = (unsigned char*) (context->srcAddr + readBytes);
        context->stream.next_out = (unsigned char*) (context->dstAddr + writtenBytes);

        auto avail_in  = context->stream.avail_in =  (unsigned int) min_l((srcLen - readBytes), 0x0FFFFFFF);
        auto avail_out = context->stream.avail_out = (unsigned int) min_l((dstLen - writtenBytes), 0x0FFFFFFF);

        int ret = deflate(&context->stream, Z_NO_FLUSH); //Z_NO_FLUSH allows zlib to decide how much data to buffer before flushing itself
        if (ret != Z_OK)    {
            throwException(env, "Invalid return value from deflate content!", ret);
            return;
        }

        //printf("srcLen: %ld, dstLen: %ld, readBytes: %ld + %d, writtenBytes: %ld + %d\n", srcLen - readBytes, dstLen - writtenBytes, readBytes, avail_in - context->stream.avail_in, writtenBytes, avail_out - context->stream.avail_out);
        readBytes    += (jlong) (avail_in - context->stream.avail_in);
        writtenBytes += (jlong) (avail_out - context->stream.avail_out);
    }

    context->stream.avail_in = 0;
    int ret;
    do {
        context->stream.next_out = (unsigned char*) (context->dstAddr + writtenBytes);
        auto avail_out = context->stream.avail_out = (unsigned int) (dstLen - writtenBytes);

        ret = deflate(&context->stream, Z_FINISH);

        //printf("srcLen: %ld, dstLen: %ld, readBytes: %ld + %d, writtenBytes: %ld + %d\n", srcLen - readBytes, dstLen - writtenBytes, readBytes, 0, writtenBytes, avail_out - context->stream.avail_out);

        writtenBytes += (jlong) (avail_out - context->stream.avail_out);
    } while (ret == Z_OK);

    if (ret != Z_STREAM_END)    {
        throwException(env, "Invalid return value from deflate flush!", ret);
    }

    context->readBytes    = readBytes;
    context->writtenBytes = writtenBytes;
}

void JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_deflate(JNIEnv* env, jobject obj);

jlong JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_readBytes(JNIEnv* env, jobject obj) {
    context_t* context = (context_t*) env->GetLongField(obj, ctxID);

    return context->readBytes;
}

jlong JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_writtenBytes(JNIEnv* env, jobject obj)  {
    context_t* context = (context_t*) env->GetLongField(obj, ctxID);

    return context->writtenBytes;
}

void JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_finish(JNIEnv* env, jobject obj);

jboolean JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_finished(JNIEnv* env, jobject obj);

void JNICALL Java_net_daporkchop_lib_natives_zlib_NativeDeflater_reset(JNIEnv* env, jobject obj)     {
    context_t* context = (context_t*) env->GetLongField(obj, ctxID);
    int ret = deflateReset(&context->stream);
    memset(context + sizeof(z_stream), 0, sizeof(context_t) - sizeof(z_stream));

    if (ret != Z_OK)    {
        throwException(env, "Couldn't reset deflater!", ret);
    }
}
