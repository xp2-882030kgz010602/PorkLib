/*
 * Adapted from the Wizardry License
 *
 * Copyright (c) 2018-2020 DaPorkchop_ and contributors
 *
 * Permission is hereby granted to any persons and/or organizations using this software to copy, modify, merge, publish, and distribute it. Said persons and/or organizations are not allowed to use the software or any derivatives of the work for commercial use or any other means to generate income, nor are they allowed to claim this software as their own.
 *
 * The persons and/or organizations are also disallowed from sub-licensing and/or trademarking this software without explicit permission from DaPorkchop_.
 *
 * Any persons and/or organizations using this software must disclose their source code and have it publicly available, include this license, provide sufficient credit to the original authors of the project (IE: DaPorkchop_), as well as provide a link to the original project.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

package net.daporkchop.lib.crypto.bc.stream;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import net.daporkchop.lib.crypto.cipher.PStreamCipher;
import net.daporkchop.lib.crypto.generic.ISimpleHeapCipher;
import org.bouncycastle.crypto.StreamCipher;

import static java.lang.Math.min;

/**
 * Base interface for implementations of {@link PStreamCipher} based on a BouncyCastle stream cipher.
 *
 * @author DaPorkchop_
 */
public interface BouncyCastleStreamCipher extends PStreamCipher, StreamCipher, ISimpleHeapCipher {
    @Override
    default String getAlgorithmName() {
        return this.name();
    }

    @Override
    default void processStreaming(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        int srcReadable = src.readableBytes();
        int dstWritable = dst.writableBytes();

        if (srcReadable == 0 || dstWritable == 0) {
            return;
        }

        int count = min(srcReadable, dstWritable);

        final byte[] globalBuffer = this.globalBuffer();

        final byte[] srcArray;
        int srcArrayOffset;
        if (src.hasArray()) {
            srcArray = src.array();
            srcArrayOffset = src.arrayOffset() + src.readerIndex();
        } else {
            srcArray = globalBuffer;
            srcArrayOffset = 0;
        }

        final byte[] dstArray;
        int dstArrayOffset;
        if (dst.hasArray()) {
            dstArray = dst.array();
            dstArrayOffset = dst.arrayOffset() + dst.arrayOffset();
        } else {
            dstArray = globalBuffer;
            dstArrayOffset = 0;
        }

        if (srcArray != globalBuffer && dstArray != globalBuffer) {
            //both buffers are heap buffers, we can just pass them on to the cipher implementation
            this.processBytes(srcArray, srcArrayOffset, count, dstArray, dstArrayOffset);
            src.skipBytes(count);
            dst.writerIndex(dst.writerIndex() + count);
        } else {
            //either one of the buffers is not a heap buffer, just repeatedly process bytes in steps of up to the block size until completion
            final int blockSize = globalBuffer.length;
            while (count > 0) {
                final int roundCount = min(blockSize, count);
                count -= roundCount;

                if (srcArray == globalBuffer) {
                    src.readBytes(srcArray, 0, roundCount);
                } else {
                    src.skipBytes(roundCount);
                }

                this.processBytes(srcArray, srcArrayOffset, roundCount, dstArray, dstArrayOffset);

                if (srcArray != globalBuffer) {
                    srcArrayOffset += roundCount;
                }
                if (dstArray == globalBuffer) {
                    dst.writeBytes(globalBuffer, 0, roundCount);
                } else {
                    dst.writerIndex(dst.writerIndex() + roundCount);
                    dstArrayOffset += roundCount;
                }
            }
        }
    }
}
