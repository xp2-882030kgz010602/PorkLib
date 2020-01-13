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

package net.daporkchop.lib.crypto.generic.block;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import net.daporkchop.lib.common.util.PorkUtil;
import net.daporkchop.lib.crypto.cipher.block.PBlockCipher;
import net.daporkchop.lib.crypto.generic.ISimpleHeapCipher;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;

/**
 * A base implementation of a simple {@link PBlockCipher} backed by heap memory.
 *
 * @author DaPorkchop_
 */
public interface ISimpleHeapBlockCipher extends PBlockCipher, ISimpleHeapCipher {
    /**
     * Process one block of input from the array in and write it to the out array.
     *
     * @param in     the array containing the input data
     * @param inOff  offset into the in array the data starts at
     * @param out    the array the output data will be copied into
     * @param outOff the offset into the out array the output will start at
     */
    void processHeapBlock(byte[] in, int inOff, byte[] out, int outOff);

    /**
     * Process a given number of blocks of input from the array in and write them to the out array.
     *
     * @param in     the array containing the input data
     * @param inOff  offset into the in array the data starts at
     * @param out    the array the output data will be copied into
     * @param outOff the offset into the out array the output will start at
     * @param blocks the number of blocks to process
     */
    default void processHeapBlocks(byte[] in, int inOff, byte[] out, int outOff, int blocks)    {
        if (blocks < 0) {
            throw new IllegalArgumentException(String.valueOf(blocks));
        } else if (blocks == 0) {
            return;
        } else {
            final int blockSize = this.blockSize();
            PorkUtil.assertInRangeLen(in.length, inOff, blocks * blockSize);
            PorkUtil.assertInRangeLen(out.length, outOff, blocks * blockSize);
            for (int i = 0; i < blocks; i++, inOff += blockSize, outOff += blockSize)    {
                this.processHeapBlock(in, inOff, out, outOff);
            }
        }
    }

    @Override
    default void processBlock(@NonNull ByteBuf src, @NonNull ByteBuf dst) throws IllegalArgumentException {
        final int blockSize = this.blockSize();

        if (src.readableBytes() < blockSize || dst.writableBytes() < blockSize) {
            throw new IllegalArgumentException(String.format("Must have at least %d bytes available in both src and dst buffers! (src: %d, dst: %d)", blockSize, src.readableBytes(), dst.writableBytes()));
        }

        final byte[] globalBuffer = this.globalBuffer();

        byte[] srcArray;
        int srcArrayOffset;
        if (src.hasArray()) {
            srcArray = src.array();
            srcArrayOffset = src.arrayOffset() + src.readerIndex();
        } else {
            srcArray = globalBuffer;
            srcArrayOffset = 0;
        }

        byte[] dstArray;
        int dstArrayOffset;
        if (dst.hasArray()) {
            dstArray = dst.array();
            dstArrayOffset = dst.arrayOffset() + dst.writerIndex();
        } else {
            dstArray = globalBuffer;
            dstArrayOffset = 0;
        }

        this.processHeapBlock(srcArray, srcArrayOffset, dstArray, dstArrayOffset);

        if (dstArray == globalBuffer) {
            dst.writeBytes(dstArray, 0, blockSize);
        } else {
            dst.writerIndex(dst.writerIndex() + blockSize);
        }
    }

    @Override
    default void processBlocks(@NonNull ByteBuf src, @NonNull ByteBuf dst, int blocks) throws IllegalArgumentException {
        final int blockSize = this.blockSize();

        if (blocks < 0) {
            throw new IllegalArgumentException(String.valueOf(blocks));
        } else if (blocks == 0) {
            return;
        } else if (src.readableBytes() < blocks * blockSize || dst.writableBytes() < blocks * blockSize) {
            throw new IllegalArgumentException(String.format("Must have at least %d bytes (for %d blocks @ %d bytes each) available in both src and dst buffers! (src: %d, dst: %d)", blocks * blockSize, blocks, blockSize, src.readableBytes(), dst.writableBytes()));
        }

        final byte[] globalBuffer = this.globalBuffer();

        byte[] srcArray;
        int srcArrayOffset;
        if (src.hasArray()) {
            srcArray = src.array();
            srcArrayOffset = src.arrayOffset() + src.readerIndex();
        } else {
            srcArray = globalBuffer;
            srcArrayOffset = 0;
        }

        byte[] dstArray;
        int dstArrayOffset;
        if (dst.hasArray()) {
            dstArray = dst.array();
            dstArrayOffset = dst.arrayOffset() + dst.writerIndex();
        } else {
            dstArray = globalBuffer;
            dstArrayOffset = 0;
        }

        if (srcArray != globalBuffer && dstArray != globalBuffer)   {
            //neither buffer is direct, we can do everything in one go on heap
            this.processHeapBlocks(srcArray, srcArrayOffset, dstArray, dstArrayOffset, blocks);
        }
        for (int i = 0; i < blocks; i++) {
            if (srcArray == globalBuffer) {
                src.readBytes(globalBuffer);
            } else {
                src.skipBytes(blockSize);
            }

            this.processHeapBlock(srcArray, srcArrayOffset, dstArray, dstArrayOffset);

            if (srcArray != globalBuffer) {
                srcArrayOffset += blockSize;
            }
            if (dstArray == globalBuffer) {
                dst.writeBytes(dstArray);
            } else {
                dst.writerIndex(dst.writerIndex() + blockSize);
                dstArrayOffset += blockSize;
            }
        }
    }

    @Override
    default void release() throws AlreadyReleasedException {
        //no-op
    }

    @Override
    default boolean direct() {
        return false;
    }
}
