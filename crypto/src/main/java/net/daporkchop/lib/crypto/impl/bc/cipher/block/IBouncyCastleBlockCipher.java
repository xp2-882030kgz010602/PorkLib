/*
 * Adapted from the Wizardry License
 *
 * Copyright (c) 2018-2019 DaPorkchop_ and contributors
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

package net.daporkchop.lib.crypto.impl.bc.cipher.block;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import net.daporkchop.lib.crypto.cipher.PBlockCipher;
import net.daporkchop.lib.crypto.impl.bc.cipher.BouncyCastleCipher;
import org.bouncycastle.crypto.BlockCipher;

/**
 * Handles actual block encryption for a {@link PBlockCipher} backed by a BouncyCastle {@link BlockCipher}.
 *
 * @author DaPorkchop_
 */
public interface IBouncyCastleBlockCipher extends PBlockCipher, BouncyCastleCipher {
    /**
     * @return a {@code byte[]} which is exactly 2x this cipher's block size
     */
    byte[] buffer();

    /**
     * @return the underlying {@link BlockCipher} implementation
     */
    BlockCipher engine();

    @Override
    default void processBlock(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        final int blockSize = this.blockSize();
        if (src.readableBytes() < blockSize) {
            throw new IllegalArgumentException(String.format("Source buffer only has %d bytes readable (required: %d)", src.readableBytes(), 128 >>> 3));
        }
        dst.ensureWritable(blockSize);

        byte[] srcArray;
        int srcArrayOffset;
        if (src.hasArray()) {
            srcArray = src.array();
            srcArrayOffset = src.arrayOffset() + src.readerIndex();
        } else {
            src.readBytes(srcArray = this.buffer(), srcArrayOffset = 0, blockSize);
        }

        byte[] dstArray;
        int dstArrayOffset;
        if (dst.hasArray()) {
            dstArray = dst.array();
            dstArrayOffset = dst.arrayOffset() + dst.writerIndex();
        } else {
            dstArray = this.buffer();
            dstArrayOffset = blockSize;
        }

        this.engine().processBlock(srcArray, srcArrayOffset, dstArray, dstArrayOffset);

        if (src.hasArray()) {
            //increase reader index
            src.skipBytes(blockSize);
        }

        if (dst.hasArray()) {
            //increase writer index
            dst.writerIndex(dst.writerIndex() + blockSize);
        } else {
            //copy encrypted bytes into destination buffer
            dst.writeBytes(dstArray, dstArrayOffset, blockSize);
        }
    }

    @Override
    default void processBlocks(@NonNull ByteBuf src, @NonNull ByteBuf dst, int blocks) {
        if (blocks < 0) {
            throw new IllegalArgumentException(String.valueOf(blocks));
        } else if (blocks > 0) {
            int blockSize = this.blockSize();
            if ((long) src.readableBytes() < (long) blocks * (long) blockSize) {
                throw new IllegalArgumentException(String.format("Not enough data to process %d blocks @ %d bytes (src=%d, needed=%d)", blocks, blockSize, src.readableBytes(), (long) blocks * (long) blockSize));
            }
            int dataSize = blocks * blockSize; //blocks * blockSize can never be larger than Integer.MAX_VALUE any more
            dst.ensureWritable(dataSize);

            if (src.hasArray() && dst.hasArray())   {
                //we can only do this if both src and dst have an array, otherwise the buffer is useless

                byte[] srcArray = src.array();
                int srcArrayOffset = src.arrayOffset() + src.readerIndex();

                byte[] dstArray = dst.array();
                int dstArrayOffset = dst.arrayOffset() + dst.writerIndex();

                BlockCipher engine = this.engine();
                while (--blocks >= 0)   {
                    engine.processBlock(srcArray, srcArrayOffset, dstArray, dstArrayOffset);
                    srcArrayOffset += blockSize;
                    dstArrayOffset += blockSize;
                }

                //increase reader+writer indices
                src.skipBytes(dataSize);
                dst.writerIndex(dst.writerIndex() + blockSize);
            } else {
                //if either one is direct we have to go the slow way
                while (--blocks >= 0)    {
                    this.processBlock(src, dst);
                }
            }
        }
    }
}
