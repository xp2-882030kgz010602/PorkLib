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
            src.skipBytes(blockSize);
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

        if (dst.hasArray()) {
            //increase writer index
            dst.writerIndex(dst.writerIndex() + blockSize);
        } else {
            //copy encrypted bytes into destination buffer
            dst.writeBytes(dstArray, dstArrayOffset, blockSize);
        }
    }
}
