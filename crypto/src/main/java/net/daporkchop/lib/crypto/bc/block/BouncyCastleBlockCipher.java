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

package net.daporkchop.lib.crypto.bc.block;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import net.daporkchop.lib.crypto.PBlockCipher;
import net.daporkchop.lib.crypto.bc.BouncyCastleCipher;
import net.daporkchop.lib.unsafe.PUnsafe;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Base interface for implementations of {@link PBlockCipher} based on a BouncyCastle block cipher.
 *
 * @author DaPorkchop_
 */
public interface BouncyCastleBlockCipher extends BlockCipher, BouncyCastleCipher, PBlockCipher {
    long KEYPARAMETER_KEY_OFFSET = PUnsafe.pork_getOffset(KeyParameter.class, "key");
    long PARAMETERSWITHIV_IV_OFFSET = PUnsafe.pork_getOffset(ParametersWithIV.class, "iv");

    /**
     * @return a {@code byte[]} the same size as this cipher's block size, to be used as a temporary buffer when using direct buffers
     */
    @Override
    byte[] globalBuffer();

    @Override
    default void init(boolean encrypt, @NonNull ByteBuf key, @NonNull ByteBuf iv) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(this.name() + " cannot use an IV!");
    }

    @Override
    default void process(@NonNull ByteBuf src, @NonNull ByteBuf dst) throws IllegalArgumentException {
        int blockSize = this.blockSize();

        int srcReadable = src.readableBytes();
        int dstWritable = dst.writableBytes();

        if (srcReadable % blockSize != 0) {
            throw new IllegalArgumentException(String.format("%s requires data to be a multiple of %d bytes (readable: %d)", this.name(), blockSize, srcReadable));
        } else if (srcReadable == 0 || dstWritable < srcReadable) {
            return;
        }

        final byte[] globalBuffer = this.globalBuffer();

        final byte[] srcArray;
        int srcArrayOffset;
        if (src.hasArray()) {
            srcArray = src.array();
            srcArrayOffset = src.arrayOffset() + src.readerIndex() - blockSize;
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

        for (int i = srcReadable / blockSize - 1; i >= 0 && srcReadable != 0 && dstWritable >= srcReadable; i--, srcReadable = src.readableBytes(), dstWritable = dst.writableBytes()) {
            if (srcArray == globalBuffer) {
                //copy source data into array if it's a native buffer
                src.readBytes(srcArray, 0, blockSize);
            } else {
                src.skipBytes(blockSize);
                srcArrayOffset += blockSize;
            }

            this.processBlock(srcArray, srcArrayOffset, dstArray, dstArrayOffset);

            if (dstArray == globalBuffer) {
                //copy processed data out of array if it's a native buffer
                dst.writeBytes(dstArray, 0, blockSize);
            } else {
                dst.writerIndex(dst.writerIndex() + blockSize);
                dstArrayOffset += blockSize;
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
            src.skipBytes(blockSize);
        } else {
            src.readBytes(srcArray = globalBuffer, srcArrayOffset = 0, blockSize);
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

        this.processBlock(srcArray, srcArrayOffset, dstArray, dstArrayOffset);

        if (dstArray == globalBuffer) {
            dst.writeBytes(dstArray, 0, blockSize);
        } else {
            dst.writerIndex(dst.writerIndex() + blockSize);
        }
    }
}
