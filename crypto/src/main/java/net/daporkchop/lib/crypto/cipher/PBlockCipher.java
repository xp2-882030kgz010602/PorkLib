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

package net.daporkchop.lib.crypto.cipher;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import net.daporkchop.lib.crypto.alg.PBlockCipherAlg;
import net.daporkchop.lib.crypto.key.PKey;
import net.daporkchop.lib.math.primitive.PMath;

/**
 * A cipher which symmetrically encrypts data in fixed-size blocks.
 *
 * @author DaPorkchop_
 */
public interface PBlockCipher extends PCipher {
    @Override
    PBlockCipherAlg alg();

    @Override
    void init(boolean encrypt, @NonNull PKey key);

    /**
     * @return this cipher's block size (in bytes)
     */
    default int blockSize() {
        return this.alg().blockSize();
    }

    /**
     * Processes a single block.
     * <p>
     * If this implementation is also a {@link PStreamCipher}, using this method in combination with any of the following methods
     * may cause issues with padding:
     * - {@link PStreamCipher#process(ByteBuf, ByteBuf)}
     *
     * @param src the {@link ByteBuf} from which to read data. Must have at least {@link #blockSize()} bytes readable!
     * @param dst the {@link ByteBuf} to which to write data
     */
    void processBlock(@NonNull ByteBuf src, @NonNull ByteBuf dst);

    /**
     * Processes multiple blocks.
     * <p>
     * Source buffer must be a multiple of {@link #blockSize()} bytes.
     * <p>
     * If this implementation is also a {@link PStreamCipher}, using this method in combination with any of the following methods
     * may cause issues with padding:
     * - {@link PStreamCipher#process(ByteBuf, ByteBuf)}
     *
     * @param src the {@link ByteBuf} from which to read data
     * @param dst the {@link ByteBuf} to which to write data
     */
    default void processBlocks(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        int blockSize = this.blockSize();
        if (src.readableBytes() % blockSize != 0) {
            throw new IllegalArgumentException(String.format("src buffers must be a multiple of block size! (src=%d,block size=%d)", src.readableBytes(), blockSize));
        }
        dst.ensureWritable(src.readableBytes());
        for (int i = src.readableBytes() / blockSize - 1; i >= 0; i--) {
            this.processBlock(src, dst);
        }
    }

    @Override
    default long processedSize(long inputSize) {
        return PMath.roundUp(inputSize, this.blockSize());
    }
}
