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

/**
 * A variant of {@link PCipher} which symmetrically encrypts data in fixed-size blocks.
 *
 * @author DaPorkchop_
 */
public interface PBlockCipher extends PCipher {
    /**
     * @return this cipher's block size (in bytes)
     */
    int blockSize();

    /**
     * Processes a single block.
     *
     * @param src the {@link ByteBuf} from which to read data. Must have at least {@link #blockSize()} bytes readable!
     * @param dst the {@link ByteBuf} to which to write data. Must have at least {@link #blockSize()} bytes writable!
     */
    void processBlock(@NonNull ByteBuf src, @NonNull ByteBuf dst);

    /**
     * Processes multiple blocks.
     * <p>
     * Both source and destination buffers must be identically sized, and be a multiple of {@link #blockSize()} bytes.
     *
     * @param src the {@link ByteBuf} from which to read data
     * @param dst the {@link ByteBuf} to which to write data
     */
    default void processBlocks(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        int blockSize = this.blockSize();
        if (src.readableBytes() != dst.writableBytes()) {
            throw new IllegalArgumentException("src and dst buffers must be identically sized!");
        } else if (src.readableBytes() % blockSize != 0 || dst.writableBytes() % blockSize != 0) {
            throw new IllegalArgumentException(String.format("src and dst buffers must be multiples of block size! (src=%d,dst=%d,block size=%d)", src.readableBytes(), dst.writableBytes(), blockSize));
        }
        for (int i = src.readableBytes() / blockSize - 1; i >= 0; i--) {
            this.processBlock(src, dst);
        }
    }
}
