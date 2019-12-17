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
import net.daporkchop.lib.crypto.alg.PCryptAlg;
import net.daporkchop.lib.crypto.key.PKey;

/**
 * A symmetric cipher which encrypts data as a stream, allowing arbitrarily sized data to be encrypted without requiring
 * padding.
 *
 * @author DaPorkchop_
 */
public interface PStreamCipher extends PCipher {
    @Override
    PCryptAlg alg();

    @Override
    void init(boolean encrypt, @NonNull PKey key);

    /**
     * Processes the given data.
     * <p>
     * If an implementation is also a {@link PBlockCipher}, using this method in combination with any of the following methods
     * may cause issues with padding:
     * - {@link PBlockCipher#processBlock(ByteBuf, ByteBuf)}
     * - {@link PBlockCipher#processBlocks(ByteBuf, ByteBuf)}
     * - {@link PBlockCipher#processBlocks(ByteBuf, ByteBuf, int)}
     *
     * @param src the {@link ByteBuf} containing the data to be processed
     * @param dst the {@link ByteBuf} that the data should be written to. Must have at least as many bytes writable as the
     *            source buffer has readable!
     */
    default void process(@NonNull ByteBuf src, @NonNull ByteBuf dst)    {
        this.process(src, dst, src.readableBytes());
    }

    /**
     * Processes the given data.
     * <p>
     * If an implementation is also a {@link PBlockCipher}, using this method in combination with any of the following methods
     * may cause issues with padding:
     * - {@link PBlockCipher#processBlock(ByteBuf, ByteBuf)}
     * - {@link PBlockCipher#processBlocks(ByteBuf, ByteBuf)}
     * - {@link PBlockCipher#processBlocks(ByteBuf, ByteBuf, int)}
     *
     * @param src the {@link ByteBuf} containing the data to be processed Must have at least {@code size} bytes readable!
     * @param dst the {@link ByteBuf} that the data should be written to
     *            @param size the number of bytes to process
     */
    void process(@NonNull ByteBuf src, @NonNull ByteBuf dst, int size);

    @Override
    default long processedSize(long inputSize) {
        return inputSize; //stream ciphers can always encrypt exactly the amount required
    }
}
