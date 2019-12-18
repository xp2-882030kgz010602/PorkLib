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
import net.daporkchop.lib.crypto.alg.PCryptAlg;

/**
 * A symmetric cipher which allows random access.
 * <p>
 * Encryption and decryption may be moved to any position without having to reset the cipher, and the encryption/decryption
 * will proceed from there.
 *
 * @author DaPorkchop_
 */
public interface PSeekableCipher extends PStreamCipher {
    @Override
    PCryptAlg alg();

    /**
     * Seeks to the given byte position.
     * <p>
     * The next encryption/decryption operation will proceed from the given position.
     * <p>
     * If an implementation is also a {@link PBlockCipher}, using this method in combination with any of the following methods
     * without the new position being a multiple of the block size may cause issues with padding:
     * - {@link PBlockCipher#processBlock(ByteBuf, ByteBuf)}
     * - {@link PBlockCipher#processBlocks(ByteBuf, ByteBuf)}
     * - {@link PBlockCipher#processBlocks(ByteBuf, ByteBuf, int)}
     *
     * @param position the new byte position to seek to
     */
    void seek(long position);

    /**
     * Resets the cipher to its original position.
     * <p>
     * Equivalent to calling {@link #seek(long)} with {@code 0L}.
     */
    default void reset() {
        this.seek(0L);
    }

    /**
     * @return the cipher's current byte position
     */
    long position();
}
