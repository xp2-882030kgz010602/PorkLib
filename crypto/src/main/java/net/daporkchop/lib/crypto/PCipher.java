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

package net.daporkchop.lib.crypto;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import net.daporkchop.lib.math.primitive.PMath;
import net.daporkchop.lib.unsafe.capability.Releasable;

/**
 * A cipher can encrypt and decrypt data.
 * <p>
 * This is a basic representation of a cipher, intended to be used for both symmetric and asymmetric ciphers, with
 * and without padding. Consider using one of the sub-interfaces in order to obtain better performance when using
 * specific cipher types.
 *
 * @author DaPorkchop_
 */
public interface PCipher extends Releasable {
    //TODO: make IV configuration be a separate group of methods
    /**
     * Initializes this cipher with the given key.
     * <p>
     * Warning: If this cipher uses an IV, a default IV of 0 will be used!
     * <p>
     * This will reset src and dst buffers to {@code null}, so they will have to be set again after initialization.
     *
     * @param encrypt whether to initialize this cipher for encrypt mode (if {@code false}, it will be initialized in decrypt mode)
     * @param key     the key to use. The number of readable bytes must be exactly one of the key sizes supported by this cipher!
     * @see #init(boolean, ByteBuf, ByteBuf)
     */
    void init(boolean encrypt, @NonNull ByteBuf key);

    /**
     * Initializes this cipher with the given key and IV.
     * <p>
     * If this cipher does not use an IV, an {@link UnsupportedOperationException} will be thrown.
     * <p>
     * This will reset src and dst buffers to {@code null}, so they will have to be set again after initialization.
     *
     * @param encrypt whether to initialize this cipher for encrypt mode (if {@code false}, it will be initialized in decrypt mode)
     * @param key     the key to use. The number of readable bytes must be exactly one of the key sizes supported by this cipher!
     * @param iv      the IV to use. The number of readable bytes must be exactly {@link #ivSize()}!
     * @throws UnsupportedOperationException if this cipher does not use an IV
     * @see #init(boolean, ByteBuf)
     */
    void init(boolean encrypt, @NonNull ByteBuf key, @NonNull ByteBuf iv) throws UnsupportedOperationException;

    /**
     * Processes all of the given source data, start to finish and writes it to the given destination buffer.
     * <p>
     * This will also flush the internal buffer, if this cipher has one.
     * <p>
     * This may cause the destination buffer to be expanded indefinitely. Use with caution!
     *
     * @param src the {@link ByteBuf} to read data from
     * @param dst the {@link ByteBuf} to write processed data to
     */
    default void fullProcess(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        if (!src.isReadable()) return;
        dst.ensureWritable(this.roundUpToBlockSize(src.readableBytes() + this.bufferedCount()));

        this.process(src, dst);

        if (src.isReadable())   {
            throw new IllegalStateException("Didn't read all source data!");
        } else if (!dst.isWritable())   {
            throw new IllegalStateException("Ran out of space for destination data!");
        } else if (this.hasBuffer() && this.bufferedCount() > 0 && !this.flush(dst)) {
            throw new IllegalStateException("Unable to flush buffer!");
        }
    }

    /**
     * Processes as much data as possible.
     * <p>
     * This will continue reading, processing and writing data until the source buffer is emptied or the destination buffer
     * is filled.
     * <p>
     * Note that more data may be read than the amount written, in case this cipher internally buffers data and
     * does not have enough source data or destination space available.
     *
     * @param src the {@link ByteBuf} to read data from
     * @param dst the {@link ByteBuf} to write processed data to
     * @throws IllegalArgumentException if this cipher only accepts data in blocks, and there is an amount of data remaining in the source buffer that is not a multiple of {@link #blockSize()}
     */
    void process(@NonNull ByteBuf src, @NonNull ByteBuf dst) throws IllegalArgumentException;

    /**
     * Attempts to flush this cipher's internal buffer, possibly applying some kind of padding to the buffered data.
     * <p>
     * This will write data until the internal buffer has been flushed or the destination buffer is filled.
     * <p>
     * If this cipher does not have an internal buffer ({@link #hasBuffer()} is {@code false}), this method will do nothing
     * and will always return {@code true}.
     * <p>
     * If this cipher has an internal buffer, but the buffer is empty, this method will return {@code true}.
     *
     * @param dst the {@link ByteBuf} to write processed data to
     * @return whether or not the flush operation could be completed (if {@code false}, the destination buffer is too small)
     */
    boolean flush(@NonNull ByteBuf dst);

    //
    //
    // cipher attributes, these methods should return constant values
    //
    //

    /**
     * Gets this cipher's name.
     * <p>
     * Examples:
     * - {@code AES/CTR/NoPadding}
     * - {@code ChaCha20-Poly1305}
     *
     * @return the name of this cipher
     */
    String name();

    /**
     * @return whether or not this cipher internally buffers data
     */
    boolean hasBuffer();

    /**
     * @return the number of currently buffered bytes (always {@code 0} if this cipher does not have a buffer)
     */
    int bufferedCount();

    /**
     * @return the block size for this cipher, or {@code -1} if this cipher does not process data in blocks
     */
    int blockSize();

    /**
     * Checks whether or not this cipher processes data in blocks.
     * <p>
     * If this method returns {@code true}, it is guaranteed to also be an instance of {@link PBlockCipher}.
     *
     * @return whether or not this cipher processes data in blocks
     */
    default boolean usesBlocks() {
        return this.blockSize() != -1;
    }

    /**
     * Rounds the given value up to the next multiple of this cipher's block size.
     * <p>
     * If this cipher does not use blocks, it will always return the input value.
     *
     * @param value the value to start
     * @return the value rounded up to the next multiple of this cipher's block size
     */
    default int roundUpToBlockSize(int value) {
        int blockSize = this.blockSize();
        return blockSize == -1 ? value : PMath.roundUp(blockSize, value);
    }

    /**
     * @return the required size of an IV for this cipher, or {@code -1} if this cipher does not use an IV
     */
    default int ivSize() {
        return -1;
    }

    /**
     * @return whether or not this cipher uses an IV
     */
    default boolean ivRequired() {
        return this.ivSize() != -1;
    }

    /**
     * @return all key sizes supported by this cipher
     */
    int[] keySizes();

    /**
     * @return the best (most secure) key size supported by this cipher
     */
    default int bestKeySize() {
        int best = -1;
        for (int i : this.keySizes()) {
            if (i > best) {
                best = i;
            }
        }
        return best;
    }

    /**
     * Checks if the given key size is supported by this cipher.
     *
     * @param size the key size to check
     * @return whether or not this cipher supports the given key size
     */
    default boolean keySizeSupported(int size) {
        for (int i : this.keySizes()) {
            if (size == i) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether or not this {@link PCipher} uses direct memory internally.
     * <p>
     * Using the same kind of buffer that this {@link PCipher} uses internally can provide significant speedups.
     *
     * @return whether or not this {@link PCipher} uses direct memory internally
     */
    boolean direct();
}
