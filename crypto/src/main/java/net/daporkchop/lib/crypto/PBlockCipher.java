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

/**
 * An extension of {@link PCipher} that provides symmetric encryption of data in fixed-size blocks.
 *
 * @author DaPorkchop_
 */
public interface PBlockCipher extends PCipher {
    /**
     * Processes a single block.
     * <p>
     * This will read, process and write exactly one block, failing if the source buffer does not have enough data readable or
     * the destination buffer does not have enough space available.
     *
     * @param src the {@link ByteBuf} to read the block from
     * @param dst the {@link ByteBuf} to write the processed block to
     * @throws IllegalArgumentException if the source buffer does not have enough data readable or the destination buffer does not have enough space available
     */
    void processBlock(@NonNull ByteBuf src, @NonNull ByteBuf dst) throws IllegalArgumentException;

    /**
     * Processes a number of blocks.
     * <p>
     * This will read, process and write the given number of blocks, failing if the source buffer does not have enough data
     * readable or the destination buffer does not have enough space available.
     *
     * @param src    the {@link ByteBuf} to read the block from
     * @param dst    the {@link ByteBuf} to write the processed block to
     * @param blocks the number of blocks to process
     * @throws IllegalArgumentException if the source buffer does not have enough data readable or the destination buffer does not have enough space available
     */
    void processBlocks(@NonNull ByteBuf src, @NonNull ByteBuf dst, int blocks) throws IllegalArgumentException;

    @Override
    default boolean usesBlocks() {
        return true;
    }
}
