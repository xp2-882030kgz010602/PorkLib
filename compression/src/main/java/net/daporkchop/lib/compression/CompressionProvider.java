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

package net.daporkchop.lib.compression;

import net.daporkchop.lib.common.util.PValidation;
import net.daporkchop.lib.common.util.exception.ValueCannotFitException;
import net.daporkchop.lib.compression.util.exception.InvalidCompressionLevelException;
import net.daporkchop.lib.natives.util.BufferTyped;

/**
 * An implementation of a compression algorithm.
 *
 * @author DaPorkchop_
 */
public interface CompressionProvider extends BufferTyped {
    @Override
    boolean directAccepted();

    /**
     * @return the compression level with the worst compression ratio in exchange for the shortest compression times
     */
    int levelFast();

    /**
     * @return the compression level used by default
     */
    int levelDefault();

    /**
     * @return the compression level with the best compression ratio in exchange for the longest compression times
     */
    int levelBest();

    /**
     * @see #compressBoundLong(long)
     * @throws ValueCannotFitException if the returned value is too large to fit in an {@code int}
     */
    default int compressBound(int srcSize) throws ValueCannotFitException {
        return PValidation.toInt(this.compressBoundLong(srcSize));
    }

    /**
     * Gets the maximum (worst-case) compressed size for input data of the given length.
     *
     * @param srcSize the size (in bytes) of the source data
     * @return the worst-case size of the compressed data
     */
    long compressBoundLong(long srcSize);
}