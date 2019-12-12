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

import net.daporkchop.lib.crypto.PCrypto;
import net.daporkchop.lib.unsafe.capability.Releasable;

/**
 * Base representation of a cipher.
 * <p>
 * Implementations are not expected to be thread-safe, and may produce unexpected behavior if used from multiple threads.
 *
 * @author DaPorkchop_
 */
public interface PCipher extends Releasable {
    /**
     * @return the algorithm that this cipher is implementing
     */
    PCrypto alg();

    /**
     * Calculates the data size produced by this cipher if provided with the given number of input bytes.
     * <p>
     * Note that the values returned by this method are a maximum, in practice the processed size may be smaller than
     * reported by this method.
     * <p>
     * The cipher must be initialized before using this method.
     *
     * @param inputSize the size of the input data, in bytes
     * @return the maximum size of the output data, in bytes
     */
    long processedSize(long inputSize);
}
