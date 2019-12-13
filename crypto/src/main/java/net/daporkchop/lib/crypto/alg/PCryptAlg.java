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

package net.daporkchop.lib.crypto.alg;

import net.daporkchop.lib.crypto.cipher.PCipher;
import net.daporkchop.lib.crypto.key.PKeyGenerator;

/**
 * Representation of a cryptographic algorithm.
 * <p>
 * This may be a full cipher configuration, or only a component (e.g. a block cipher padding mode).
 *
 * @author DaPorkchop_
 * @see PBlockCipherAlg
 */
public interface PCryptAlg {
    /**
     * Gets this algorithm's textual name.
     * <p>
     * Examples:
     * - {@code AES/CTR/NoPadding}
     * - {@code AES}
     * - {@code NoPadding}
     *
     * @return this algorithm's textual name
     */
    String name();

    /**
     * @return a new {@link PCipher} capable of encrypting/decrypting data with this algorithm
     */
    PCipher cipher();

    /**
     * @return a {@link PKeyGenerator} which can generate {@link net.daporkchop.lib.crypto.key.PKey}s suitable for use with this algorithm
     */
    PKeyGenerator keyGen();

    /**
     * @return all key sizes allowed by this generator (in bytes)
     */
    int[] keySizes();
}
