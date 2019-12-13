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

package net.daporkchop.lib.crypto.key;

import lombok.NonNull;
import net.daporkchop.lib.crypto.alg.PCryptAlg;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Generates keys.
 *
 * @author DaPorkchop_
 */
public interface PKeyGenerator {
    /**
     * @return the {@link PCryptAlg} which this generator generates key for
     */
    PCryptAlg alg();

    /**
     * @return the currently configured key size
     */
    int size();

    /**
     * Sets the size of the keys created by this generator.
     *
     * @param size the new key size
     * @return this {@link PKeyGenerator} instance
     */
    PKeyGenerator size(int size);

    /**
     * @see #generate(Random)
     */
    default PKey generate() {
        return this.generate(ThreadLocalRandom.current());
    }

    /**
     * Generates a new key using the given {@link Random} instance as a source.
     *
     * @param random the {@link Random} instance to use for generating the key
     * @return a newly generated {@link PKey}
     */
    PKey generate(@NonNull Random random);
}
