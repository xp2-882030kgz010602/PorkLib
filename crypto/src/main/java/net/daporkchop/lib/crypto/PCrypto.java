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

package net.daporkchop.lib.crypto;

import lombok.NonNull;
import lombok.experimental.UtilityClass;
import net.daporkchop.lib.crypto.alg.PCipherAlg;
import net.daporkchop.lib.crypto.alg.PCryptAlg;
import net.daporkchop.lib.crypto.alg.PCryptProvider;
import net.daporkchop.lib.crypto.cipher.PCipher;
import net.daporkchop.lib.crypto.impl.bc.BouncyCastleCryptProvider;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;

/**
 * Base class for accessing ciphers and other things provided by PorkLib crypto.
 * <p>
 * Using this allows selecting the best implementation of an algorithm based on the system at runtime.
 *
 * @author DaPorkchop_
 */
@UtilityClass
public class PCrypto {
    protected final PCryptProvider[] PROVIDERS = {
            BouncyCastleCryptProvider.INSTANCE
    };

    protected final Map<String, PCryptAlg> LOOKUP_CACHE = new HashMap<>();
    protected final ReadWriteLock LOOKUP_LOCK = new ReentrantReadWriteLock();

    protected final Function<String, PCryptAlg> LOOKUP_FUNCTION = name -> {
        for (PCryptProvider provider : PROVIDERS)   {
            try {
                return provider.get(name);
            } catch (IllegalArgumentException e)    {
                //ignore and continue to next provider
            }
        }
        //if no provider supports the given algorithm, fail
        throw new IllegalArgumentException(name);
    };

    /**
     * Creates a new cipher with the given name.
     *
     * @param name the name of the cipher
     * @return a new cipher with the given name
     * @throws IllegalArgumentException if no cipher algorithm could be found with the given name, or if the given algorithm does not support creation of ciphers
     */
    public PCipher cipher(@NonNull String name) throws IllegalArgumentException {
        PCryptAlg alg = getAlg(name);
        if (alg instanceof PCipherAlg)  {
            return ((PCipherAlg) alg).cipher();
        } else {
            throw new IllegalArgumentException(String.format("Algorithm \"%s\" cannot create a cipher!", name));
        }
    }

    protected PCryptAlg getAlg(@NonNull String name) throws IllegalArgumentException    {
        LOOKUP_LOCK.readLock().lock();
        try {
            PCryptAlg alg = LOOKUP_CACHE.get(name);
            if (alg != null) {
                return alg;
            }
        } finally {
            LOOKUP_LOCK.readLock().unlock();
        }

        //alg does not exist, create it
        LOOKUP_LOCK.writeLock().lock();
        try {
            return LOOKUP_CACHE.computeIfAbsent(name, LOOKUP_FUNCTION);
        } finally {
            LOOKUP_LOCK.writeLock().unlock();
        }
    }
}
