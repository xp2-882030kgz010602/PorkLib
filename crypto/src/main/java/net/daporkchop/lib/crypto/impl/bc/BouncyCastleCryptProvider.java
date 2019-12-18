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

package net.daporkchop.lib.crypto.impl.bc;

import lombok.NonNull;
import net.daporkchop.lib.crypto.alg.PCryptAlg;
import net.daporkchop.lib.crypto.alg.PCryptProvider;
import net.daporkchop.lib.crypto.impl.bc.algo.block.BouncyCastleAES;
import net.daporkchop.lib.crypto.impl.bc.algo.mode.BouncyCastleCTR;
import net.daporkchop.lib.crypto.impl.bc.cipher.block.BouncyCastleCipherAES;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Implementation of {@link PCryptProvider} for the BouncyCastle crypto suite.
 *
 * @author DaPorkchop_
 */
public final class BouncyCastleCryptProvider implements PCryptProvider {
    public static final BouncyCastleCryptProvider INSTANCE = new BouncyCastleCryptProvider();

    protected static final String[] BLOCK_CIPHERS = { "AES" };
    protected static final String[] BLOCK_CIPHER_MODES = { "CTR" };
    protected static final String[] BLOCK_CIPHER_PADDINGS = { };

    protected final Map<String, Supplier<PCryptAlg>> algFactories = new HashMap<>();
    protected final Map<String, PCryptAlg> algorithms = new HashMap<>();
    protected final Collection<String> names;
    protected final ReadWriteLock lock = new ReentrantReadWriteLock();
    protected final Function<String, PCryptAlg> lookerUpper = name -> {
        Supplier<PCryptAlg> factory = this.algFactories.remove(name);
        if (factory == null)    {
            throw new IllegalArgumentException(name);
        }
        PCryptAlg alg = factory.get();
        if (alg == null)    {
            throw new IllegalArgumentException(name);
        }
        return alg;
    };

    private BouncyCastleCryptProvider() {
        this.algFactories.put("AES", () -> BouncyCastleAES.INSTANCE);
        this.algFactories.put("AES/CTR", () -> new BouncyCastleCTR(BouncyCastleAES.INSTANCE));

        this.names = Collections.unmodifiableList(new ArrayList<>(this.algFactories.keySet()));
    }

    @Override
    public PCryptAlg get(@NonNull String name) throws IllegalArgumentException {
        this.lock.readLock().lock();
        try {
            PCryptAlg alg = this.algorithms.get(name);
            if (alg != null)    {
                return alg;
            }
        } finally {
            this.lock.readLock().unlock();
        }

        //run factory and store it
        this.lock.writeLock().lock();
        try {
            return this.algorithms.computeIfAbsent(name, this.lookerUpper);
        } finally {
            this.lock.writeLock().unlock();
        }
    }

    @Override
    public Collection<String> supportedAlgorithms() {
        return Collections.unmodifiableSet(this.algFactories.keySet());
    }
}
