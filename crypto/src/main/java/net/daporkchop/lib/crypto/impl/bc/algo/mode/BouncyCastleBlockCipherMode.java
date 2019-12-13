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

package net.daporkchop.lib.crypto.impl.bc.algo.mode;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import net.daporkchop.lib.crypto.alg.PBlockCipherAlg;
import net.daporkchop.lib.crypto.alg.PBlockCipherMode;
import net.daporkchop.lib.crypto.key.PKey;
import net.daporkchop.lib.crypto.key.PKeyGenerator;
import net.daporkchop.lib.unsafe.PUnsafe;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Random;

/**
 * Abstract implementation of {@link PBlockCipherMode} for the BouncyCastle API.
 *
 * @author DaPorkchop_
 */
@RequiredArgsConstructor
@Getter
@Accessors(fluent = true)
public abstract class BouncyCastleBlockCipherMode implements PBlockCipherMode {
    @NonNull
    protected final PBlockCipherAlg delegate;

    protected int ivSize() {
        return this.blockSize();
    }

    @Override
    public PKeyGenerator keyGen() {
        return new KeyGen(this, this.delegate.keyGen(), this.ivSize());
    }

    @Override
    public PKey decodeKey(int size, @NonNull ByteBuf src) {
        byte[] iv = new byte[this.ivSize()];
        src.readBytes(iv);
        return PUnsafe.allocateInstance(WrappedIVKey.class).set(iv, this.delegate.decodeKey(size, src));
    }

    @RequiredArgsConstructor
    @Accessors(fluent = true)
    public static class KeyGen implements PKeyGenerator {
        @Getter
        @NonNull
        protected final BouncyCastleBlockCipherMode alg;
        @NonNull
        protected final PKeyGenerator delegate;
        protected final int ivSize;

        @Override
        public int size() {
            return this.delegate.size();
        }

        @Override
        public PKeyGenerator size(int size) {
            this.delegate.size(size);
            return this;
        }

        @Override
        public PKey generate(@NonNull Random random) {
            byte[] iv = new byte[this.ivSize];
            random.nextBytes(iv);
            return PUnsafe.allocateInstance(WrappedIVKey.class).set(iv, this.delegate.generate(random));
        }
    }

    public static class WrappedIVKey extends ParametersWithIV implements PKey {
        protected static final long IV_OFFSET = PUnsafe.pork_getOffset(ParametersWithIV.class, "iv");
        protected static final long PARAMETERS_OFFSET = PUnsafe.pork_getOffset(ParametersWithIV.class, "parameters");

        public WrappedIVKey(CipherParameters parameters, byte[] iv) {
            super(parameters, iv);
            throw new IllegalStateException();
        }

        public WrappedIVKey set(@NonNull byte[] iv, @NonNull Object parameters) {
            PUnsafe.putObject(this, IV_OFFSET, iv);
            PUnsafe.putObject(this, PARAMETERS_OFFSET, parameters);
            return this;
        }

        @Override
        public int encodedSize() {
            return ((PKey) this.getParameters()).encodedSize() + this.getIV().length;
        }

        @Override
        public ByteBuf encoded() {
            return Unpooled.wrappedUnmodifiableBuffer(Unpooled.wrappedBuffer(this.getIV()), ((PKey) this.getParameters()).encoded()).asReadOnly();
        }
    }
}
