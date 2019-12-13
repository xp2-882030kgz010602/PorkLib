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

package net.daporkchop.lib.crypto.impl.bc.algo;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import net.daporkchop.lib.crypto.alg.PBlockCipherAlg;
import net.daporkchop.lib.crypto.alg.PCryptAlg;
import net.daporkchop.lib.crypto.cipher.PBlockCipher;
import net.daporkchop.lib.crypto.impl.bc.cipher.BouncyCastleCipherAES;
import net.daporkchop.lib.crypto.key.PKey;
import net.daporkchop.lib.crypto.key.PKeyGenerator;
import net.daporkchop.lib.unsafe.PUnsafe;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Random;

/**
 * Implementation of {@link PBlockCipherAlg} for BouncyCastle AES.
 *
 * @author DaPorkchop_
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class BouncyCastleAES implements PBlockCipherAlg {
    public static final BouncyCastleAES INSTANCE = new BouncyCastleAES();

    protected static final int[] AES_KEY_SIZES = {128 >>> 3, 192 >>> 3, 256 >>> 3};

    protected static void assertValidKeySize(int size) {
        if (size != (128 >>> 3) && size != (192 >>> 3) && size != (256 >>> 3)) {
            throw new IllegalArgumentException(String.valueOf(size));
        }
    }

    @Override
    public PBlockCipher cipher() {
        return new BouncyCastleCipherAES();
    }

    @Override
    public int blockSize() {
        return 128 >>> 3;
    }

    @Override
    public String name() {
        return "AES";
    }

    @Override
    public PKeyGenerator keyGen() {
        return new KeyGen();
    }

    @Override
    public PKey decodeKey(int size, @NonNull ByteBuf src) {
        assertValidKeySize(size);
        byte[] key = new byte[size];
        src.readBytes(key);
        return PUnsafe.allocateInstance(Key.class).setKey(key);
    }

    @Override
    public int[] keySizes() {
        return AES_KEY_SIZES.clone();
    }

    @Getter
    @Accessors(fluent = true)
    public static final class KeyGen implements PKeyGenerator {
        protected int size = 128 >>> 3;

        @Override
        public PCryptAlg alg() {
            return BouncyCastleAES.INSTANCE;
        }

        @Override
        public PKeyGenerator size(int size) {
            assertValidKeySize(size);
            this.size = size;
            return this;
        }

        @Override
        public PKey generate(@NonNull Random random) {
            byte[] key = new byte[this.size];
            random.nextBytes(key);
            return PUnsafe.allocateInstance(Key.class).setKey(key);
        }
    }

    public static final class Key extends KeyParameter implements PKey {
        private static final long KEY_OFFSET = PUnsafe.pork_getOffset(KeyParameter.class, "key");

        public Key(byte[] key) {
            super(key);
            throw new IllegalStateException();
        }

        protected Key setKey(@NonNull byte[] key) {
            assertValidKeySize(key.length);
            PUnsafe.putObject(this, KEY_OFFSET, key);
            return this;
        }

        @Override
        public int encodedSize() {
            return this.getKey().length;
        }

        @Override
        public ByteBuf encoded() {
            return Unpooled.wrappedBuffer(this.getKey()).asReadOnly();
        }
    }
}
