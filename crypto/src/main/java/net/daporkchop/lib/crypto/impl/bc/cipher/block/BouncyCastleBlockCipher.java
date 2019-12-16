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

package net.daporkchop.lib.crypto.impl.bc.cipher.block;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.Accessors;
import net.daporkchop.lib.common.util.GenericMatcher;
import net.daporkchop.lib.crypto.cipher.PBlockCipher;
import net.daporkchop.lib.crypto.key.PKey;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Base implementation of {@link PBlockCipher} for all BouncyCastle-based block ciphers.
 *
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public abstract class BouncyCastleBlockCipher<B extends BlockCipher, K extends PKey & CipherParameters> implements IBouncyCastleBlockCipher {
    @Getter
    protected final B engine;
    @Getter
    protected final byte[] buffer;
    protected final Class<K> keyClass;

    @Getter
    protected final int blockSize;

    public BouncyCastleBlockCipher(@NonNull B engine) {
        this.engine = engine;
        this.buffer = new byte[(this.blockSize = engine.getBlockSize()) * 2];

        this.keyClass = GenericMatcher.uncheckedFind(this.getClass(), BouncyCastleBlockCipher.class, "K");
    }

    @Override
    @SuppressWarnings("unchecked")
    public void init(boolean encrypt, @NonNull PKey key) {
        if (key.getClass() == this.keyClass) {
            this.engine.init(encrypt, (K) key);
        } else {
            throw new IllegalArgumentException(String.format("Invalid key type \"%s\", expected \"%s\"!", key.getClass().getCanonicalName(), this.keyClass.getCanonicalName()));
        }
    }

    @Override
    public void release() throws AlreadyReleasedException {
        //no-op
    }
}
