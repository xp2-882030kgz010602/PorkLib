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

package net.daporkchop.lib.crypto.impl.bc.cipher.mode;

import io.netty.buffer.ByteBuf;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.Accessors;
import net.daporkchop.lib.crypto.alg.PBlockCipherAlg;
import net.daporkchop.lib.crypto.cipher.PBlockCipher;
import net.daporkchop.lib.crypto.impl.bc.algo.mode.BouncyCastleCTR;
import net.daporkchop.lib.crypto.impl.bc.cipher.block.BouncyCastleBlockCipher;
import net.daporkchop.lib.crypto.key.PKey;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;

/**
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public final class BouncyCastleModeCTR extends SICBlockCipher implements PBlockCipher {
    @Getter
    protected final BouncyCastleCTR alg;
    protected final BouncyCastleBlockCipher delegate;

    public BouncyCastleModeCTR(@NonNull BouncyCastleCTR alg, @NonNull BouncyCastleBlockCipher delegate) {
        super(delegate.engine());

        this.alg = alg;
        this.delegate = delegate;
    }

    @Override
    public void init(boolean encrypt, @NonNull PKey key) {
    }

    @Override
    public void processBlock(@NonNull ByteBuf src, @NonNull ByteBuf dst) {

    }

    @Override
    public void release() throws AlreadyReleasedException {
        //no-op
    }
}
