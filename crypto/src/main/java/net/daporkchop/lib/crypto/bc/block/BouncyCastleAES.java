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

package net.daporkchop.lib.crypto.bc.block;

import io.netty.buffer.ByteBuf;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.Accessors;
import net.daporkchop.lib.crypto.bc.BouncyCastleCipher;
import net.daporkchop.lib.unsafe.PUnsafe;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * @author DaPorkchop_
 */
@Accessors(fluent = true, chain = false)
public final class BouncyCastleAES extends AESEngine implements BouncyCastleBlockCipher {
    protected static final int[] KEY_SIZES = {
            128 >>> 3,
            192 >>> 3,
            256 >>> 3
    };

    protected static final int BLOCK_SIZE = 128 >>> 3;

    @Getter
    protected final byte[] globalBuffer = new byte[BLOCK_SIZE];

    protected final KeyParameter param = PUnsafe.allocateInstance(KeyParameter.class);

    @Getter
    protected boolean finished = false;

    public BouncyCastleAES()    {
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key) {
        final int keySize = key.readableBytes();
        if (!this.keySizeSupported(keySize)) {
            throw new IllegalArgumentException(String.format("AES does not support keys @ %d bytes!", key.readableBytes()));
        }

        byte[] keyArray = this.param.getKey();
        if (keyArray == null || keyArray.length != keySize) {
            PUnsafe.putObject(this.param, KEYPARAMETER_KEY_OFFSET, keyArray = new byte[keySize]);
        }
        key.readBytes(keyArray);

        //actually init cipher
        super.init(encrypt, this.param);

        this.finished = false;
    }

    @Override
    public boolean flush(@NonNull ByteBuf dst) {
        return true;
    }

    @Override
    public String name() {
        return "AES";
    }

    @Override
    public boolean hasBuffer() {
        return false;
    }

    @Override
    public int bufferedCount() {
        return 0;
    }

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public int[] keySizes() {
        return KEY_SIZES.clone();
    }

    @Override
    public int bestKeySize() {
        return 256 >>> 3;
    }

    @Override
    public boolean keySizeSupported(int size) {
        return size == (128 >>> 3) || size == (192 >>> 3) || size == (256 >>> 3);
    }
}
