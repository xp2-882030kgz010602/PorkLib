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

package net.daporkchop.lib.crypto.bc.block.mode;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.Accessors;
import net.daporkchop.lib.crypto.bc.block.BouncyCastleBlockCipher;
import net.daporkchop.lib.unsafe.PUnsafe;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;

/**
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public final class BouncyCastleModeCTR extends SICBlockCipher implements BouncyCastleBlockCipher {
    protected static final long IV_OFFSET = PUnsafe.pork_getOffset(SICBlockCipher.class, "IV");

    protected final BouncyCastleBlockCipher cipher;

    @Getter
    protected final byte[] globalBuffer;

    public BouncyCastleModeCTR(@NonNull BouncyCastleBlockCipher cipher)    {
        super(cipher);

        this.cipher = cipher;
        this.globalBuffer = new byte[this.cipher.blockSize()];
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key) {
        this.init(encrypt, key, Unpooled.wrappedBuffer(new byte[this.ivSize()]));
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key, @NonNull ByteBuf iv) {
        if (iv.readableBytes() < this.ivSize()) {
            throw new IllegalArgumentException(String.format("%s requires an IV of %d bytes (given: %d)", this.name(), this.ivSize(), iv.readableBytes()));
        }

        iv.readBytes(PUnsafe.<byte[]>getObject(this, IV_OFFSET));
        this.cipher.init(true, key); //must always be initialized in encrypt mode

        this.reset();
    }

    @Override
    public boolean flush(@NonNull ByteBuf dst) {
        return true;
    }

    @Override
    public String name() {
        return this.cipher.name() + "/CTR";
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
        return this.globalBuffer.length;
    }

    @Override
    public int ivSize() {
        return this.globalBuffer.length;
    }

    @Override
    public boolean ivRequired() {
        return false;
    }

    @Override
    public int[] keySizes() {
        return this.cipher.keySizes();
    }

    @Override
    public int bestKeySize() {
        return this.cipher.bestKeySize();
    }

    @Override
    public boolean keySizeSupported(int size) {
        return this.cipher.keySizeSupported(size);
    }
}
