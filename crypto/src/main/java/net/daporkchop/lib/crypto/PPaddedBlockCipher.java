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

package net.daporkchop.lib.crypto;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;

/**
 * A wrapper around a {@link PBlockCipher} that applies cipher padding using a {@link PBlockCipherPadding}.
 *
 * @author DaPorkchop_
 */
//TODO: impleemnt
@RequiredArgsConstructor
@Accessors(fluent = true)
public final class PPaddedBlockCipher implements PCipher {
    protected final PBlockCipher cipher;
    protected final PBlockCipherPadding padding;
    protected final ByteBuf buffer;

    public PPaddedBlockCipher(@NonNull PBlockCipher cipher, @NonNull PBlockCipherPadding padding)   {
        this.cipher = cipher;
        this.padding = padding;

        int blockSize = this.blockSize();
        this.buffer = cipher.direct() ? Unpooled.directBuffer(blockSize, blockSize) : Unpooled.buffer(blockSize, blockSize);
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key) {
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key, @NonNull ByteBuf iv) throws UnsupportedOperationException {
    }

    @Override
    public void src(@NonNull ByteBuf src) {
    }

    @Override
    public ByteBuf src() {
        return null;
    }

    @Override
    public void dst(@NonNull ByteBuf dst) {
    }

    @Override
    public ByteBuf dst() {
        return null;
    }

    @Override
    public void process() throws IllegalArgumentException {
    }

    @Override
    public boolean flush() {
        return false;
    }

    @Override
    public boolean finish() throws IllegalArgumentException {
        return false;
    }

    @Override
    public boolean finished() {
        return false;
    }

    @Override
    public String name() {
        return this.cipher.name() + "/" + this.padding.name();
    }

    @Override
    public boolean hasBuffer() {
        return true;
    }

    @Override
    public int blockSize() {
        return this.cipher.blockSize();
    }

    @Override
    public int[] keySizes() {
        return this.cipher.keySizes();
    }

    @Override
    public boolean direct() {
        return this.cipher.direct();
    }

    @Override
    public void release() throws AlreadyReleasedException {
        if (this.buffer.refCnt() == 0)  {
            throw new AlreadyReleasedException();
        } else {
            this.buffer.release();
            this.cipher.release();
        }
    }
}
