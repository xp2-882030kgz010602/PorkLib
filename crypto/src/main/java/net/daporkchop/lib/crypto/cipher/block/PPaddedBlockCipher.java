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

package net.daporkchop.lib.crypto.cipher.block;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import lombok.experimental.Accessors;

/**
 * A wrapper around a {@link PBlockCipher} that applies cipher padding using a {@link PBlockCipherPadding}.
 *
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public final class PPaddedBlockCipher extends PBufferedBlockCipher {
    protected final PBlockCipherPadding padding;

    public PPaddedBlockCipher(@NonNull PBlockCipher cipher, @NonNull PBlockCipherPadding padding) {
        super(cipher);

        this.padding = padding;
    }

    @Override
    protected void drainBuffer(@NonNull ByteBuf dst) {
        if (this.encrypt && this.buffer.writerIndex() != this.blockSize) {
            //apply padding to buffered block if needed
            this.padding.pad(this.buffer, this.blockSize - this.buffer.writerIndex(), this.blockSize);
        }

        super.drainBuffer(dst);
    }

    @Override
    public String name() {
        return this.cipher.name() + "/" + this.padding.name();
    }
}
