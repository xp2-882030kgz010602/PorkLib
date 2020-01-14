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
import io.netty.buffer.Unpooled;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.Accessors;
import net.daporkchop.lib.crypto.cipher.PCipher;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;

/**
 * A wrapper around a {@link PBlockCipher} that allows processing data in arbitrarily sized-steps (rather than requiring all
 * input be a multiple of the block size).
 *
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public class PBufferedBlockCipher implements PCipher {
    protected final PBlockCipher cipher;
    protected final ByteBuf buffer;

    @Getter
    protected final int blockSize;
    @Getter
    protected final boolean direct;

    protected boolean encrypt;

    public PBufferedBlockCipher(@NonNull PBlockCipher cipher) {
        this.cipher = cipher;

        this.blockSize = this.cipher.blockSize();
        this.direct = cipher.direct();

        this.buffer = this.direct
                ? Unpooled.directBuffer(this.blockSize, this.blockSize)
                : Unpooled.buffer(this.blockSize, this.blockSize);
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key) {
        this.cipher.init(encrypt, key);

        this.encrypt = encrypt;
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key, @NonNull ByteBuf iv) throws UnsupportedOperationException {
        this.cipher.init(encrypt, key, iv);

        this.encrypt = encrypt;
    }

    @Override
    public void process(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        if (dst.writableBytes() < this.blockSize) {
            //don't bother doing anything if there isn't enough space for a block
            return;
        }

        if (this.buffer.writerIndex() != 0) {
            //there is data in the buffer, attempt to fill up rest of buffer
            int toRead = this.blockSize - this.buffer.writerIndex();
            if (toRead > 0) {
                //copy data from source into buffer
                this.buffer.writeBytes(src, toRead);
            }

            if (this.buffer.writerIndex() != this.blockSize) {
                //there wasn't enough data in the source to fill up the buffer
                return;
            }

            this.drainBuffer(dst);
        }

        //number of complete blocks that can be transferred
        int blocks = Math.min(src.readableBytes(), dst.writableBytes()) / this.blockSize;
        this.cipher.processBlocks(src, dst, blocks);

        if (src.isReadable()) {
            //buffer any remaining data after destination buffer fills up
            this.buffer.writeBytes(src, Math.min(src.readableBytes(), this.blockSize));
        }
    }

    @Override
    public boolean flush(@NonNull ByteBuf dst) {
        if (this.buffer.writerIndex() != 0) {
            //there is data in the buffer, attempt to flush
            if (dst.writableBytes() < this.blockSize) {
                //don't bother flushing if there isn't enough space for a block
                return false;
            }

            this.drainBuffer(dst);
            return true;
        } else {
            //the buffer is already empty, nothing needs to be done
            return true;
        }
    }

    protected void drainBuffer(@NonNull ByteBuf dst) {
        if (this.buffer.writerIndex() != this.blockSize) {
            throw new IllegalStateException("Buffer is not full!");
        }

        this.cipher.processBlock(this.buffer, dst);
        this.buffer.clear();
    }

    @Override
    public String name() {
        return this.cipher.name();
    }

    @Override
    public boolean hasBuffer() {
        return true;
    }

    @Override
    public int bufferedCount() {
        return this.buffer.writerIndex();
    }

    @Override
    public boolean usesBlocks() {
        return false;
    }

    @Override
    public int ivSize() {
        return this.cipher.ivSize();
    }

    @Override
    public boolean ivRequired() {
        return this.cipher.ivRequired();
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

    @Override
    public void release() throws AlreadyReleasedException {
        if (this.buffer.refCnt() == 0) {
            throw new AlreadyReleasedException();
        } else if (this.buffer.release()) {
            this.cipher.release();
        } else {
            throw new IllegalStateException();
        }
    }
}
