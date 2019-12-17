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
import net.daporkchop.lib.crypto.cipher.PSeekableCipher;
import net.daporkchop.lib.crypto.impl.bc.algo.mode.BouncyCastleBlockCipherMode;
import net.daporkchop.lib.crypto.impl.bc.algo.mode.BouncyCastleCTR;
import net.daporkchop.lib.crypto.impl.bc.cipher.block.BouncyCastleBlockCipher;
import net.daporkchop.lib.crypto.impl.bc.cipher.block.IBouncyCastleBlockCipher;
import net.daporkchop.lib.crypto.key.PKey;
import net.daporkchop.lib.unsafe.PUnsafe;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.modes.SICBlockCipher;

/**
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public final class BouncyCastleModeCTR extends SICBlockCipher implements IBouncyCastleBlockCipher, PSeekableCipher {
    protected static final long BYTECOUNT_OFFSET = PUnsafe.pork_getOffset(SICBlockCipher.class, "byteCount");
    protected static final long COUNTER_OFFSET = PUnsafe.pork_getOffset(SICBlockCipher.class, "counter");
    protected static final long COUNTEROUT_OFFSET = PUnsafe.pork_getOffset(SICBlockCipher.class, "counterOut");

    @Getter
    protected final BouncyCastleCTR alg;
    protected final BouncyCastleBlockCipher delegate;

    @Getter
    protected final byte[] buffer;

    protected final int blockSize;

    public BouncyCastleModeCTR(@NonNull BouncyCastleCTR alg, @NonNull BouncyCastleBlockCipher delegate) {
        super(delegate.engine());

        this.alg = alg;
        this.delegate = delegate;
        this.buffer = new byte[(this.blockSize = delegate.blockSize()) << 1];
    }

    //optimization
    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        final int blockSize = this.blockSize;
        if (inOff + blockSize > in.length)  {
            throw new DataLengthException(String.format("Insufficient data to process block @ %d bytes (length=%d, offset=%d)", blockSize, in.length, inOff));
        } else if (outOff + blockSize > out.length) {
            throw new DataLengthException(String.format("Insufficient output space to process block @ %d bytes (length=%d, offset=%d)", blockSize, out.length, outOff));
        }

        if (PUnsafe.getInt(this, BYTECOUNT_OFFSET) == 0) {
            //fast mode
            byte[] counterOut = PUnsafe.getObject(this, COUNTEROUT_OFFSET);

            //update counterOut
            this.delegate.engine().processBlock(PUnsafe.getObject(this, COUNTER_OFFSET), 0, counterOut, 0);

            int i = 0;
            //do XOR-ing in 8-byte steps
            for (; i + 8L < blockSize; i += 8L)    {
                PUnsafe.putLong(out, PUnsafe.ARRAY_LONG_BASE_OFFSET + outOff + i, PUnsafe.getLong(in, PUnsafe.ARRAY_LONG_BASE_OFFSET + inOff + i) ^ PUnsafe.getLong(counterOut, PUnsafe.ARRAY_LONG_BASE_OFFSET + i));
            }

            //finish up any remaining bytes one at a time
            while (i < blockSize)   {
                out[outOff + i] = (byte) (in[inOff + i] ^ counterOut[i]);
                i++;
            }

            //force final step of calculateByte
            PUnsafe.putInt(this, BYTECOUNT_OFFSET, blockSize - 1);
            this.calculateByte((byte) 0);
        } else {
            //slow mode
            for (int i = 0; i < blockSize; i++) {
                out[outOff + i] = this.calculateByte(in[inOff + i]);
            }
        }
        return blockSize;
    }

    //block cipher implementations

    @Override
    public BlockCipher engine() {
        return this;
    }

    @Override
    public void init(boolean encrypt, @NonNull PKey key) {
        if (key instanceof BouncyCastleBlockCipherMode.WrappedIVKey) {
            super.init(encrypt, (BouncyCastleBlockCipherMode.WrappedIVKey) key);
        } else {
            throw new IllegalArgumentException(String.format("Invalid key type \"%s\", expected \"%s\"!", key.getClass().getCanonicalName(), BouncyCastleBlockCipherMode.WrappedIVKey.class.getCanonicalName()));
        }
    }

    @Override
    public void release() throws AlreadyReleasedException {
        //no-op
    }

    @Override
    public long processedSize(long inputSize) {
        //return block cipher processedSize, since it's an upper bound
        return IBouncyCastleBlockCipher.super.processedSize(inputSize);
    }

    //stream cipher implementations
    @Override
    public void seek(long position) {
        super.seekTo(position);
    }

    @Override
    public long position() {
        return super.getPosition();
    }

    @Override
    public void process(@NonNull ByteBuf src, @NonNull ByteBuf dst, int size) {
        if (size < 0) {
            throw new IllegalArgumentException(String.valueOf(size));
        } else if (size > 0) {
            if (src.readableBytes() < size) {
                throw new IllegalArgumentException(String.format("Not enough data to process %d bytes (src=%d)", size, src.readableBytes()));
            }
            dst.ensureWritable(size);

            final int blockSize = this.blockSize;
            int byteCount = PUnsafe.getInt(this, BYTECOUNT_OFFSET);

            boolean srcHasArray = src.hasArray();
            boolean dstHasArray = dst.hasArray();
            if (srcHasArray && dstHasArray) {
                //very fast mode
                byte[] srcArray = src.array();
                int srcArrayOffset = src.arrayOffset() + src.readerIndex();

                byte[] dstArray = dst.array();
                int dstArrayOffset = dst.arrayOffset() + dst.writerIndex();

                //do individual bytes until next block border
                while (PUnsafe.getInt(this, BYTECOUNT_OFFSET) != 0 && size-- > 0) {
                    dstArray[dstArrayOffset++] = this.calculateByte(srcArray[srcArrayOffset++]);
                }

                //stop if we are already done
                if (size == 0) return;

                int blocks = size / blockSize;
                if (blocks != 0)    {
                    //calculate full blocks at a time
                } //TODO: finish this
            }
        }
    }
}
