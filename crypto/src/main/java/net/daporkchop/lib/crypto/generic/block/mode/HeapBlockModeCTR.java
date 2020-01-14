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

package net.daporkchop.lib.crypto.generic.block.mode;

import io.netty.buffer.ByteBuf;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.Accessors;
import net.daporkchop.lib.binary.Endianess;
import net.daporkchop.lib.common.util.PorkUtil;
import net.daporkchop.lib.crypto.cipher.block.PSeekableBlockCipher;
import net.daporkchop.lib.crypto.generic.IDelegatingCipher;
import net.daporkchop.lib.crypto.generic.block.IHeapBlockCipher;
import net.daporkchop.lib.unsafe.PUnsafe;

/**
 * A simple implementation of CTR mode on a heap-based block cipher.
 *
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public final class HeapBlockModeCTR implements IHeapBlockCipher, IDelegatingCipher, PSeekableBlockCipher {
    private static long fixOrder(long val) {
        return Endianess.NATIVE == Endianess.BIG ? val : Long.reverseBytes(val);
    }

    protected long position;
    protected long base;

    @Getter
    protected final IHeapBlockCipher delegate;
    @Getter
    protected final byte[] globalBuffer;
    protected final byte[] internalBuffer;
    protected final byte[] iv;

    public HeapBlockModeCTR(@NonNull IHeapBlockCipher delegate) {
        this.delegate = delegate;

        if (delegate.blockSize() < 8) {
            throw new IllegalArgumentException(String.format("CTR mode requires a block size of at least 8 bytes (given: %d)", delegate.blockSize()));
        }

        this.globalBuffer = new byte[delegate.blockSize()];
        this.internalBuffer = this.globalBuffer.clone();
        this.iv = this.globalBuffer.clone();
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key) {
        this.doInit(key, null);
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key, @NonNull ByteBuf iv) throws UnsupportedOperationException {
        this.doInit(key, iv);
    }

    private void doInit(@NonNull ByteBuf key, ByteBuf iv) {
        this.delegate.init(true, key);

        if (iv == null) {
            PUnsafe.setMemory(this.iv, PUnsafe.ARRAY_BYTE_BASE_OFFSET, this.iv.length, (byte) 0);
        } else if (iv.readableBytes() == this.iv.length) {
            iv.readBytes(this.iv);
        } else {
            throw new IllegalArgumentException(String.format("%s/CTR requires an IV length of %d bytes (given: %d)", this.delegate.name(), this.iv.length, iv.readableBytes()));
        }

        this.position = 0L;
        this.base = fixOrder(PUnsafe.getLong(this.iv, PUnsafe.ARRAY_BYTE_BASE_OFFSET + this.iv.length - 8L));
    }

    @Override
    public void processHeapBlock(@NonNull byte[] in, int inOff, @NonNull byte[] out, int outOff) {
        final int blockSize = this.iv.length;

        PorkUtil.assertInRangeLen(in.length, inOff, blockSize);
        PorkUtil.assertInRangeLen(out.length, outOff, blockSize);

        final byte[] buffer = in == out ? this.internalBuffer : out;
        final int bufOff = in == out ? 0 : outOff;

        //encrypt block
        this.delegate.processHeapBlock(this.iv, 0, buffer, 0);

        //xor with data
        if ((blockSize & 0x7) == 0) {
            //if a multiple of 8, xor entire words at a time
            for (long i = 0L; i < blockSize; i += 8L) {
                //we don't need to worry about byte ordering since we're just XOR-ing the data
                PUnsafe.putLong(
                        out,
                        PUnsafe.ARRAY_BYTE_BASE_OFFSET + i + outOff,
                        PUnsafe.getLong(buffer, PUnsafe.ARRAY_BYTE_BASE_OFFSET + i + bufOff)
                                ^ PUnsafe.getLong(in, PUnsafe.ARRAY_BYTE_BASE_OFFSET + i + inOff)
                );
            }
        } else {
            //xor bytewise
            for (int i = 0; i < blockSize; i++) {
                out[i + outOff] = (byte) (buffer[i + bufOff] ^ in[i + inOff]);
            }
        }

        //increment counter
        PUnsafe.putLong(this.iv, PUnsafe.ARRAY_BYTE_BASE_OFFSET + blockSize - 8L, fixOrder(this.base + (++this.position)));
    }

    @Override
    public void processHeapBlocks(@NonNull byte[] in, int inOff, @NonNull byte[] out, int outOff, int blocks)    {
        if (blocks < 0) {
            throw new IllegalArgumentException(String.valueOf(blocks));
        } else if (blocks == 0) {
            return;
        } else if (blocks == 1) {
            this.processHeapBlock(in, inOff, out, outOff);
        } else {
            final int blockSize = this.blockSize();
            PorkUtil.assertInRangeLen(in.length, inOff, blocks * blockSize);
            PorkUtil.assertInRangeLen(out.length, outOff, blocks * blockSize);
            if (in == out) {
                //if arrays are the same, process each block individually
                for (int i = 0; i < blocks; i++, inOff += blockSize, outOff += blockSize) {
                    this.processHeapBlock(in, inOff, out, outOff);
                }
            } else {
                //bulk processing
                for (int i = 0; i < blocks; i++)    {
                    this.delegate.processHeapBlock(this.iv, 0, out, outOff + i * blockSize);

                    //increment counter
                    PUnsafe.putLong(this.iv, PUnsafe.ARRAY_BYTE_BASE_OFFSET + blockSize - 8L, fixOrder(this.base + (++this.position)));
                }

                //TODO
            }
        }
    }

    @Override
    public long currentBlock() {
        return this.position;
    }

    @Override
    public void seekBlock(long block) {
        PUnsafe.putLong(this.iv, PUnsafe.ARRAY_BYTE_BASE_OFFSET + this.iv.length - 8L, fixOrder(this.base + (this.position = block)));
    }

    @Override
    public int blockSize() {
        return this.iv.length;
    }

    @Override
    public String name() {
        return this.delegate.name() + "/CTR";
    }

    @Override
    public int ivSize() {
        return this.iv.length;
    }

    @Override
    public boolean ivRequired() {
        return true;
    }
}
