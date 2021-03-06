/*
 * Adapted from The MIT License (MIT)
 *
 * Copyright (c) 2018-2020 DaPorkchop_
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 *
 * Any persons and/or organizations using this software must include the above copyright notice and this permission notice,
 * provide sufficient credit to the original authors of the project (IE: DaPorkchop_), as well as provide a link to the original project.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

package net.daporkchop.lib.compression.zlib.natives;

import io.netty.buffer.ByteBuf;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import net.daporkchop.lib.compression.PDeflater;
import net.daporkchop.lib.compression.util.exception.ContextFinishedException;
import net.daporkchop.lib.compression.util.exception.ContextFinishingException;
import net.daporkchop.lib.compression.zlib.ZlibDeflater;
import net.daporkchop.lib.natives.util.exception.InvalidBufferTypeException;
import net.daporkchop.lib.unsafe.PCleaner;
import net.daporkchop.lib.unsafe.util.AbstractReleasable;

/**
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
final class NativeZlibDeflater extends AbstractReleasable implements ZlibDeflater {
    static native void load();

    private static native long allocateCtx(int level, int strategy, int mode);

    private static native void releaseCtx(long ctx);

    private final long ctx;

    @Getter
    private final NativeZlib provider;
    private final PCleaner   cleaner;

    private ByteBuf src;
    private ByteBuf dst;
    private ByteBuf dict;

    private int readBytes;
    private int writtenBytes;

    private boolean reset;
    private boolean started;
    private boolean finishing;
    private boolean finished;

    NativeZlibDeflater(@NonNull NativeZlib provider, int level, int strategy, int mode) {
        this.provider = provider;

        this.ctx = allocateCtx(level, strategy, mode);
        this.cleaner = PCleaner.cleaner(this, new Releaser(this.ctx));
        this.reset = true;
    }

    @Override
    public boolean fullDeflate(@NonNull ByteBuf src, @NonNull ByteBuf dst) throws InvalidBufferTypeException {
        if (!src.hasMemoryAddress() || !dst.hasMemoryAddress()) {
            throw InvalidBufferTypeException.direct();
        }

        this.reset(); //this will do nothing if we're already reset
        this.reset = false;

        if (this.doFullDeflate(src.memoryAddress() + src.readerIndex(), src.readableBytes(),
                dst.memoryAddress() + dst.writerIndex(), dst.writableBytes())) {
            //increase indices if successful
            src.skipBytes(this.readBytes);
            dst.writerIndex(dst.writerIndex() + this.writtenBytes);
            return true;
        } else {
            return false;
        }
    }

    private native boolean doFullDeflate(long srcAddr, int srcSize, long dstAddr, int dstSize);

    @Override
    public PDeflater update(boolean flush) throws ContextFinishedException, ContextFinishingException {
        this.update(this.src, this.dst, flush);
        return this;
    }

    private void update(@NonNull ByteBuf src, @NonNull ByteBuf dst, boolean flush) {
        if (this.finished) {
            throw new ContextFinishedException();
        } else if (this.finishing) {
            throw new ContextFinishingException();
        }

        this.reset = false;
        this.started = true;

        this.doUpdate(src.memoryAddress() + src.readerIndex(), src.readableBytes(),
                dst.memoryAddress() + dst.writerIndex(), dst.writableBytes(),
                flush);

        //increase indices
        src.skipBytes(this.readBytes);
        dst.writerIndex(dst.writerIndex() + this.writtenBytes);
    }

    private native void doUpdate(long srcAddr, int srcSize, long dstAddr, int dstSize, boolean flush);

    @Override
    public boolean finish() throws ContextFinishedException {
        return this.finish(this.src, this.dst);
    }

    private boolean finish(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        if (this.finished) {
            throw new ContextFinishedException();
        }

        this.reset = false;
        this.started = true;
        this.finishing = true;

        if (this.doFinish(src.memoryAddress() + src.readerIndex(), src.readableBytes(),
                dst.memoryAddress() + dst.writerIndex(), dst.writableBytes())) {
            //increase indices if successful
            src.skipBytes(this.readBytes);
            dst.writerIndex(dst.writerIndex() + this.writtenBytes);
            return true;
        } else {
            return false;
        }
    }

    private native boolean doFinish(long srcAddr, int srcSize, long dstAddr, int dstSize);

    @Override
    public PDeflater reset() {
        if (!this.reset) {
            this.src = null;
            this.dst = null;
            if (this.dict != null) {
                this.dict.release();
                this.dict = null;
            }

            this.readBytes = 0;
            this.writtenBytes = 0;

            this.started = false;
            this.finishing = false;
            this.finished = false;

            this.doReset();
        }
        return this;
    }

    private native void doReset();

    @Override
    public PDeflater dict(@NonNull ByteBuf dict) throws InvalidBufferTypeException {
        if (!dict.hasMemoryAddress()) {
            throw InvalidBufferTypeException.direct();
        } else if (this.started) {
            throw new IllegalStateException("Cannot set dictionary after compression has started!");
        } else if (this.dict != null) {
            throw new IllegalStateException("Dictionary has already been set!");
        }

        this.dict = dict = dict.retainedSlice();
        this.doDict(dict.memoryAddress(), dict.readableBytes());

        return this;
    }

    private native void doDict(long dictAddr, int dictSize);

    @Override
    public PDeflater src(@NonNull ByteBuf src) throws InvalidBufferTypeException {
        if (!src.hasMemoryAddress()) {
            throw InvalidBufferTypeException.direct();
        }
        this.src = src;
        return this;
    }

    @Override
    public PDeflater dst(@NonNull ByteBuf dst) throws InvalidBufferTypeException {
        if (!dst.hasMemoryAddress()) {
            throw InvalidBufferTypeException.direct();
        }
        this.dst = dst;
        return this;
    }

    @Override
    public boolean directAccepted() {
        return true;
    }

    @Override
    protected void doRelease() {
        this.cleaner.clean();
    }

    @RequiredArgsConstructor
    private static final class Releaser implements Runnable {
        private final long ctx;

        @Override
        public void run() {
            releaseCtx(this.ctx);
        }
    }
}
