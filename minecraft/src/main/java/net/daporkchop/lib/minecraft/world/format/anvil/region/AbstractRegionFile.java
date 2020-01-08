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

package net.daporkchop.lib.minecraft.world.format.anvil.region;

import io.netty.buffer.ByteBuf;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.Accessors;
import net.daporkchop.lib.minecraft.world.format.anvil.region.ex.ReadOnlyRegionException;

import java.io.File;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Abstract implementation of {@link RegionFile}.
 *
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public abstract class AbstractRegionFile implements RegionFile {
    protected static final OpenOption[] RO_OPEN_OPTIONS  = {StandardOpenOption.READ};
    protected static final OpenOption[] RW_OPEN_OPTIONS  = {StandardOpenOption.READ, StandardOpenOption.WRITE};
    protected static final OpenOption[] RWC_OPEN_OPTIONS = {StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE};

    @Getter
    protected final File        file;
    protected final Lock        readLock;
    protected final Lock        writeLock;
    protected final FileChannel channel;

    @Getter
    protected final boolean readOnly;

    public AbstractRegionFile(@NonNull File file, @NonNull RegionOpenOptions options) throws IOException {
        if (!this.optionsSupported(options)) throw new IllegalArgumentException(String.valueOf(options));

        boolean readOnly;
        FileChannel channel;
        Path path = (this.file = file.getAbsoluteFile()).toPath();
        if (options.access == Access.WRITE_REQUIRED) {
            channel = FileChannel.open(path, options.createNewFiles ? RWC_OPEN_OPTIONS : RW_OPEN_OPTIONS);
            readOnly = false;
        } else if (options.access == Access.READ_ONLY) {
            channel = FileChannel.open(path, RO_OPEN_OPTIONS);
            readOnly = true;
        } else if (options.access == Access.WRITE_OPTIONAL) {
            try {
                channel = FileChannel.open(path, options.createNewFiles ? RWC_OPEN_OPTIONS : RW_OPEN_OPTIONS);
                readOnly = false;
            } catch (IOException e) {
                //try to open it in read-only mode
                channel = FileChannel.open(path, RO_OPEN_OPTIONS);
                readOnly = true;
            }
        } else {
            throw new IllegalArgumentException(String.valueOf(options.access));
        }
        this.channel = channel;

        if (!(this.readOnly = readOnly) && channel.tryLock() == null) {
            this.channel.close();
            throw new IOException(String.format("Unable to lock file: \"%s\"", file.getAbsolutePath()));
        }

        ReadWriteLock lock = new ReentrantReadWriteLock();
        this.readLock = lock.readLock();
        this.writeLock = lock.writeLock();
    }

    /**
     * Checks whether the given {@link RegionOpenOptions} are supported by this {@link RegionFile} implementation.
     *
     * @param options the {@link RegionOpenOptions} to check
     * @return whether the given {@link RegionOpenOptions} are supported by this {@link RegionFile} implementation
     */
    protected abstract boolean optionsSupported(@NonNull RegionOpenOptions options);

    /**
     * @return an 8KiB {@link ByteBuf} for accessing this region's two header sections
     */
    protected abstract ByteBuf headersBuf();

    @Override
    public ByteBuf readDirect(int x, int z) throws IOException {
        int index = RegionConstants.getOffsetIndex(x, z);
        this.readLock.lock();
        try {
            this.assertOpen();

            int offset = this.headersBuf().getInt(index);
            if (offset != 0) {
                return this.doRead(x, z, index, offset);
            } else {
                return null;
            }
        } finally {
            this.readLock.unlock();
        }
    }

    protected abstract ByteBuf doRead(int x, int z, int offsetIndex, int offset) throws IOException;

    @Override
    public void writeDirect(int x, int z, @NonNull ByteBuf buf) throws ReadOnlyRegionException, IOException {
        int index = RegionConstants.getOffsetIndex(x, z);
        this.assertWritable();
        this.writeLock.lock();
        try {
            this.assertOpen();

            this.doWrite(x, z, index, buf, (buf.readableBytes() - 1 >> 12) + 1);
        } finally {
            this.writeLock.unlock();
            buf.release();
        }
    }

    protected abstract void doWrite(int x, int z, int offsetIndex, @NonNull ByteBuf chunk, int requiredSectors) throws IOException;

    @Override
    public boolean delete(int x, int z, boolean erase) throws ReadOnlyRegionException, IOException {
        int index = RegionConstants.getOffsetIndex(x, z);
        this.assertWritable();
        this.writeLock.lock();
        try {
            this.assertOpen();

            ByteBuf headers = this.headersBuf();
            int offset = headers.getInt(index);
            if (offset != 0)    {
                this.doDelete(x, z, offset >>> 8, offset & 0xFF, erase);
                return true;
            } else {
                return false;
            }
        } finally {
            this.writeLock.unlock();
        }
    }

    protected abstract void doDelete(int x, int z, int startIndex, int length, boolean erase) throws IOException;

    @Override
    public int getOffset(int x, int z) {
        this.readLock.lock();
        try {
            this.assertOpen();

            return this.headersBuf().getInt(RegionConstants.getOffsetIndex(x, z));
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            this.readLock.unlock();
        }
    }

    @Override
    public int getTimestamp(int x, int z) {
        this.readLock.lock();
        try {
            this.assertOpen();

            return this.headersBuf().getInt(RegionConstants.getTimestampIndex(x, z));
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            this.readLock.unlock();
        }
    }

    @Override
    public void flush() throws IOException, ReadOnlyRegionException {
        this.assertWritable();
        this.writeLock.lock();
        try {
            this.assertOpen();

            this.doFlush();
        } finally {
            this.writeLock.unlock();
        }
    }

    protected abstract void doFlush() throws IOException;

    @Override
    public void close() throws IOException {
        this.writeLock.lock();
        try {
            this.assertOpen();

            this.doClose();
            this.channel.close();
        } finally {
            this.writeLock.unlock();
        }
    }

    protected abstract void doClose() throws IOException;

    protected void assertOpen() throws IOException   {
        if (!this.channel.isOpen()) {
            throw new IOException("Region closed!");
        }
    }
}
