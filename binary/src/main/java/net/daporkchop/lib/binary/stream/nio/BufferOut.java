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

package net.daporkchop.lib.binary.stream.nio;

import lombok.AllArgsConstructor;
import lombok.NonNull;
import net.daporkchop.lib.binary.stream.DataOut;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * An implementation of {@link DataOut} that can write to a {@link ByteBuffer}
 *
 * @author DaPorkchop_
 */
@AllArgsConstructor
public class BufferOut extends DataOut {
    @NonNull
    private final ByteBuffer buffer;

    @Override
    public void write(int b) throws IOException {
        this.buffer.put((byte) b);
    }

    @Override
    public void write(@NonNull byte[] b, int off, int len) throws IOException {
        this.buffer.put(b, off, len);
    }

    @Override
    public DataOut writeByte(byte b) throws IOException {
        this.buffer.put(b);
        return this;
    }

    @Override
    public DataOut writeShort(short s) throws IOException {
        this.buffer.order(ByteOrder.BIG_ENDIAN).putShort(s);
        return this;
    }

    @Override
    public DataOut writeShortLE(short s) throws IOException {
        this.buffer.order(ByteOrder.LITTLE_ENDIAN).putShort(s);
        return this;
    }

    @Override
    public DataOut writeChar(char c) throws IOException {
        this.buffer.order(ByteOrder.BIG_ENDIAN).putChar(c);
        return this;
    }

    @Override
    public DataOut writeCharLE(char c) throws IOException {
        this.buffer.order(ByteOrder.LITTLE_ENDIAN).putChar(c);
        return this;
    }

    @Override
    public DataOut writeInt(int i) throws IOException {
        this.buffer.order(ByteOrder.BIG_ENDIAN).putInt(i);
        return this;
    }

    @Override
    public DataOut writeIntLE(int i) throws IOException {
        this.buffer.order(ByteOrder.LITTLE_ENDIAN).putInt(i);
        return this;
    }

    @Override
    public DataOut writeLong(long l) throws IOException {
        this.buffer.order(ByteOrder.BIG_ENDIAN).putLong(l);
        return this;
    }

    @Override
    public DataOut writeLongLE(long l) throws IOException {
        this.buffer.order(ByteOrder.LITTLE_ENDIAN).putLong(l);
        return this;
    }

    @Override
    public DataOut writeFloat(float f) throws IOException {
        this.buffer.order(ByteOrder.BIG_ENDIAN).putFloat(f);
        return this;
    }

    @Override
    public DataOut writeFloatLE(float f) throws IOException {
        this.buffer.order(ByteOrder.LITTLE_ENDIAN).putFloat(f);
        return this;
    }

    @Override
    public DataOut writeDouble(double d) throws IOException {
        this.buffer.order(ByteOrder.BIG_ENDIAN).putDouble(d);
        return this;
    }

    @Override
    public DataOut writeDoubleLE(double d) throws IOException {
        this.buffer.order(ByteOrder.LITTLE_ENDIAN).putDouble(d);
        return this;
    }

    @Override
    public void close() throws IOException {
    }
}
