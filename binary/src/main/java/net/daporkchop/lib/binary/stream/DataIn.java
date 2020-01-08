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

package net.daporkchop.lib.binary.stream;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import net.daporkchop.lib.binary.stream.netty.NettyByteBufIn;
import net.daporkchop.lib.binary.stream.nio.BufferIn;
import net.daporkchop.lib.binary.stream.stream.StreamIn;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

/**
 * Provides simple methods for reading data from a binary form
 *
 * @author DaPorkchop_
 * @see DataOut
 */
public abstract class DataIn extends InputStream {
    /**
     * Wraps an {@link InputStream} to make it into a {@link DataIn}.
     *
     * @param in the stream to wrap
     * @return the wrapped stream, or the original stream if it was already a {@link DataIn}
     */
    public static DataIn wrap(@NonNull InputStream in) {
        return in instanceof DataIn ? (DataIn) in : new StreamIn.Closing(in);
    }

    /**
     * Wraps an {@link InputStream} to make it into a {@link DataIn}.
     * <p>
     * Calling {@link #close()} on the returned {@link DataIn} will not cause the wrapped stream to be closed.
     *
     * @param in the stream to wrap
     * @return the wrapped stream, or the original stream if it was already a {@link StreamIn}
     */
    public static DataIn wrapNonClosing(@NonNull InputStream in) {
        return in instanceof StreamIn && !(in instanceof StreamIn.Closing)
                ? (StreamIn) in
                : new StreamIn(in instanceof DataIn ? ((DataIn) in).unwrap() : in);
    }

    /**
     * Wraps a {@link ByteBuffer} to make it into a {@link DataIn}.
     *
     * @param buffer the buffer to wrap
     * @return the wrapped buffer as a {@link DataIn}
     */
    public static DataIn wrap(@NonNull ByteBuffer buffer) {
        /*if (buffer.hasArray()) {
            return new StreamIn(new ByteArrayInputStream(buffer.array(), buffer.position(), buffer.remaining()));
        } else {*/
            return new BufferIn(buffer);
        //}
    }

    /**
     * Wraps a {@link ByteBuffer} to make it into an {@link InputStream}.
     *
     * @param buffer the buffer to wrap
     * @return the wrapped buffer as an {@link InputStream}
     */
    public static InputStream wrapAsStream(@NonNull ByteBuffer buffer) {
        if (buffer.hasArray()) {
            return new ByteArrayInputStream(buffer.array(), buffer.position(), buffer.remaining());
        } else {
            return new BufferIn(buffer);
        }
    }

    /**
     * @see #wrapBuffered(File)
     */
    public static DataIn wrap(@NonNull File file) throws IOException {
        return wrapBuffered(file);
    }

    /**
     * Gets a {@link DataIn} for reading from a {@link File}.
     * <p>
     * The file will additionally be wrapped in a {@link BufferedInputStream} for faster read/write access, using
     * the default buffer size of {@link BufferedInputStream#DEFAULT_BUFFER_SIZE}.
     *
     * @param file the file to read from
     * @return a buffered {@link DataIn} that will read from the given file
     * @throws IOException if an IO exception occurs you dummy
     */
    public static DataIn wrapBuffered(@NonNull File file) throws IOException {
        return wrap(new BufferedInputStream(new FileInputStream(file)));
    }

    /**
     * Gets a {@link DataIn} for reading from a {@link File}.
     * <p>
     * The file will additionally be wrapped in a {@link BufferedInputStream} for faster read/write access, using
     * the given buffer size.
     *
     * @param file       the file to read from
     * @param bufferSize the size of the buffer to use
     * @return a buffered {@link DataIn} that will read from the given file
     * @throws IOException if an IO exception occurs you dummy
     */
    public static DataIn wrapBuffered(@NonNull File file, int bufferSize) throws IOException {
        return wrap(new BufferedInputStream(new FileInputStream(file), bufferSize));
    }

    /**
     * Gets a {@link DataIn} for reading from a {@link File}.
     * <p>
     * {@link DataIn} instances returned from this method will NOT be buffered.
     *
     * @param file the file to read from
     * @return a direct {@link DataIn} that will read from the given file
     * @throws IOException if an IO exception occurs you dummy
     */
    public static DataIn wrapNonBuffered(@NonNull File file) throws IOException {
        return wrap(new FileInputStream(file));
    }
    /**
     * Wraps a {@link ByteBuf} into a {@link DataIn} for reading.
     * <p>
     * When the {@link DataIn} is closed (using {@link DataIn#close()}), the {@link ByteBuf} will not be released.
     *
     * @param buf the {@link ByteBuf} to read from
     * @return a {@link DataIn} that can read data from the {@link ByteBuf}
     */
    public static DataIn wrap(@NonNull ByteBuf buf) {
        return wrap(buf, false);
    }

    /**
     * Wraps a {@link ByteBuf} into a {@link DataIn} for reading.
     * <p>
     * When the {@link DataIn} is closed (using {@link DataIn#close()}), the {@link ByteBuf} may or may not be released, depending on the value of the
     * {@code release} parameter.
     *
     * @param buf     the {@link ByteBuf} to read from
     * @param release whether or not to release the buffer when the {@link DataIn} is closed
     * @return a {@link DataIn} that can read data from the {@link ByteBuf}
     */
    public static DataIn wrap(@NonNull ByteBuf buf, boolean release) {
        return release ? new NettyByteBufIn.Releasing(buf) : new NettyByteBufIn(buf);
    }

    /**
     * Read a boolean.
     *
     * @return a boolean
     */
    public boolean readBoolean() throws IOException {
        return this.read() == 1;
    }

    /**
     * Read a byte (8-bit) value.
     *
     * @return a byte
     */
    public byte readByte() throws IOException {
        return (byte) this.read();
    }

    /**
     * Read a byte (8-bit) value.
     *
     * @return a byte
     */
    public int readUByte() throws IOException {
        return this.read() & 0xFF;
    }

    /**
     * Read a big-endian short (16-bit) value.
     *
     * @return a short
     */
    public short readShort() throws IOException {
        return (short) (((this.read() & 0xFF) << 8)
                | (this.read() & 0xFF));
    }

    /**
     * Read a big-endian short (16-bit) value.
     *
     * @return a short
     */
    public int readUShort() throws IOException {
        return this.readShort() & 0xFFFF;
    }

    /**
     * Read a little-endian short (16-bit) value.
     *
     * @return a short
     */
    public short readShortLE() throws IOException {
        return (short) ((this.read() & 0xFF)
                | ((this.read() & 0xFF) << 8));
    }

    /**
     * Read a little-endian short (16-bit) value.
     *
     * @return a short
     */
    public int readUShortLE() throws IOException {
        return this.readShortLE() & 0xFFFF;
    }

    /**
     * Read a big-endian char (16-bit) value.
     *
     * @return a char
     */
    public char readChar() throws IOException {
        return (char) (((this.read() & 0xFF) << 8)
                | (this.read() & 0xFF));
    }

    /**
     * Read a little-endian char (16-bit) value.
     *
     * @return a char
     */
    public char readCharLE() throws IOException {
        return (char) ((this.read() & 0xFF)
                | ((this.read() & 0xFF) << 8));
    }

    /**
     * Read a big-endian int (32-bit) value.
     *
     * @return an int
     */
    public int readInt() throws IOException {
        return ((this.read() & 0xFF) << 24)
                | ((this.read() & 0xFF) << 16)
                | ((this.read() & 0xFF) << 8)
                | (this.read() & 0xFF);
    }

    /**
     * Read a big-endian int (32-bit) value.
     *
     * @return an int
     */
    public long readUInt() throws IOException {
        return this.readInt() & 0xFFFFFFFFL;
    }

    /**
     * Read a little-endian int (32-bit) value.
     *
     * @return an int
     */
    public int readIntLE() throws IOException {
        return (this.read() & 0xFF)
                | ((this.read() & 0xFF) << 8)
                | ((this.read() & 0xFF) << 16)
                | ((this.read() & 0xFF) << 24);
    }

    /**
     * Read a little-endian int (32-bit) value.
     *
     * @return an int
     */
    public long readUIntLE() throws IOException {
        return this.readIntLE() & 0xFFFFFFFFL;
    }

    /**
     * Read a big-endian long (64-bit) value.
     *
     * @return a long
     */
    public long readLong() throws IOException {
        return (((long) this.read() & 0xFF) << 56L)
                | (((long) this.read() & 0xFF) << 48L)
                | (((long) this.read() & 0xFF) << 40L)
                | (((long) this.read() & 0xFF) << 32L)
                | (((long) this.read() & 0xFF) << 24L)
                | (((long) this.read() & 0xFF) << 16L)
                | (((long) this.read() & 0xFF) << 8L)
                | ((long) this.read() & 0xFF);
    }

    /**
     * Read a little-endian long (64-bit) value.
     *
     * @return a long
     */
    public long readLongLE() throws IOException {
        return ((long) this.read() & 0xFF)
                | (((long) this.read() & 0xFF) << 8L)
                | (((long) this.read() & 0xFF) << 16L)
                | (((long) this.read() & 0xFF) << 24L)
                | (((long) this.read() & 0xFF) << 32L)
                | (((long) this.read() & 0xFF) << 40L)
                | (((long) this.read() & 0xFF) << 48L)
                | (((long) this.read() & 0xFF) << 56L);
    }

    /**
     * Read a big-endian float (32-bit floating point) value.
     *
     * @return a float
     */
    public float readFloat() throws IOException {
        return Float.intBitsToFloat(this.readInt());
    }

    /**
     * Read a little-endian float (32-bit floating point) value.
     *
     * @return a float
     */
    public float readFloatLE() throws IOException {
        return Float.intBitsToFloat(this.readIntLE());
    }

    /**
     * Read a big-endian double (64-bit floating point) value.
     *
     * @return a double
     */
    public double readDouble() throws IOException {
        return Double.longBitsToDouble(this.readLong());
    }

    /**
     * Read a little-endian double (64-bit floating point) value.
     *
     * @return a double
     */
    public double readDoubleLE() throws IOException {
        return Double.longBitsToDouble(this.readLongLE());
    }

    /**
     * Read a UTF-8 encoded string.
     *
     * @return a string
     */
    public String readUTF() throws IOException {
        return new String(this.readByteArray(), StandardCharsets.UTF_8);
    }

    /**
     * Reads a plain byte array with a length prefix encoded as a varInt.
     *
     * @return a byte array
     */
    public byte[] readByteArray() throws IOException {
        byte[] b = new byte[this.readVarInt()];
        this.readFully(b);
        return b;
    }

    /**
     * Reads an enum value.
     *
     * @param f   a function to calculate the enum value from the name (i.e. MyEnum::valueOf)
     * @param <E> the enum type
     * @return a value of <E>, or null if input was null
     */
    public <E extends Enum<E>> E readEnum(@NonNull Function<String, E> f) throws IOException {
        if (this.readBoolean()) {
            return f.apply(this.readUTF());
        } else {
            return null;
        }
    }

    /**
     * Reads a Mojang-style VarInt.
     * <p>
     * As described at https://wiki.vg/index.php?title=Protocol&oldid=14204#VarInt_and_VarLong
     *
     * @return the read value
     */
    public int readVarInt() throws IOException {
        int numRead = 0;
        int result = 0;
        byte read;
        do {
            read = this.readByte();
            result |= ((read & 0b01111111) << (7 * numRead));

            numRead++;
            if (numRead > 5) {
                throw new RuntimeException("VarInt is too big");
            }
        } while ((read & 0b10000000) != 0);
        return result;
    }

    /**
     * Reads a Mojang-style VarLong.
     * <p>
     * As described at https://wiki.vg/index.php?title=Protocol&oldid=14204#VarInt_and_VarLong
     *
     * @return the read value
     */
    public long readVarLong() throws IOException {
        int numRead = 0;
        long result = 0;
        byte read;
        do {
            read = this.readByte();
            result |= ((read & 0b01111111L) << (7 * numRead));

            numRead++;
            if (numRead > 10) {
                throw new RuntimeException("VarLong is too big");
            }
        } while ((read & 0b10000000) != 0);
        return result;
    }

    /**
     * Reads a {@link CharSequence} using the given {@link Charset}.
     * <p>
     * Depending on the {@link Charset} used, certain optimizations may be applied. It is therefore recommended to use values from {@link StandardCharsets}
     * if possible.
     *
     * @param size    the length of the encoded {@link CharSequence} in bytes
     * @param charset the {@link Charset} to encode the text using
     * @return the read {@link CharSequence}
     */
    public CharSequence readText(long size, @NonNull Charset charset) throws IOException  {
        if (size > Integer.MAX_VALUE)   {
            throw new IllegalArgumentException("size parameter too large!");
        }
        return new String(this.readFully(new byte[(int) size]), charset);
    }

    /**
     * Attempts to fill a byte array with data.
     * <p>
     * Functionally equivalent to:
     * {@code return readFully(b, 0, b.length);}
     *
     * @param b the byte array to read into
     * @return the {@code byte[]} that the data was read into
     * @throws IOException if end of stream is reached before the required number required bytes are read
     */
    public byte[] readFully(@NonNull byte[] b) throws IOException {
        return this.readFully(b, 0, b.length);
    }

    /**
     * Attempts to fill a given region of a byte array with data.
     *
     * @param b   the byte array to read into
     * @param off the offset in the array to write data to
     * @param len the number of bytes to read
     * @return the {@code byte[]} that the data was read into
     * @throws IOException if end of stream is reached before the required number required bytes are read
     */
    public byte[] readFully(@NonNull byte[] b, int off, int len) throws IOException {
        int i = 0;
        while (len > 0 && (i = this.read(b, off + i, len)) != -1) {
            len -= i;
        }
        if (i == -1) {
            throw new IOException("Reached end of stream!");
        }
        return b;
    }

    /**
     * Reads all available bytes from this stream, as returned by {@link #available()}.
     *
     * @return all available bytes from this stream
     */
    public byte[] readAllAvailableBytes() throws IOException {
        byte[] b = new byte[this.available()];
        this.readFully(b);
        return b;
    }

    /**
     * Gets an {@link InputStream} that may be used in place of this {@link DataIn} instance.
     * <p>
     * An implementation may choose to return itself.
     * <p>
     * This is intended for use where a {@link DataIn} instance must be passed to external code that only accepts a
     * traditional Java {@link InputStream}, and performance may benefit from not having all method calls be proxied
     * by a wrapper {@link DataIn} instance.
     *
     * @return an {@link InputStream} that may be used in place of this {@link DataIn} instance
     */
    public InputStream unwrap() {
        return this;
    }

    @Override
    public abstract void close() throws IOException;
}
