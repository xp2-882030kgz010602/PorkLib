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

package net.daporkchop.lib.unsafe.block;

import lombok.NonNull;
import net.daporkchop.lib.unsafe.PUnsafe;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;

/**
 * @author DaPorkchop_
 */
public class ArrayMemoryBlock implements MemoryBlock {
    protected       Object array;
    protected final long   offset;
    protected final long   size;

    public ArrayMemoryBlock(@NonNull Object array) {
        Class<?> clazz = array.getClass();
        if (!clazz.isArray()) {
            throw new IllegalArgumentException(String.format("Not an array: %s", clazz.getCanonicalName()));
        }
        if (clazz == byte[].class) {
            this.offset = PUnsafe.ARRAY_BYTE_BASE_OFFSET;
            this.size = ((byte[]) array).length * PUnsafe.ARRAY_BYTE_INDEX_SCALE;
        } else if (clazz == short[].class) {
            this.offset = PUnsafe.ARRAY_SHORT_BASE_OFFSET;
            this.size = ((short[]) array).length * PUnsafe.ARRAY_SHORT_INDEX_SCALE;
        } else if (clazz == int[].class) {
            this.offset = PUnsafe.ARRAY_INT_BASE_OFFSET;
            this.size = ((int[]) array).length * PUnsafe.ARRAY_INT_INDEX_SCALE;
        } else if (clazz == long[].class) {
            this.offset = PUnsafe.ARRAY_LONG_BASE_OFFSET;
            this.size = ((long[]) array).length * PUnsafe.ARRAY_LONG_INDEX_SCALE;
        } else if (clazz == float[].class) {
            this.offset = PUnsafe.ARRAY_FLOAT_BASE_OFFSET;
            this.size = ((float[]) array).length * PUnsafe.ARRAY_FLOAT_INDEX_SCALE;
        } else if (clazz == double[].class) {
            this.offset = PUnsafe.ARRAY_DOUBLE_BASE_OFFSET;
            this.size = ((double[]) array).length * PUnsafe.ARRAY_DOUBLE_INDEX_SCALE;
        } else if (clazz == char[].class) {
            this.offset = PUnsafe.ARRAY_CHAR_BASE_OFFSET;
            this.size = ((char[]) array).length * PUnsafe.ARRAY_CHAR_INDEX_SCALE;
        } else {
            throw new IllegalArgumentException(String.format("Not a primitive array: %s", clazz.getCanonicalName()));
        }
        this.array = array;
    }

    @Override
    public Object memoryRef() {
        return this.array;
    }

    @Override
    public long memoryOff() {
        return this.offset;
    }

    @Override
    public long memorySize() {
        return this.size;
    }

    @Override
    public synchronized void release() throws AlreadyReleasedException {
        if (this.array == null) {
            throw new AlreadyReleasedException();
        }
        this.array = null;
    }

    @Override
    public byte getByte(long index) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            return PUnsafe.getByte(this.array, this.offset + index);
        }
    }

    @Override
    public short getShort(long index) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 1L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            return PUnsafe.getShort(this.array, this.offset + index);
        }
    }

    @Override
    public int getInt(long index) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 3L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            return PUnsafe.getInt(this.array, this.offset + index);
        }
    }

    @Override
    public long getLong(long index) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 7L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            return PUnsafe.getLong(this.array, this.offset + index);
        }
    }

    @Override
    public float getFloat(long index) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 3L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            return PUnsafe.getFloat(this.array, this.offset + index);
        }
    }

    @Override
    public double getDouble(long index) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 7L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            return PUnsafe.getDouble(this.array, this.offset + index);
        }
    }

    @Override
    public char getChar(long index) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 1L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            return PUnsafe.getChar(this.array, this.offset + index);
        }
    }

    @Override
    public void getBytes(long index, @NonNull byte[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + len > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(this.array, this.offset, arr, PUnsafe.ARRAY_BYTE_BASE_OFFSET + off, len);
        }
    }

    @Override
    public void getShorts(long index, @NonNull short[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 1L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(this.array, this.offset, arr, PUnsafe.ARRAY_SHORT_BASE_OFFSET + (off << 1L), len << 1L);
        }
    }

    @Override
    public void getInts(long index, @NonNull int[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 2L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(this.array, this.offset, arr, PUnsafe.ARRAY_INT_BASE_OFFSET + (off << 2L), len << 2L);
        }
    }

    @Override
    public void getLongs(long index, @NonNull long[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 3L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(this.array, this.offset, arr, PUnsafe.ARRAY_LONG_BASE_OFFSET + (off << 3L), len << 3L);
        }
    }

    @Override
    public void getFloats(long index, @NonNull float[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 2L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(this.array, this.offset, arr, PUnsafe.ARRAY_FLOAT_BASE_OFFSET + (off << 2L), len << 2L);
        }
    }

    @Override
    public void getDoubles(long index, @NonNull double[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 3L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(this.array, this.offset, arr, PUnsafe.ARRAY_DOUBLE_BASE_OFFSET + (off << 3L), len << 3L);
        }
    }

    @Override
    public void getChars(long index, @NonNull char[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 1L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(this.array, this.offset, arr, PUnsafe.ARRAY_CHAR_BASE_OFFSET + (off << 1L), len << 1L);
        }
    }

    @Override
    public void setByte(long index, byte val) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            PUnsafe.putByte(this.array, this.offset + index, val);
        }
    }

    @Override
    public void setShort(long index, short val) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 1L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            PUnsafe.putShort(this.array, this.offset + index, val);
        }
    }

    @Override
    public void setInt(long index, int val) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 3L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            PUnsafe.putInt(this.array, this.offset + index, val);
        }
    }

    @Override
    public void setLong(long index, long val) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 7L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            PUnsafe.putLong(this.array, this.offset + index, val);
        }
    }

    @Override
    public void setFloat(long index, float val) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 3L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            PUnsafe.putFloat(this.array, this.offset + index, val);
        }
    }

    @Override
    public void setDouble(long index, double val) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 7L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            PUnsafe.putDouble(this.array, this.offset + index, val);
        }
    }

    @Override
    public void setChar(long index, char val) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + 1L > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else {
            PUnsafe.putChar(this.array, this.offset + index, val);
        }
    }

    @Override
    public void setBytes(long index, @NonNull byte[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + len > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(arr, PUnsafe.ARRAY_BYTE_BASE_OFFSET + off, this.array, this.offset, len);
        }
    }

    @Override
    public void setShorts(long index, @NonNull short[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 1L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(arr, PUnsafe.ARRAY_SHORT_BASE_OFFSET + (off << 1L), this.array, this.offset, len << 1L);
        }
    }

    @Override
    public void setInts(long index, @NonNull int[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 2L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(arr, PUnsafe.ARRAY_INT_BASE_OFFSET + (off << 2L), this.array, this.offset, len << 2L);
        }
    }

    @Override
    public void setLongs(long index, @NonNull long[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 3L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(arr, PUnsafe.ARRAY_LONG_BASE_OFFSET + (off << 3L), this.array, this.offset, len << 3L);
        }
    }

    @Override
    public void setFloats(long index, @NonNull float[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 2L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(arr, PUnsafe.ARRAY_FLOAT_BASE_OFFSET + (off << 2L), this.array, this.offset, len << 2L);
        }
    }

    @Override
    public void setDoubles(long index, @NonNull double[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 3L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(arr, PUnsafe.ARRAY_DOUBLE_BASE_OFFSET + (off << 3L), this.array, this.offset, len << 3L);
        }
    }

    @Override
    public void setChars(long index, @NonNull char[] arr, int off, int len) {
        if (this.array == null) {
            throw new IllegalStateException("Already freed!");
        } else if (index < 0L || index + (len << 1L) > this.size) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal index: %d (must be in range 0-%d)", index, this.size));
        } else if (off < 0 || off + len > arr.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("Illegal offset/length: off=%d,length=%d for array length %d", off, len, arr.length));
        } else {
            PUnsafe.copyMemory(arr, PUnsafe.ARRAY_CHAR_BASE_OFFSET + (off << 1L), this.array, this.offset, len << 1L);
        }
    }

    @Override
    public void clear() {
        PUnsafe.setMemory(this.array, this.offset, this.size, (byte) 0);
    }
}
