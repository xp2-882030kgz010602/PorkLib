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

package net.daporkchop.lib.binary.serialization;

import lombok.NonNull;
import net.daporkchop.lib.binary.stream.DataIn;
import net.daporkchop.lib.binary.stream.DataOut;
import net.daporkchop.lib.common.function.io.IOBiConsumer;
import net.daporkchop.lib.common.function.io.IOFunction;

import java.io.IOException;

/**
 * A serializer can read and write objects to and from their binary representation
 *
 * @author DaPorkchop_
 */
public interface Serializer<T> {
    /**
     * Convenience method to define a serializer from a reader and writer function
     *
     * @param writer a function that can write an object. see {@link #write(Object, DataOut)}
     * @param reader a function that can read an object. see {@link #read(DataIn)}
     * @param <T>    the type of object that can be serialized
     * @return a new serializer that can serialize objects using the given reader and writer functions
     */
    static <T> Serializer<T> of(@NonNull IOBiConsumer<T, DataOut> writer, @NonNull IOFunction<DataIn, T> reader) {
        return new Serializer<T>() {
            @Override
            public void write(@NonNull T value, @NonNull DataOut out) throws IOException {
                writer.acceptThrowing(value, out);
            }

            @Override
            public T read(@NonNull DataIn in) throws IOException {
                return reader.applyThrowing(in);
            }
        };
    }

    /**
     * Writes (encodes) a value
     *
     * @param value the value to encode
     * @param out   a {@link DataOut} to write data to
     * @throws IOException if an IO exception occurs you dummy
     */
    void write(@NonNull T value, @NonNull DataOut out) throws IOException;

    /**
     * Reads (decodes) a value
     *
     * @param in a {@link DataIn} to read data from
     * @return the decoded value. must not be null!
     * @throws IOException if an IO exception occurs you dummy
     */
    T read(@NonNull DataIn in) throws IOException;
}
