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

package net.daporkchop.lib.nbt.tag.notch;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import net.daporkchop.lib.nbt.NBTInputStream;
import net.daporkchop.lib.nbt.NBTOutputStream;
import net.daporkchop.lib.nbt.tag.Tag;
import net.daporkchop.lib.nbt.tag.TagRegistry;

import java.io.IOException;

/**
 * A tag that contains a single long[]
 *
 * @author DaPorkchop_
 */
@Getter
@Setter
public class LongArrayTag extends Tag {
    @NonNull
    protected long[] value;

    public LongArrayTag(String name) {
        super(name);
    }

    public LongArrayTag(String name, @NonNull long[] value) {
        super(name);
        this.value = value;
    }

    @Override
    public void read(@NonNull NBTInputStream in, @NonNull TagRegistry registry) throws IOException {
        final int length = in.readInt();
        final long[] value = this.value = new long[length];
        for (int i = 0; i < length; i++) {
            value[i] = in.readLong();
        }
    }

    @Override
    public void write(@NonNull NBTOutputStream out, @NonNull TagRegistry registry) throws IOException {
        final long[] value = this.value;
        final int length = value.length;
        out.writeInt(length);
        for (int i = 0; i < length; i++) {
            out.writeLong(value[i]);
        }
    }

    @Override
    public String toString() {
        return String.format("LongArrayTag(\"%s\"): %d longs", this.getName(), this.value.length);
    }
}
