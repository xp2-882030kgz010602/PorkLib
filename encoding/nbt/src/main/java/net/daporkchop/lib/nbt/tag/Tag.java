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

package net.daporkchop.lib.nbt.tag;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import net.daporkchop.lib.nbt.NBTInputStream;
import net.daporkchop.lib.nbt.NBTOutputStream;
import net.daporkchop.lib.nbt.tag.notch.CompoundTag;
import net.daporkchop.lib.nbt.tag.notch.ListTag;
import net.daporkchop.lib.unsafe.capability.Releasable;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;

import java.io.IOException;

/**
 * Represents an NBT tag.
 *
 * @author DaPorkchop_
 */
@RequiredArgsConstructor
@Getter
public abstract class Tag implements Releasable {
    /**
     * The name of this tag.
     * <p>
     * This will never be {@code null} unless this is an element of a {@link ListTag} or the root {@link CompoundTag}.
     */
    private final String name;

    /**
     * Gets and casts this tag to a specific tag type
     *
     * @param <T> the type to cast to
     * @return this tag casted to the given type
     */
    @SuppressWarnings("unchecked")
    public <T extends Tag> T getAs() {
        return (T) this;
    }

    /**
     * Gets this tag as a {@link CompoundTag}
     *
     * @return this tag as a {@link CompoundTag}
     */
    public CompoundTag getAsCompoundTag() {
        return this.getAs();
    }

    /**
     * Gets this tag as a {@link ListTag}
     *
     * @param <T> the type of tag contained in the list
     * @return this tag as a {@link ListTag}
     */
    public <T extends Tag> ListTag<T> getAsList() {
        return this.getAs();
    }

    /**
     * Reads this tag from a stream
     *
     * @param in       the input stream to read from
     * @param registry the registry of NBT tag ids
     * @throws IOException if an IO exception occurs you dummy
     */
    public abstract void read(@NonNull NBTInputStream in, @NonNull TagRegistry registry) throws IOException;

    /**
     * Writes this tag to a stream
     *
     * @param out      the output stream to write to
     * @param registry the registry of NBT tag ids
     * @throws IOException if an IO exception occurs you dummy
     */
    public abstract void write(@NonNull NBTOutputStream out, @NonNull TagRegistry registry) throws IOException;

    @Override
    public abstract String toString();

    /**
     * Releases this {@link Tag}, along with any children it may have.
     * <p>
     * This method is not required to be called, and tags should be able to be left for the garbage collector without any concern, however releasing
     * them manually may be beneficial for performance.
     *
     * @throws AlreadyReleasedException if this {@link Tag} was already released and the implementation of {@link #release()} is not no-op
     */
    @Override
    public void release() throws AlreadyReleasedException {
        //no-op
    }
}
