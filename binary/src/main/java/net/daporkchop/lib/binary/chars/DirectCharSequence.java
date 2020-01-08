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

package net.daporkchop.lib.binary.chars;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import net.daporkchop.lib.common.util.PorkUtil;
import net.daporkchop.lib.unsafe.PUnsafe;

/**
 * A wrapper around a direct memory address to allow it to be used as a {@link CharSequence} of 2-byte characters (aka. UTF-16, just like a normal Java
 * {@link String}).
 *
 * @author DaPorkchop_
 */
@RequiredArgsConstructor
@Getter
@Accessors(fluent = true)
public final class DirectCharSequence implements CharSequence {
    private final long addr;
    private final int  length;

    @Override
    public char charAt(int index) {
        if (index < 0 || index >= this.length) {
            throw new StringIndexOutOfBoundsException(index);
        }
        return PUnsafe.getChar(this.addr + index * PUnsafe.ARRAY_CHAR_INDEX_SCALE);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        PorkUtil.assertInRange(this.length, start, end);
        return start == 0 && end == this.length ? this : new DirectCharSequence(this.addr + start * PUnsafe.ARRAY_CHAR_INDEX_SCALE, end - start);
    }

    @Override
    public int hashCode() {
        int i = 0;
        for (long addr = this.addr, end = addr + this.length * PUnsafe.ARRAY_CHAR_INDEX_SCALE; addr != end; addr += PUnsafe.ARRAY_CHAR_INDEX_SCALE) {
            i = i * 31 + PUnsafe.getChar(addr);
        }
        return i;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        } else if (obj instanceof CharSequence) {
            CharSequence seq = (CharSequence) obj;
            final long addr = this.addr;
            final int len = this.length;
            if (seq.length() != len) {
                return false;
            }
            int i = 0;
            while (i < len && PUnsafe.getChar(addr + i * PUnsafe.ARRAY_CHAR_INDEX_SCALE) == seq.charAt(i)) {
                i++;
            }
            return i == len;
        } else {
            return false;
        }
    }

    @Override
    public String toString() {
        final int len = this.length;
        char[] arr = new char[len];
        PUnsafe.copyMemory(null, this.addr, arr, PUnsafe.ARRAY_CHAR_BASE_OFFSET, len * PUnsafe.ARRAY_CHAR_INDEX_SCALE);
        return PorkUtil.wrap(arr);
    }
}
