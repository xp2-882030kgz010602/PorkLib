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

package net.daporkchop.lib.natives.cipher.java;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import lombok.experimental.Accessors;
import net.daporkchop.lib.natives.cipher.PCipher;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;

import javax.crypto.Cipher;

/**
 * Abstract representation of a {@link PCipher} backed by a Java
 *
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public abstract class JavaCipher implements PCipher {
    protected final Cipher cipher;

    @NonNull
    protected final String name;

    public JavaCipher(@NonNull Cipher cipher, @NonNull String name) {
        this.cipher = cipher;
        this.name = name;
    }

    @Override
    public String name() {
        return null;
    }

    @Override
    public int keySize() {
        return 0;
    }

    @Override
    public int ivSize() {
        return 0;
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key, ByteBuf iv) {

    }

    @Override
    public long processedSize(long inputSize) {
        if (inputSize < 0L) {
            throw new IllegalArgumentException("inputSize may not be negative!");
        } else if (inputSize > Integer.MAX_VALUE)   {
            throw new IllegalArgumentException("Java cipher does not support computing processed size for more than Integer.MAX_VALUE!");
        }
        return this.cipher.getOutputSize((int) inputSize);
    }

    @Override
    public void release() throws AlreadyReleasedException {

    }
}
