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

import lombok.NonNull;
import net.daporkchop.lib.natives.NativeCode;
import net.daporkchop.lib.natives.cipher.CipherProvider;
import net.daporkchop.lib.natives.cipher.PCipher;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

/**
 * Implementation of {@link CipherProvider} using Java's built-in crypto APIs.
 *
 * @author DaPorkchop_
 */
public final class JavaCipherProvider extends NativeCode.Impl<CipherProvider> implements CipherProvider {
    @Override
    protected CipherProvider _get() {
        return this;
    }

    @Override
    protected boolean _available() {
        return true;
    }

    @Override
    public PCipher create(@NonNull String name) throws IllegalArgumentException {
        try {
            Cipher cipher = Cipher.getInstance(name);

            return new JavaBlockCipher(cipher, name);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e)   {
            throw new IllegalArgumentException(name, e);
        }
    }
}
