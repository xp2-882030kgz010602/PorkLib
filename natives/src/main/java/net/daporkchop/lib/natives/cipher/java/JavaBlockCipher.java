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
import net.daporkchop.lib.natives.cipher.PBlockCipher;
import net.daporkchop.lib.unsafe.PUnsafe;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public class JavaBlockCipher extends JavaCipher implements PBlockCipher {
    protected static final long SECRETKEYSPEC_KEY_OFFSET = PUnsafe.pork_getOffset(SecretKeySpec.class, "key");
    protected static final long SECRETKEYSPEC_ALGORITHM_OFFSET = PUnsafe.pork_getOffset(SecretKeySpec.class, "algorithm");
    protected static final long IVPARAMETERSPEC_IV_OFFSET = PUnsafe.pork_getOffset(IvParameterSpec.class, "iv");

    protected static final Map<String, Integer> KEY_SIZES = Collections.synchronizedMap(new HashMap<>());

    protected final SecretKeySpec key;
    protected final IvParameterSpec iv;

    public JavaBlockCipher(@NonNull Cipher cipher, @NonNull String name) {
        super(cipher, name);

        this.key = PUnsafe.allocateInstance(SecretKeySpec.class);
        PUnsafe.putObject(this.key, SECRETKEYSPEC_KEY_OFFSET, new byte[this.keySize()]);
        PUnsafe.putObject(this.key, SECRETKEYSPEC_ALGORITHM_OFFSET, name);

        this.iv = PUnsafe.allocateInstance(IvParameterSpec.class);
        PUnsafe.putObject(this.iv, IVPARAMETERSPEC_IV_OFFSET, new byte[this.ivSize()]);
    }

    @Override
    public int keySize() {
        //TODO: this is dumb
        return KEY_SIZES.computeIfAbsent(this.name, name -> {
            try {
                return KeyGenerator.getInstance(name).generateKey().getEncoded().length;
            } catch (NoSuchAlgorithmException e)    {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public int ivSize() {
        return this.keySize();
    }

    @Override
    public int blockSize() {
        return this.cipher.getBlockSize();
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key, ByteBuf iv) {
        if (iv == null) {
            throw new IllegalArgumentException("IV is required!");
        }

        byte[] keyArray = PUnsafe.getObject(this.key, SECRETKEYSPEC_KEY_OFFSET);
        if (key.readableBytes() != keyArray.length) {
            throw new IllegalArgumentException(String.format("Key must be %d bytes! Given: %d", keyArray.length, key.readableBytes()));
        }
        byte[] ivArray = PUnsafe.getObject(this.iv, IVPARAMETERSPEC_IV_OFFSET);
        if (iv.readableBytes() != ivArray.length) {
            throw new IllegalArgumentException(String.format("IV must be %d bytes! Given: %d", ivArray.length, iv.readableBytes()));
        }

        key.readBytes(keyArray);
        iv.readBytes(ivArray);
        try {
            this.cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, this.key, this.iv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e)    {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int process(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        return 0;
    }

    @Override
    public void finish(@NonNull ByteBuf dst) {
    }
}
