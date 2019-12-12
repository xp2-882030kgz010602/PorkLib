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

package net.daporkchop.lib.crypto.impl.java.cipher;

import io.netty.buffer.ByteBuf;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.Accessors;
import net.daporkchop.lib.common.util.PorkUtil;
import net.daporkchop.lib.crypto.PCrypto;
import net.daporkchop.lib.crypto.cipher.PBlockCipher;
import net.daporkchop.lib.unsafe.PUnsafe;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * @author DaPorkchop_
 */
@Accessors(fluent = true)
public class JavaBlockCipher implements PBlockCipher {
    protected static final long SECRETKEYSPEC_KEY_OFFSET = PUnsafe.pork_getOffset(SecretKeySpec.class, "key");
    protected static final long SECRETKEYSPEC_ALGORITHM_OFFSET = PUnsafe.pork_getOffset(SecretKeySpec.class, "algorithm");
    protected static final long IVPARAMETERSPEC_IV_OFFSET = PUnsafe.pork_getOffset(IvParameterSpec.class, "iv");

    @Getter
    protected final PCrypto alg;
    protected final Cipher cipher;

    protected final ByteBuffer buf;

    protected final SecretKeySpec keySpec;
    protected final IvParameterSpec param;

    public JavaBlockCipher(@NonNull Cipher cipher, @NonNull PCrypto alg)    {
        this.cipher = cipher;
        this.alg = alg;

        this.buf = ByteBuffer.allocateDirect(this.blockSize());

        this.keySpec = PUnsafe.allocateInstance(SecretKeySpec.class);
        PUnsafe.putObject(this.keySpec, SECRETKEYSPEC_ALGORITHM_OFFSET, alg.name());

        this.param = PUnsafe.allocateInstance(IvParameterSpec.class);
    }

    @Override
    public int blockSize() {
        return this.cipher.getBlockSize();
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key, ByteBuf iv) {
        int keyLen = key.readableBytes();
        {
            byte[] keyArr = PUnsafe.getObject(this.keySpec, SECRETKEYSPEC_KEY_OFFSET);
            if (keyArr == null || keyArr.length != keyLen) {
                PUnsafe.putObject(this.keySpec, SECRETKEYSPEC_KEY_OFFSET, keyArr = new byte[keyLen]);
            }
            key.readBytes(keyArr);
        }
        {
            byte[] ivArr = PUnsafe.getObject(this.param, IVPARAMETERSPEC_IV_OFFSET);
            if (iv == null) {
                if (ivArr == null || ivArr.length != keyLen)  {
                    PUnsafe.putObject(this.param, IVPARAMETERSPEC_IV_OFFSET, ivArr = new byte[keyLen]);
                } else {
                    Arrays.fill(ivArr, (byte) 0);
                }
            } else {
                if (ivArr == null || ivArr.length != iv.readableBytes())    {
                    PUnsafe.putObject(this.param, IVPARAMETERSPEC_IV_OFFSET, ivArr = new byte[iv.readableBytes()]);
                }
                iv.readBytes(ivArr);
            }
        }
        try {
            this.cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, this.keySpec, this.param);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e)    {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void processBlock(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        if (src.readableBytes() < this.blockSize()) {
            throw new IllegalArgumentException(String.format("Must have at least %d bytes readable! (found: %d)", this.blockSize(), src.readableBytes()));
        }
        dst.ensureWritable(this.blockSize());

        this.buf.clear();
        src.readBytes(this.buf);
        this.buf.clear();
        try {
            this.cipher.update(this.buf, this.buf);
        } catch (ShortBufferException e)    {
            throw new RuntimeException(e);
        }
        this.buf.clear();
        dst.writeBytes(this.buf);
    }

    @Override
    public void processBlocks(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        int blockSize = this.blockSize();
        if (src.readableBytes() % blockSize != 0) {
            throw new IllegalArgumentException(String.format("src buffers must be a multiple of block size! (src=%d,block size=%d)", src.readableBytes(), blockSize));
        }
        dst.ensureWritable(src.readableBytes());
        try {
            this.cipher.update(src.nioBuffer(), dst.nioBuffer());
        } catch (ShortBufferException e)    {
            throw new RuntimeException(e);
        }
    }

    @Override
    public long processedSize(long inputSize) {
        if (inputSize % this.blockSize() == 0) {
            return inputSize;
        } else {
            throw new IllegalArgumentException(String.format("Input size must be a multiple of %d bytes!", this.blockSize()));
        }
    }

    @Override
    public void release() throws AlreadyReleasedException {
        PorkUtil.release(this.buf);
    }
}
