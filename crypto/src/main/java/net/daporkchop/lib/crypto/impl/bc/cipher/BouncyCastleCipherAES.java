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

package net.daporkchop.lib.crypto.impl.bc.cipher;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import net.daporkchop.lib.crypto.alg.PBlockCipherAlg;
import net.daporkchop.lib.crypto.cipher.PBlockCipher;
import net.daporkchop.lib.crypto.impl.bc.algo.BouncyCastleAES;
import net.daporkchop.lib.crypto.key.PKey;
import net.daporkchop.lib.unsafe.util.exception.AlreadyReleasedException;
import org.bouncycastle.crypto.engines.AESEngine;

/**
 * @author DaPorkchop_
 */
public final class BouncyCastleCipherAES implements PBlockCipher {
    protected final AESEngine engine = new AESEngine();
    protected final byte[] buffer = new byte[(128 >>> 3) << 1];

    @Override
    public PBlockCipherAlg alg() {
        return BouncyCastleAES.INSTANCE;
    }

    @Override
    public void init(boolean encrypt, @NonNull PKey key) {
        if (key instanceof BouncyCastleAES.Key) {
            this.engine.init(encrypt, (BouncyCastleAES.Key) key);
        } else {
            throw new IllegalArgumentException(key.getClass().getCanonicalName());
        }
    }

    @Override
    public void processBlock(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
        if (src.readableBytes() < (128 >>> 3))  {
            throw new IllegalArgumentException(String.format("Source buffer only has %d bytes readable (required: %d)", src.readableBytes(), 128 >>> 3));
        }
        dst.ensureWritable(128 >>> 3);

        byte[] srcArray;
        int srcArrayOffset;
        if (src.hasArray()) {
            srcArray = src.array();
            srcArrayOffset = src.arrayOffset() + src.readerIndex();
            src.skipBytes(128 >>> 3);
        } else {
            src.readBytes(srcArray = this.buffer, srcArrayOffset = 0, 128 >>> 3);
        }

        byte[] dstArray;
        int dstArrayOffset;
        if (dst.hasArray()) {
            dstArray = dst.array();
            dstArrayOffset = dst.arrayOffset() + dst.writerIndex();
        } else {
            dstArray = this.buffer;
            dstArrayOffset = 128 >>> 3;
        }

        this.engine.processBlock(srcArray, srcArrayOffset, dstArray, dstArrayOffset);

        if (dst.hasArray()) {
            //increase writer index
            dst.writerIndex(dst.writerIndex() + (128 >>> 3));
        } else {
            //copy encrypted bytes into destination buffer
            dst.writeBytes(dstArray, dstArrayOffset, 128 >>> 3);
        }
    }

    @Override
    public void release() throws AlreadyReleasedException {
        //no-op
    }
}
