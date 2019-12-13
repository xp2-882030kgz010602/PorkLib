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

package crypto;

import io.netty.buffer.Unpooled;
import net.daporkchop.lib.crypto.alg.PBlockCipherAlg;
import net.daporkchop.lib.crypto.cipher.PBlockCipher;
import net.daporkchop.lib.crypto.cipher.PCipher;
import net.daporkchop.lib.crypto.impl.bc.algo.BouncyCastleAES;
import net.daporkchop.lib.crypto.key.PKey;
import net.daporkchop.lib.encoding.Hexadecimal;
import org.junit.Test;

/**
 * @author DaPorkchop_
 */
public class CryptoTest {
    @Test
    public void test()  {
        PBlockCipherAlg alg = BouncyCastleAES.INSTANCE;
        byte[] srcData = new byte[alg.blockSize() << 2];
        byte[] dstData = new byte[srcData.length];
        PKey key = alg.keyGen().size(256 >>> 3).generate();
        try (PBlockCipher cipher = alg.cipher())    {
            cipher.init(true, key);
            cipher.processBlocks(Unpooled.wrappedBuffer(srcData), Unpooled.wrappedBuffer(dstData).clear());
        }

        System.out.println(Hexadecimal.encode(srcData));
        System.out.println(Hexadecimal.encode(dstData));

        System.arraycopy(dstData, 0, srcData, 0, srcData.length);

        try (PBlockCipher cipher = alg.cipher())    {
            cipher.init(false, key);
            cipher.processBlocks(Unpooled.wrappedBuffer(srcData), Unpooled.wrappedBuffer(dstData).clear());
        }

        System.out.println(Hexadecimal.encode(srcData));
        System.out.println(Hexadecimal.encode(dstData));
    }
}
