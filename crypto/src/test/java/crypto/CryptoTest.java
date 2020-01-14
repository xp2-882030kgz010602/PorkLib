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

package crypto;

import io.netty.buffer.Unpooled;
import net.daporkchop.lib.crypto.cipher.PCipher;
import net.daporkchop.lib.crypto.cipher.block.PPaddedBlockCipher;
import net.daporkchop.lib.crypto.bc.block.BouncyCastleAES;
import net.daporkchop.lib.crypto.generic.block.mode.HeapBlockModeCTR;
import net.daporkchop.lib.crypto.generic.block.padding.PKCS7Padding;
import net.daporkchop.lib.encoding.Hexadecimal;
import org.junit.Test;

/**
 * @author DaPorkchop_
 */
public class CryptoTest {
    @Test
    public void test()  {
        PCipher cipher = new PPaddedBlockCipher(new HeapBlockModeCTR(new BouncyCastleAES()), new PKCS7Padding());
        //cipher = new PBufferedBlockCipher(new BouncyCastleAES());

        System.out.println(cipher.name());

        final int blocks = 4;

        byte[] src = new byte[cipher.blockSize() * blocks - 5];
        byte[] dst = new byte[cipher.blockSize() * blocks];

        cipher.init(true, Unpooled.wrappedBuffer(new byte[cipher.bestKeySize()]));
        cipher.fullProcess(Unpooled.wrappedBuffer(src), Unpooled.wrappedBuffer(dst).clear());

        System.out.println(Hexadecimal.encode(src));
        System.out.println(Hexadecimal.encode(dst));
        System.out.println();

        src = dst;
        dst = new byte[src.length];
        cipher.init(false, Unpooled.wrappedBuffer(new byte[cipher.bestKeySize()]));
        cipher.fullProcess(Unpooled.wrappedBuffer(src), Unpooled.wrappedBuffer(dst).clear());

        System.out.println(Hexadecimal.encode(src));
        System.out.println(Hexadecimal.encode(dst));
    }
}
