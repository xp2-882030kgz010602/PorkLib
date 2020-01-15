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

package net.daporkchop.lib.crypto.pork.stream;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import net.daporkchop.lib.crypto.cipher.stream.PStreamCipher;
import net.daporkchop.lib.crypto.generic.IHeapCipher;

/**
 * A simple implementation of the Salsa20 stream cipher algorithm.
 * <p>
 * Implemented based on <a href="https://en.wikipedia.org/wiki/Salsa20">the Wikipedia article</a>.
 *
 * @author DaPorkchop_
 */
public final class HeapSalsa20 implements PStreamCipher, IHeapCipher {
    protected static final int KEY_SIZE = 256 >>> 3;
    protected static final int NONCE_SIZE = 64 >>> 3;

    protected static void salsa20Block(@NonNull int[] src, @NonNull int[] dst) {
        int i00 = src[0];
        int i01 = src[1];
        int i02 = src[2];
        int i03 = src[3];
        int i04 = src[4];
        int i05 = src[5];
        int i06 = src[6];
        int i07 = src[7];
        int i08 = src[8];
        int i09 = src[9];
        int i10 = src[10];
        int i11 = src[11];
        int i12 = src[12];
        int i13 = src[13];
        int i14 = src[14];
        int i15 = src[15];

        for (int i = 0; i < 20; i += 2) {
            //column 1
            i04 ^= Integer.rotateLeft(i00 + i12, 7);
            i08 ^= Integer.rotateLeft(i04 + i00, 9);
            i12 ^= Integer.rotateLeft(i08 + i04, 13);
            i00 ^= Integer.rotateLeft(i12 + i08, 18);

            //column 2
            i09 ^= Integer.rotateLeft(i05 + i01, 7);
            i13 ^= Integer.rotateLeft(i09 + i05, 9);
            i01 ^= Integer.rotateLeft(i13 + i09, 13);
            i05 ^= Integer.rotateLeft(i01 + i13, 18);

            //column 3
            i14 ^= Integer.rotateLeft(i10 + i06, 7);
            i02 ^= Integer.rotateLeft(i14 + i10, 9);
            i06 ^= Integer.rotateLeft(i02 + i14, 13);
            i10 ^= Integer.rotateLeft(i06 + i02, 18);

            //column 4
            i03 ^= Integer.rotateLeft(i15 + i11, 7);
            i07 ^= Integer.rotateLeft(i03 + i15, 9);
            i11 ^= Integer.rotateLeft(i07 + i03, 13);
            i15 ^= Integer.rotateLeft(i11 + i07, 18);

            //row 1
            i01 ^= Integer.rotateLeft(i00 + i03, 7);
            i02 ^= Integer.rotateLeft(i01 + i00, 9);
            i03 ^= Integer.rotateLeft(i02 + i01, 13);
            i00 ^= Integer.rotateLeft(i03 + i02, 18);

            //row 2
            i06 ^= Integer.rotateLeft(i05 + i04, 7);
            i07 ^= Integer.rotateLeft(i06 + i05, 9);
            i04 ^= Integer.rotateLeft(i07 + i06, 13);
            i05 ^= Integer.rotateLeft(i04 + i07, 18);

            //row 3
            i11 ^= Integer.rotateLeft(i10 + i09, 7);
            i08 ^= Integer.rotateLeft(i11 + i10, 9);
            i09 ^= Integer.rotateLeft(i08 + i11, 13);
            i10 ^= Integer.rotateLeft(i09 + i08, 18);

            //row 4
            i12 ^= Integer.rotateLeft(i15 + i14, 7);
            i13 ^= Integer.rotateLeft(i12 + i15, 9);
            i14 ^= Integer.rotateLeft(i13 + i12, 13);
            i15 ^= Integer.rotateLeft(i14 + i13, 18);
        }

        dst[0] = i00 + src[0];
        dst[1] = i01 + src[1];
        dst[2] = i02 + src[2];
        dst[3] = i03 + src[3];
        dst[4] = i04 + src[4];
        dst[5] = i05 + src[5];
        dst[6] = i06 + src[6];
        dst[7] = i07 + src[7];
        dst[8] = i08 + src[8];
        dst[9] = i09 + src[9];
        dst[10] = i10 + src[10];
        dst[11] = i11 + src[11];
        dst[12] = i12 + src[12];
        dst[13] = i13 + src[13];
        dst[14] = i14 + src[14];
        dst[15] = i15 + src[15];
    }

    protected final int[] state = {
            'e' | ('x' << 8) | ('p' << 16) | ('a' << 24), 0, 0, 0,
            0, 'n' | ('d' << 8) | (' ' << 16) | ('3' << 24), 0, 0,
            0, 0, '2' | ('-' << 8) | ('b' << 16) | ('y' << 24), 0,
            0, 0, 0, 't' | ('e' << 8) | (' ' << 16) | ('k' << 24)
    };

    protected final int[] buf = new int[state.length];

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key) {
    }

    @Override
    public void init(boolean encrypt, @NonNull ByteBuf key, @NonNull ByteBuf iv) {
    }

    @Override
    public void process(@NonNull ByteBuf src, @NonNull ByteBuf dst) {
    }

    @Override
    public byte process(byte in) {
        return 0;
    }

    @Override
    public boolean flush(@NonNull ByteBuf dst) {
        return true;
    }

    @Override
    public String name() {
        return "Salsa20";
    }

    @Override
    public int[] keySizes() {
        return new int[]{KEY_SIZE};
    }

    @Override
    public int bestKeySize() {
        return KEY_SIZE;
    }

    @Override
    public boolean keySizeSupported(int size) {
        return size == KEY_SIZE;
    }

    @Override
    public boolean ivRequired() {
        return true;
    }

    @Override
    public int ivSize() {
        return NONCE_SIZE;
    }
}
