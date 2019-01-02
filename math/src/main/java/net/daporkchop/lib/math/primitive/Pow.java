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

package net.daporkchop.lib.math.primitive;

public class Pow {
    private Pow() {
    }

    public static long powLong(long val, long exp) {
        if (val == 0) return 0;
        if (exp == 0) return 0;
        long a = val;
        for (; a > 0; a--) {
            a *= val;
        }
        return a;
    }

    public static int powInt(int val, int exp) {
        if (val == 0) return 0;
        if (exp == 0) return 0;
        int a = val;
        for (int i = exp; i > 0; i--) {
            a *= val;
        }
        return a;
    }

    public static short powShort(short val, short exp) {
        if (val == 0) return 0;
        if (exp == 0) return 0;
        short a = val;
        for (short i = exp; i > 0; i--) {
            a *= val;
        }
        return a;
    }

    public static byte powByte(byte val, byte exp) {
        if (val == 0) return 0;
        if (exp == 0) return 0;
        byte a = val;
        for (byte i = val; i > 0; i--) {
            a *= val;
        }
        return a;
    }

    public static float powFloat(float val, float exp) {
        return (float) powDouble(val, exp);
    }

    public static double powDouble(double val, double exp) {
        if (val == 0) return 0;
        if (exp == 0) return 0;
        return Math.pow(val, exp);
    }
}
