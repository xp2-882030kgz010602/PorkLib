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

package net.daporkchop.lib.natives.cipher;

import io.netty.buffer.ByteBuf;
import lombok.NonNull;
import net.daporkchop.lib.unsafe.capability.Releasable;

/**
 * Base representation of a cipher.
 * <p>
 * Implementations are not expected to be thread-safe, and may produce unexpected behavior if used from multiple threads.
 *
 * @author DaPorkchop_
 */
public interface PCipher extends Releasable {
    /**
     * Gets this cipher's textual name.
     * <p>
     * Example: {@code AES/CTR/NoPadding}
     *
     * @return this cipher's textual name
     */
    String name();

    /**
     * Processes the given bytes.
     *
     * @param src the {@link ByteBuf} from which to read data
     * @param dst the {@link ByteBuf} to which to write data
     */
    void process(@NonNull ByteBuf src, @NonNull ByteBuf dst);

    /**
     * Resets this cipher to its original state, allowing it to be re-used with different initialization parameters.
     */
    void reset();
}
