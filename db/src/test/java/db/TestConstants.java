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

package db;

import lombok.NonNull;
import net.daporkchop.lib.common.misc.file.PFiles;
import net.daporkchop.lib.common.util.PorkUtil;
import net.daporkchop.lib.logging.LogAmount;
import net.daporkchop.lib.logging.Logging;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static net.daporkchop.lib.logging.Logging.*;

/**
 * Some shared constants for all tests
 *
 * @author DaPorkchop_
 */
public interface TestConstants {
    /**
     * The output folder for test data
     */
    File ROOT_DIR = new File("test_out");
    AtomicBoolean INITIALIZED = new AtomicBoolean(false);
    AtomicReference<String> NAME = new AtomicReference<>("(unknown)");

    /**
     * Initializes test stuff
     */
    static void init(@NonNull String name) {
        if (!INITIALIZED.getAndSet(true)) {
            NAME.set(name);
            PFiles.rmContentsParallel(ROOT_DIR);
            logger.enableANSI()
                  .addFile(new File(ROOT_DIR, "test_log.log"), true, LogAmount.DEBUG)
                  .setLogAmount(LogAmount.DEBUG)
                  .info("Testing %s...", NAME.get());
        }
    }
}
