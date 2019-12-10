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

package net.daporkchop.lib.natives;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.Accessors;
import net.daporkchop.lib.common.system.Architecture;
import net.daporkchop.lib.common.system.OperatingSystem;
import net.daporkchop.lib.common.system.PlatformInfo;
import net.daporkchop.lib.unsafe.PUnsafe;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.function.Supplier;

/**
 * A wrapper around multiple distinct implementations of something.
 *
 * @param <T> the type of the feature to be implemented
 * @author DaPorkchop_
 */
public final class NativeCode<T> implements Supplier<T> {
    private static final String LIB_ARCH;
    private static final String LIB_EXT;

    private static final Collection<String> LOADED_LIBS = Collections.synchronizedCollection(new ArrayList<>());

    static {
        String arch = null;
        String ext = null;

        switch (PlatformInfo.OPERATING_SYSTEM) {
            case Linux:
                ext = "so";
                switch (PlatformInfo.ARCHITECTURE) {
                    case x86_64:
                        arch = "x86_64-linux-gnu";
                        break;
                    case x86:
                        arch = "x86-linux-gnu";
                        break;
                }
                break;
            case Windows:
                ext = "dll";
                if (PlatformInfo.ARCHITECTURE == Architecture.x86_64) {
                    arch = "x86_64-w64-mingw32";
                }
                break;
        }

        LIB_ARCH = arch;
        LIB_EXT = ext;
    }

    public synchronized static boolean loadNativeLibrary(@NonNull String libname) {
        if (LOADED_LIBS.contains(libname))  {
            return true;
        }

        String libPath = getLibraryPath(libname);
        if (libPath == null)    {
            //throw new IllegalStateException(String.format("native libraries are not supported on %s:%s", PlatformInfo.OPERATING_SYSTEM, PlatformInfo.ARCHITECTURE));
            return false;
        }

        try (InputStream in = NativeCode.class.getResourceAsStream(libPath))    {
            if (in == null) {
                return false;
            }

            File file = File.createTempFile(String.format("%s-%s-", libname, LIB_ARCH), String.format(".%s", LIB_EXT));
            file.deleteOnExit();

            try (OutputStream out = new FileOutputStream(file)) {
                byte[] arr = new byte[PUnsafe.pageSize()];
                for (int b; (b = in.read(arr)) >= 0; out.write(arr, 0, b)) ;
            }
            System.load(file.getAbsolutePath());
            LOADED_LIBS.add(libname);
            return true;
        } catch (Exception e) {
            throw new RuntimeException(String.format("Unable to load library \"%s\"", libname), e);
        }
    }

    public static String getLibraryPath(@NonNull String libname) {
        return LIB_ARCH != null && LIB_EXT != null ? String.format("/%s/lib%s.%s", LIB_ARCH, libname, LIB_EXT) : null;
    }

    private Supplier<Impl<T>>[] implementations;
    private Impl<T> implementation;

    @SafeVarargs
    public NativeCode(@NonNull Supplier<Impl<T>>... implementations) {
        this.implementations = implementations;

        for (Supplier<Impl<T>> implementationFactory : implementations) {
            Impl<T> implementation = implementationFactory.get();
            if (implementation.available()) {
                this.implementation = implementation;
                return;
            }
        }

    }

    @Override
    public T get() {
        if (this.implementations != null) {
            synchronized (this) {
                if (this.implementations != null) {
                    for (Supplier<Impl<T>> implementationFactory : this.implementations) {
                        Impl<T> implementation = implementationFactory.get();
                        if (implementation.available()) {
                            this.implementation = implementation;
                            break;
                        }
                    }

                    this.implementations = null;
                }
            }
        }

        if (this.implementation != null) {
            return this.implementation.get();
        } else {
            throw new IllegalStateException("No implementations found!");
        }
    }

    /**
     * @return whether or not the currently used implementation is based on native code
     */
    public boolean isNative() {
        return this.get() instanceof NativeImpl;
    }

    /**
     * An implementation for use by {@link NativeCode}.
     *
     * @param <T> the type of the feature to be implemented
     * @author DaPorkchop_
     */
    @Getter
    @Accessors(fluent = true)
    public static abstract class Impl<T> implements Supplier<T> {
        protected final boolean available = this._available();

        @Override
        public T get() {
            if (this.available) {
                return this._get();
            } else {
                throw new IllegalStateException("Not available!");
            }
        }

        protected abstract T _get();

        protected abstract boolean _available();
    }

    /**
     * Extension of {@link Impl} for use by implementations that actually use native code.
     *
     * @param <T> the type of the feature to be implemented
     * @author DaPorkchop_
     */
    public static abstract class NativeImpl<T> extends Impl<T> {
    }
}
