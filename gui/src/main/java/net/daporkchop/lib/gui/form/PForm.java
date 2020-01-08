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

package net.daporkchop.lib.gui.form;

import lombok.Getter;
import lombok.NonNull;
import net.daporkchop.lib.common.util.PorkUtil;
import net.daporkchop.lib.gui.component.Container;
import net.daporkchop.lib.gui.component.Element;
import net.daporkchop.lib.gui.component.type.functional.Button;
import net.daporkchop.lib.gui.form.data.FormObject;
import net.daporkchop.lib.gui.form.util.FormCompletionListener;
import net.daporkchop.lib.gui.form.util.FormCompletionStatus;
import net.daporkchop.lib.gui.form.util.exception.FormCompletionException;
import net.daporkchop.lib.unsafe.PUnsafe;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * @author DaPorkchop_
 */
@Getter
public class PForm<T> {
    protected static final Map<Class<?>, FormObject> OBJECT_CACHE = PorkUtil.newSoftCache();

    protected final Class<T>        clazz;
    protected final FormObject      base;
    protected final Container<?, ?> container;

    protected final Collection<FormCompletionListener<T>> listeners = new ArrayList<>();

    protected boolean built = false;

    public PForm(@NonNull Class<T> clazz, @NonNull Container container) {
        this.clazz = clazz;
        this.container = container;

        this.base = OBJECT_CACHE.computeIfAbsent(clazz, c -> new FormObject(c, null));
    }

    public synchronized PForm<T> buildDefault() {
        if (!this.built) {
            String last = this.base.buildDefault(null, this.container);
            if (last == null) {
                this.container.button("complete", button -> button
                        .orientRelative(0.1d, 0.1d, 0.8d, 0.1d)
                        .setText("Submit")
                        .minDimensionsAreValueSize()
                        .pad(10));
            } else {
                this.container.button("complete", button -> button
                        .orientAdvanced(adv -> adv.below(last).x(10))
                        .setText("Submit")
                        .minDimensionsAreValueSize()
                        .pad(10));
            }
            this.built = true;
        }
        return this.submitButton("complete");
    }

    public PForm<T> loadFrom(@NonNull T value)  {
        if (!this.built)    {
            throw new IllegalStateException("Form has not yet been built!");
        }
        this.base.loadFrom(value, this.container);
        return this;
    }

    public PForm<T> submitButton(@NonNull String name) {
        Element element = this.container.getChild(name);
        if (element == null) {
            throw new IllegalStateException(String.format("No element with name: \"%s\"!", name));
        } else if (element instanceof Button) {
            return this.submitButton((Button) element);
        } else {
            throw new IllegalStateException(String.format("Invalid component type for \"%s\": %s!", name, element.getClass().getCanonicalName()));
        }
    }

    public PForm<T> submitButton(@NonNull Button button) {
        button.setClickHandler((mouseButton, x, y) -> this.complete());
        return this;
    }

    public PForm<T> addSuccessListener(@NonNull Consumer<T> listener) {
        return this.addListener((status, value) -> {
            if (status == FormCompletionStatus.SUCCESS) {
                listener.accept(value);
            }
        });
    }

    public PForm<T> addCancelListener(@NonNull Runnable listener) {
        return this.addListener((status, value) -> {
            if (status == FormCompletionStatus.CANCELLED) {
                listener.run();
            }
        });
    }

    public PForm<T> addErrorListener(@NonNull Runnable listener) {
        return this.addListener((status, value) -> {
            if (status == FormCompletionStatus.ERROR) {
                listener.run();
            }
        });
    }

    public PForm<T> addListener(@NonNull BiConsumer<FormCompletionStatus, T> listener) {
        this.listeners.add(listener::accept);
        return this;
    }

    public PForm<T> addListener(@NonNull FormCompletionListener<T> listener) {
        this.listeners.add(listener);
        return this;
    }

    public PForm<T> prepare() {
        this.base.configure(this.container);
        return this;
    }

    public void cancel() {
        this.fireComplete(FormCompletionStatus.CANCELLED, null);
    }

    @SuppressWarnings("unchecked")
    public T complete() {
        T val;
        try {
            val = (T) PUnsafe.allocateInstance(this.clazz);
            this.base.loadInto(val, this.container);
        } catch (Exception e) {
            this.fireComplete(FormCompletionStatus.ERROR, null);
            throw new FormCompletionException(e);
        }
        this.fireComplete(FormCompletionStatus.SUCCESS, val);
        return val;
    }

    protected void fireComplete(@NonNull FormCompletionStatus status, T value) {
        this.listeners.forEach(listener -> listener.accept(status, value));
    }
}
