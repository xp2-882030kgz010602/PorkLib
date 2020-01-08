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

package net.daporkchop.lib.gui.swing.impl;

import lombok.Getter;
import lombok.NonNull;
import net.daporkchop.lib.gui.component.Element;
import net.daporkchop.lib.gui.component.impl.AbstractElement;
import net.daporkchop.lib.gui.component.state.ElementState;
import net.daporkchop.lib.gui.swing.GuiEngineSwing;
import net.daporkchop.lib.gui.util.math.BoundingBox;
import net.daporkchop.lib.gui.util.math.Size;

import javax.swing.*;

/**
 * @author DaPorkchop_
 */
@Getter
public abstract class SwingElement<Impl extends Element, Swing extends java.awt.Component, State extends ElementState<? extends Element, State>> extends AbstractElement<Impl, State> {
    protected final Swing swing;

    public SwingElement(String name, Swing swing) {
        super(name);
        this.swing = swing;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Impl setVisible(boolean state) {
        if (Thread.currentThread().getClass() == GuiEngineSwing.EVENT_DISPATCH_THREAD) {
            if (state != this.swing.isVisible()) {
                this.swing.setVisible(state);
                this.fireStateChange();
            }
        } else {
            SwingUtilities.invokeLater(() -> this.setVisible(state));
        }
        return (Impl) this;
    }

    @Override
    public boolean isVisible() {
        return this.swing.isVisible();
    }
}
