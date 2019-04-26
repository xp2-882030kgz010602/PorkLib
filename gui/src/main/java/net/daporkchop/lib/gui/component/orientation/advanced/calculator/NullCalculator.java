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

package net.daporkchop.lib.gui.component.orientation.advanced.calculator;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import net.daporkchop.lib.gui.component.Component;
import net.daporkchop.lib.gui.component.Container;
import net.daporkchop.lib.gui.component.orientation.advanced.Calculator;
import net.daporkchop.lib.gui.util.math.BoundingBox;

/**
 * @author DaPorkchop_
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class NullCalculator<T extends Component> implements Calculator<T> {
    private static final NullCalculator INSTANCE = new NullCalculator();

    @SuppressWarnings("unchecked")
    public static <T extends Component> NullCalculator<T> getInstance() {
        return (NullCalculator<T>) INSTANCE;
    }

    @SuppressWarnings("unchecked")
    public static <T extends Component> Calculator<T>[] getBaseArray() {
        return (Calculator<T>[]) new Calculator[] {
                getInstance(), getInstance(), getInstance(), getInstance()
        };
    }

    @Override
    public int get(BoundingBox bb, Container parent, T component, int[] dims) {
        return 0;
    }
}