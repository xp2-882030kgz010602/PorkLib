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

package gui;

import lombok.NonNull;
import lombok.ToString;
import net.daporkchop.lib.gui.component.type.Window;
import net.daporkchop.lib.gui.form.annotation.FormComponentName;
import net.daporkchop.lib.gui.form.annotation.FormDefaultDimensions;
import net.daporkchop.lib.gui.form.annotation.FormDisplayName;
import net.daporkchop.lib.gui.form.annotation.FormTooltip;
import net.daporkchop.lib.gui.form.annotation.FormType;
import net.daporkchop.lib.gui.util.ScrollCondition;
import net.daporkchop.lib.logging.Logging;

import static net.daporkchop.lib.logging.Logging.*;

/**
 * @author DaPorkchop_
 */
public class FormExample {
    public static void displayForm(@NonNull Window parentWindow) {
        parentWindow.popup(128, 128, 512, 300)
                .setTitle("Form test")
                .scrollPane("scrollpane", scrollPane -> scrollPane
                        .setScrolling(ScrollCondition.AUTO)
                        .orientRelative(0, 0, 1.0d, 1.0d)
                        .form(FormData.class)
                        .addListener((status, value) -> logger.info("Form completed with status: %s", status))
                        .addSuccessListener(value -> logger.info("%s", value)))
                .show();
    }

    @ToString
    protected static class FormData {
        @FormType.Int(value = 27, max = 9001)
        @FormTooltip({
                "This value can be configured with a spinner.",
                "It may be set to at most 9001 and at least 0, and has a step size of 1."
        })
        public int spinner;

        @FormType.Int(50)
        @FormTooltip({
                "This is also a spinner, initialized by default to 50.\nIt's component is named differently than it's field."
        })
        @FormComponentName("spinner2")
        public int otherSpinner;

        @FormType.Int(type = FormType.Int.Type.SLIDER)
        @FormTooltip({
                "Sliders can be more useful than spinners in many cases!"
        })
        public int slider;

        @FormType.Object(type = FormType.Object.Type.PANEL)
        public SubData sub; //TODO: we really, really need a way to have containers scale to their contents
        //TODO-amendment: ScrollPane seems to be able to do this correctly automatically, let's see how it does it (and do it correctly)

        @FormType.Text(hint = "user@example.com")
        @FormDefaultDimensions(dWidth = 0.25d)
        @FormTooltip("Your username to this amazing non-existent site!")
        @FormDisplayName("Username")
        public String username;

        @FormType.Text(type = FormType.Text.Type.PASSWORD)
        @FormDefaultDimensions(dWidth = 0.25d)
        @FormTooltip("Your password to this amazing non-existent site!")
        public String password;
    }

    @ToString
    protected static class SubData {
        @FormTooltip("This is a simple boolean value.")
        @FormComponentName("checkbox")
        public boolean flag;

        @FormDisplayName("Dropdown Menu")
        @FormType.Enum(externNames = {
                "",
                "Type 2 (name set externally!)"
        })
        public EnumValues dropdown;

        //TODO
        /*@FormType.Enum(value = 3, type = FormType.Enum.Type.RADIO_BUTTON)
        public EnumValues radio;*/

        enum EnumValues {
            TYPE_1,
            @FormType.EnumMemberTooltip({
                    "This is the second value in the enum",
                    "It has a tooltip which is only visible when used as a radio button!"
            })
            TYPE_2,
            TYPE_3,
            @FormType.EnumMemberName("jeff")
            @FormType.EnumMemberTooltip("name jeff lol")
            JEFF,;
        }
    }
}
