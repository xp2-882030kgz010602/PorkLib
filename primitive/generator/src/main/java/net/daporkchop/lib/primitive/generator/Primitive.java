/*
 * Adapted from The MIT License (MIT)
 *
 * Copyright (c) 2018-2020 DaPorkchop_
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 *
 * Any persons and/or organizations using this software must include the above copyright notice and this permission notice,
 * provide sufficient credit to the original authors of the project (IE: DaPorkchop_), as well as provide a link to the original project.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

package net.daporkchop.lib.primitive.generator;

import com.google.gson.JsonObject;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.Accessors;
import net.daporkchop.lib.common.util.PArrays;

import java.util.ArrayDeque;
import java.util.Collection;

@Accessors(chain = true)
@Setter
@NoArgsConstructor
public class Primitive {
    public static final Collection<Primitive> PRIMITIVES = new ArrayDeque<>();
    public static final String PARAM_DEF = "P%d";
    public static final String DISPLAYNAME_DEF = String.format("_%s_", PARAM_DEF);
    public static final String BOXED_FORCE_DEF = String.format("_obj%s_", PARAM_DEF);
    public static final String UNSAFE_FORCE_DEF = String.format("_unsafe%s_", PARAM_DEF);
    public static final String FULLNAME_FORCE_DEF = String.format("_fullname%s_", PARAM_DEF);
    public static final String NAME_DEF = String.format("_%s_", PARAM_DEF.toLowerCase());
    public static final String NAME_FORCE_DEF = String.format("_name%s_", PARAM_DEF);
    public static final String HASHCODE_DEF = String.format("_hashCode%s_", PARAM_DEF);
    public static final String EQUALS_DEF = String.format("_equals%s_", PARAM_DEF);
    public static final String CAST_DEF = String.format("_cast%s_", PARAM_DEF);
    public static final String EMPTYVALUE_DEF = String.format("_%sE_", PARAM_DEF);
    public static final String NON_GENERIC_DEF = String.format("_nG%s_", PARAM_DEF);
    public static final String GENERIC_DEF = String.format("_G%s_", PARAM_DEF);
    public static final String GENERIC_SUPER_P_DEF = String.format("_Gsuper%s_", PARAM_DEF);
    public static final String GENERIC_EXTENDS_P_DEF = String.format("_Gextends%s_", PARAM_DEF);
    public static final String GENERIC_HEADER_DEF = "_gH_";

    public static final String HEADERS_DEF = "_headers_";
    public static final String LICENSE_DEF = "_copyright_";
    public static final String PACKAGE_DEF = "_package_";
    public static final String IMPORTS_DEF = "_imports_";

    public static final String METHODS_DEF = "_methods_";

    public static final String UNSAFE_ARRAY_OFFSET_DEF = String.format("_arrOffset%s_", PARAM_DEF);
    public static final String UNSAFE_ARRAY_SCALE_DEF = String.format("_arrScale%s_", PARAM_DEF);

    public static int countVariables(@NonNull String filename) {
        for (int i = 0; ; i++) {
            String s = String.format(DISPLAYNAME_DEF, i);
            if (!filename.contains(s)) {
                return i;
            }
        }
    }

    protected static String[] getGenericNames(@NonNull JsonObject settings, int count) {
        return settings.has("genericNames") ?
                PArrays.filled(count, String[]::new, i -> settings.getAsJsonObject("genericNames").get(String.format("P%d", i)).getAsString().trim()) :
                PArrays.filled(count, String[]::new, i -> String.valueOf((char) ('A' + i)));
    }

    public static String getGenericHeader(@NonNull JsonObject settings, @NonNull Primitive... primitives) {
        if (primitives.length == 0) {
            return "";
        }
        String[] genericNames = getGenericNames(settings, primitives.length);
        int i = 0;
        for (Primitive p : primitives) {
            if (p.generic) {
                i++;
            }
        }
        if (i == 0) {
            return "";
        }
        String s = "<";
        for (int j = 0; j < primitives.length; j++) {
            if (primitives[j].generic) {
                s += genericNames[j] + ", ";
            }
        }
        return (s.endsWith(", ") ? s.substring(0, s.length() - 2) : s) + '>';
    }

    public static String getGenericSuper(@NonNull JsonObject settings, int x, Primitive... primitives) {
        if (primitives.length == 0) {
            return "";
        }
        String[] genericNames = getGenericNames(settings, primitives.length);
        int i = 0;
        for (Primitive p : primitives) {
            if (p.generic) {
                i++;
            }
        }
        if (i == 0) {
            return "";
        }
        String s = "<";
        for (int j = 0; j < primitives.length; j++) {
            if (primitives[j].generic) {
                s += "? super " + genericNames[j] + ", ";
            }
        }
        if (s.endsWith(", ")) {
            s = s.substring(0, s.length() - 2);
        }
        return s + '>';
    }

    public static String getGenericExtends(@NonNull JsonObject settings, int x, Primitive... primitives) {
        if (primitives.length == 0) {
            return "";
        }
        String[] genericNames = getGenericNames(settings, primitives.length);
        int i = 0;
        for (Primitive p : primitives) {
            if (p.generic) {
                i++;
            }
        }
        if (i == 0) {
            return "";
        }
        String s = "<";
        for (int j = 0; j < primitives.length; j++) {
            if (primitives[j].generic) {
                s += "? extends " + genericNames[j] + ", ";
            }
        }
        if (s.endsWith(", ")) {
            s = s.substring(0, s.length() - 2);
        }
        return s + '>';
    }

    @NonNull
    public String fullName;
    @NonNull
    public String displayName;
    @NonNull
    public String unsafeName;
    @NonNull
    public String name;
    @NonNull
    public String hashCode;
    public boolean generic;
    @NonNull
    public String emptyValue;
    @NonNull
    public String equals;
    @NonNull
    public String nequals;

    public String format(@NonNull String text, int i)   {
        return this.format(text, i, new JsonObject());
    }

    public String format(@NonNull String text, int i, @NonNull JsonObject settings) {
        String genericName = String.valueOf((char) ('A' + i));
        if (settings.has("genericNames"))   {
            genericName = settings.getAsJsonObject("genericNames").get(String.format("P%d", i)).getAsString();
        }

        if (this.generic) {
            text = text.replaceAll("\\s*?<~!%[\\s\\S]*?%>".replace("~", String.valueOf(i)), "")
                    .replaceAll("<~!%[\\s\\S]*?%>".replace("~", String.valueOf(i)), "")
                    .replaceAll("(\\s*?)<~%([\\s\\S]*?)%>".replace("~", String.valueOf(i)), "$1$2")
                    .replaceAll("<~%([\\s\\S]*?)%>".replace("~", String.valueOf(i)), "$1");
        } else {
            text = text.replaceAll("\\s*?<~%[\\s\\S]*?%>".replace("~", String.valueOf(i)), "")
                    .replaceAll("<~%[\\s\\S]*?%>".replace("~", String.valueOf(i)), "")
                    .replaceAll("(\\s*?)<~!%([\\s\\S]*?)%>".replace("~", String.valueOf(i)), "$1$2")
                    .replaceAll("<~!%([\\s\\S]*?)%>".replace("~", String.valueOf(i)), "$1");
        }
        return text
                .replace(String.format(DISPLAYNAME_DEF, i), this.displayName)
                .replace(String.format(BOXED_FORCE_DEF, i), this.fullName)
                .replace(String.format(UNSAFE_FORCE_DEF, i), this.unsafeName != null ? this.unsafeName : this.fullName)
                .replace(String.format(FULLNAME_FORCE_DEF, i), this.generic ? genericName : this.fullName)
                .replace(String.format(NAME_DEF, i), this.generic ? genericName : this.name)
                .replace(String.format(NAME_FORCE_DEF, i), this.name)
                .replace(String.format(CAST_DEF, i), this.generic ? "(" + genericName + ") " : "")
                .replace(String.format(EMPTYVALUE_DEF, i), this.emptyValue)
                .replace(String.format(NON_GENERIC_DEF, i), this.generic ? "" : this.name)
                .replace(String.format(GENERIC_DEF, i), this.generic ? "<" + genericName + "> " : " ")
                .replace(String.format(GENERIC_SUPER_P_DEF, i), getGenericSuper(settings, i, this))
                .replace(String.format(GENERIC_EXTENDS_P_DEF, i), getGenericExtends(settings, i, this))
                .replace(String.format(UNSAFE_ARRAY_OFFSET_DEF, i), String.format("PUnsafe.ARRAY_%s_BASE_OFFSET", this.name.toUpperCase()))
                .replace(String.format(UNSAFE_ARRAY_SCALE_DEF, i), String.format("PUnsafe.ARRAY_%s_INDEX_SCALE", this.name.toUpperCase()))
                .replaceAll("_equalsP~\\|([^!]*?)\\|([^!]*?)\\|_".replace("~", String.valueOf(i)), this.equals)
                .replaceAll("_nequalsP~\\|([^!]*?)\\|([^!]*?)\\|_".replace("~", String.valueOf(i)), this.nequals)
                .replaceAll("_hashP~\\|([^!]*?)\\|_".replace("~", String.valueOf(i)), this.hashCode);
    }

    public Primitive setGeneric() {
        this.generic = true;
        return this;
    }

    public Primitive build() {
        if (this.displayName == null) {
            this.displayName = this.fullName;
        }
        return this;
    }

    @Override
    public String toString() {
        return this.fullName;
    }
}
