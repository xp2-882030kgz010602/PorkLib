/*
 * Adapted from the Wizardry License
 *
 * Copyright (c) 2018-2018 DaPorkchop_ and contributors
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

package net.daporkchop.lib.crypto.key.serializer.impl;

import net.daporkchop.lib.crypto.key.ec.AbstractECKeyPair;
import net.daporkchop.lib.crypto.key.serializer.AbstractKeySerializer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ECKeySerializer extends AbstractKeySerializer<AbstractECKeyPair> {
    public static final ECKeySerializer INSTANCE = new ECKeySerializer();

    private ECKeySerializer() {
    }

    @Override
    protected void doSerialize(AbstractECKeyPair key, OutputStream baos) throws IOException {
        new DataOutputStream(baos).writeUTF(key.getClass().getCanonicalName());

        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(key.getPublicKey());
        oos.writeObject(key.getPrivateKey());
        oos.close();
    }

    @Override
    protected AbstractECKeyPair doDeserialize(InputStream bais) throws IOException {
        String className = new DataInputStream(bais).readUTF();
        Constructor<?> constructor;

        try {
            Class<?> clazz = Class.forName(className);
            constructor = clazz.getConstructor(PrivateKey.class, PublicKey.class);
            constructor.setAccessible(true);
        } catch (ClassNotFoundException
                | NoSuchMethodException e) {
            e.printStackTrace();
            throw new IllegalStateException(e);
        }

        ObjectInputStream ois = new ObjectInputStream(bais);
        PrivateKey privateKey;
        PublicKey publicKey;
        try {
            publicKey = (PublicKey) ois.readObject();
            privateKey = (PrivateKey) ois.readObject();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            throw new IllegalStateException(e);
        } finally {
            ois.close();
        }
        try {
            return (AbstractECKeyPair) constructor.newInstance(privateKey, publicKey);
        } catch (IllegalAccessException
                | InvocationTargetException
                | InstantiationException e) {
            e.printStackTrace();
            throw new IllegalStateException(e);
        }
    }
}
