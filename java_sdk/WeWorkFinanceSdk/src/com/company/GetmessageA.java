package com.company;

import com.tencent.wework.Finance;
import com.tencent.wework.RSAEncrypt;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsonorg.JsonOrgModule;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class GetmessageA {
	private static final String SEQ_FILE_PATH = "seq.txt";
	private static AtomicLong currentSeq = new AtomicLong(0);
	private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
	//获取私钥
	private static String readPrivateKeyFromFile(String fileName) throws IOException {
        return new String(Files.readAllBytes(Path.of(fileName))).trim();
    }
	private static final String privateKey;
    static {
        try {
            privateKey = readPrivateKeyFromFile("pri.key");
        } catch (IOException e) {
            System.out.println("读取私钥文件失败：" + e.getMessage());
            // 退出程序，没有私钥，后续代码无法正常执行
            System.exit(1);
            throw new RuntimeException("Could not read private key");
        }
   	}
    private static long sdkInstance;
    // 创建 mapper 并复用
    private static ObjectMapper mapper = new ObjectMapper();
    public void start() {
    	ScheduledExecutorService executorService = Executors.newScheduledThreadPool(2);
    	Runnable Getmessage = () -> {
    		long startTime = System.currentTimeMillis(); // 记录任务开始的时间
            try {
            	// 使用currentSeq来获取加密数据
                String encryptedData = getEncryptedChatData(sdkInstance, currentSeq.intValue());
                if (encryptedData == null) {
                    System.out.println("未获取到加密数据,结果为空");
                    return;
                }

                //System.out.println("获取到的加密数据：");
                //System.out.println(encryptedData);

                // 解析JSON数据为 ResponseData 对象
                ResponseData responseData = mapper.readValue(encryptedData, ResponseData.class);

                // 获取 chatdata 列表并检查是否为空
                List<ChatData> chatDataList = responseData.getChatdata();
                if (chatDataList.isEmpty()) {
                    // 没有chatdata，跳过后续操作
                    return;
                }

                // 获取最新的消息数据（列表的最后一个元素）
                int lastElementIndex = chatDataList.size() - 1;
                ChatData latestChatData = chatDataList.get(lastElementIndex);

                // 更新当前的消息序列号
                currentSeq.set(latestChatData.getSeq());

                // 获取加密的随机密钥和聊天消息
                String encryptRandomKey = latestChatData.getEncrypt_random_key();
                String encryptChatMsg = latestChatData.getEncrypt_chat_msg();


                // 使用解密函数
                String message = RSAEncrypt.decryptRSA(encryptRandomKey, privateKey);
                long msg = Finance.NewSlice();
                Finance.DecryptData(sdkInstance, message, encryptChatMsg, msg);
                String plaintext = Finance.GetContentFromSlice(msg);
                System.out.println("获取明文数据:" + plaintext);
                System.out.println("currentSeq:" + currentSeq.get());
                // 将 "from" 更改为 "from_name" 
                plaintext = plaintext.replace("\"from\":", "\"from_name\":");
                //rootree
                JsonNode rootNode = mapper.readTree(plaintext);
                // Check if the message type is "image"
                JsonNode msgTypeNode = rootNode.path("msgtype");
                //System.out.println("MsgType Node: " + msgTypeNode.toString());
                if (msgTypeNode.isTextual() && "image".equals(msgTypeNode.asText())) {
                	System.out.println("发现图片,准备拉取");
                    // 获取拉取图片所需参数
                    JsonNode sdkFileidNode = rootNode.path("image").path("sdkfileid");
                    String sdkFileid = sdkFileidNode.asText();
                    // 调用函数拉取图片
                    byte[] completeMediaData = fetchCompleteMediaData(sdkInstance, sdkFileid, null, null);
                    String md5Hex = saveToFile(completeMediaData, "D:\\sanae\\channel_temp");
                    String imageString = constructImageString(md5Hex);
                    plaintext = modifyPlaintextWithImageString(plaintext, imageString);
                    System.out.println("插入图片信息:"+plaintext);
                    }
                // 创建要传递的数据对象
                Map<String, Object> data = new HashMap<>();
                data.put("plaintext", mapper.readValue(plaintext, Object.class)); // 将字符串转换为实际的JSON对象
                data.put("seq", currentSeq);
                // 将data转换为字符串
                String jsonData = mapper.writeValueAsString(data);
                System.out.println("上报数据:" + jsonData);
                sendPostRequest("http://127.0.0.1:32767/group_message", jsonData);
                Finance.FreeSlice(msg);

            } catch (IOException e) {
                System.out.println("解析JSON数据失败：" + e.getMessage());
            } catch (Exception e) {
                System.out.println("发生错误: " + e.getMessage());
            }
            long endTime = System.currentTimeMillis(); // 记录任务结束的时间
            long timeElapsed = endTime - startTime; // 计算所耗时间
            // 打印所耗时间
            System.out.println("Execution time in milliseconds : " + timeElapsed);
        };
        // 初始延迟为 0，之后每 100 毫秒执行一次
        executorService.scheduleAtFixedRate(Getmessage, 0, 100, TimeUnit.MILLISECONDS);
    }
    
    
    public static void main(String[] args) {
        currentSeq.set(readLastSeq()); // 读取seq 全局静态变量
        // 启动定期保存任务，这里设置为每10分钟保存一次
        scheduler.scheduleAtFixedRate(GetmessageA::saveSeqToFile, 10, 10, TimeUnit.MINUTES);
        //registerAfterburnerModule();
        sdkInstance = initSdk();
        if (sdkInstance == 0) {
            System.out.println("SDK初始化失败");
            return;
        }
        new GetmessageA().start();    
    }

    private static void registerAfterburnerModule() {
    	  /*
    	   * Avoiding java.lang.NoSuchMethodError: com.fasterxml.jackson.databind.ser.BeanPropertyWriter.isUnwrapping()
    	   * This happens, if the version of jackson databind less that the Afterburner version.
    	   *
    	   * One reason can be maven, because it resolves a version conflict with the nearest-wins strategy it is possible that
    	   * jackson-module-afterburner is in a higher version that jackson-databind and jackson-core
    	   *
    	   * Another reason could be that a application server bundled version of jackson databind is used
    	   */
    	  final AfterburnerModule afterburnerModule = new AfterburnerModule();
    	  mapper.registerModule(afterburnerModule);	  
    	}
    
    // 从文件中读取上次保存的seq值
    private static long readLastSeq() {
        try {
            File file = new File(SEQ_FILE_PATH);
            if (file.exists()) {
                String content = new String(Files.readAllBytes(file.toPath()));
                return Long.parseLong(content.trim());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }
    
    // 将seq值保存到文件中
    private static void saveSeqToFile() {
        try {
        	Files.write(Paths.get(SEQ_FILE_PATH), String.valueOf(currentSeq.get()).getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 初始化sdk 读取corpid和secret
    private static long initSdk() {
        String corpid = "";
        String secret = "";

        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        try {
            Config config = mapper.readValue(new File("config.yaml"), Config.class);
            
            corpid = config.getCorpid();
            secret = config.getSecret();
            System.out.println("读取到corpid：" + corpid);
            System.out.println("读取到secret：" + secret);
            
        } catch (IOException e) {
            e.printStackTrace();
        }

        long sdk = Finance.NewSdk();
        int reqInit = Finance.Init(sdk, corpid, secret);
        if (reqInit != 0) {
            System.out.println("初始化错误，代码：" + reqInit);
            return 0;
        } else {
            return sdk;
        }
    }

    /**
     * 获取加密的聊天数据。
     * 
     * @param sdk    已初始化的SDK实例。
     * @param nowSeq 当前的序列号。如果之前没有存档消息，则传入0。
     * @return 返回加密的聊天数据。如果发生错误则返回null。
     */
    private static String getEncryptedChatData(long sdk, int nowSeq) {
        
        // 从当前的seq开始拉取
        int seq = nowSeq;

        // 设置拉取的消息限制
        int limit = 1;

        // 创建一个新的数据片段结构，用于接收数据
        long slice = Finance.NewSlice();

        // 调用SDK方法以获取聊天数据。代理和密码字段为null，超时设置为10秒。
        long reqGetChatData = Finance.GetChatData(sdk, seq, limit, null, null, 10, slice);

        // 如果返回码不为0，表示发生了错误
        if (reqGetChatData != 0) {
            System.out.println("获取会话记录数据错误，代码：" + reqGetChatData);
            return null;
        } else {
            // 从数据片段中提取和返回聊天数据
            return Finance.GetContentFromSlice(slice);
        }
    }
    /**
     * 尝试拉取完整的媒体数据。
     * 
     * @param sdk 已初始化的SDK实例。
     * @param sdkFileid 媒体消息中的sdkfileid。
     * @param proxy 代理地址，例如"socks5://10.0.0.1:8081"。
     * @param passwd 代理的账号密码，例如"user_name:passwd_123"。
     * @param timeout 超时时间。
     * @return 完整的媒体数据，如果出错则返回null。
     */
    public static byte[] fetchCompleteMediaData(long sdk, String sdkFileid, String proxy, String passwd) {
        ByteArrayOutputStream completeData = new ByteArrayOutputStream();
        String indexbuf = null; // 初始值应该为空
        boolean isFinished = false;
        int maxAttempts = 5;  // 设置一个合适的最大尝试次数，以避免无限循环
        int attempts = 0;

        while (!isFinished && attempts < maxAttempts) {
            // 使用NewMediaData分配内存
            long mediaDataSlice = Finance.NewMediaData();

            //System.out.println(sdkFileid);
            int result = Finance.GetMediaData(sdk, indexbuf, sdkFileid, proxy, passwd, 10, mediaDataSlice);
            if (result != 0) {
                System.out.println("拉取媒体数据错误，代码：" + result);
                Finance.FreeMediaData(mediaDataSlice); // 如果出错，确保释放内存
                return null;
            }

            // 从数据片段中提取媒体数据
            byte[] fetchedDataBytes = Finance.GetData(mediaDataSlice);
            try {
                completeData.write(fetchedDataBytes);
            } catch (IOException e) {
                System.out.println("写入数据出错：" + e.getMessage());
                Finance.FreeMediaData(mediaDataSlice); 
                return null;
            }

            // 检查是否完成
            isFinished = (Finance.IsMediaDataFinish(mediaDataSlice) == 1);
            if (!isFinished) {
                indexbuf = Finance.GetOutIndexBuf(mediaDataSlice);
            }

            Finance.FreeMediaData(mediaDataSlice); // 在循环结束时释放内存
            attempts++;
        }

        if (attempts == maxAttempts) {
            System.out.println("已达到最大尝试次数，但媒体数据拉取仍未完成");
            return null;  // 或其他适当的错误处理
        }
        System.out.println("图片拉取完成");
        return completeData.toByteArray();
    }
    
    // 一个简单的方法，用于向指定URL发送POST请求并传递JSON数据
    private static void sendPostRequest(String urlString, String jsonData) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        con.setDoOutput(true);

        try (OutputStream os = con.getOutputStream()) {
            byte[] input = jsonData.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        int responseCode = con.getResponseCode();
        System.out.println("POST Response Code :: " + responseCode);
        if (responseCode == HttpURLConnection.HTTP_OK) { 
            try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                String inputLine;
                StringBuffer response = new StringBuffer();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                System.out.println(response.toString());  // 输出服务器响应
            }
        } else {
            System.out.println("POST request not worked");
        }
    }
    
    public static String saveToFile(byte[] data, String directoryPath) throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] md5Bytes = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : md5Bytes) {
            sb.append(String.format("%02x", b));
        }
        String md5Hex = sb.toString();

        File outputFile = new File(directoryPath, md5Hex + ".jpg");
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(data);
        }

        return md5Hex;
    }
    
    public static String modifyPlaintextWithImageString(String plaintext, String imageString) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(plaintext);
        ((ObjectNode) rootNode).put("text.content", imageString);
        return mapper.writeValueAsString(rootNode);
    }
    
    public static String constructImageString(String md5) {
        String imageUrl = "http://127.0.0.1/channel_temp/" + md5 + ".jpg";
        return "[CQ:image,file=" + md5 + ".image,url=" + imageUrl + "]";
    }

    //数据类型
    static class ResponseData {
        private int errcode;
        private String errmsg;
        private List<ChatData> chatdata;

        // Getters and Setters
        public int getErrcode() { return errcode; }
        public void setErrcode(int errcode) { this.errcode = errcode; }
        public String getErrmsg() { return errmsg; }
        public void setErrmsg(String errmsg) { this.errmsg = errmsg; }
        public List<ChatData> getChatdata() { return chatdata; }
        public void setChatdata(List<ChatData> chatdata) { this.chatdata = chatdata; }
    }

    static class ChatData {
        private long seq;
        private String msgid;
        private int publickey_ver;
        private String encrypt_random_key;
        private String encrypt_chat_msg;

        // Getters and Setters
        public long getSeq() { return seq; }
        public void setSeq(long seq) { this.seq = seq; }
        public String getMsgid() { return msgid; }
        public void setMsgid(String msgid) { this.msgid = msgid; }
        public int getPublickey_ver() { return publickey_ver; }
        public void setPublickey_ver(int publickey_ver) { this.publickey_ver = publickey_ver; }
        public String getEncrypt_random_key() { return encrypt_random_key; }
        public void setEncrypt_random_key(String encrypt_random_key) { this.encrypt_random_key = encrypt_random_key; }
        public String getEncrypt_chat_msg() { return encrypt_chat_msg; }
        public void setEncrypt_chat_msg(String encrypt_chat_msg) { this.encrypt_chat_msg = encrypt_chat_msg; }
    }
    static class Config {
        private String corpid;
        private String secret;

        // getters and setters
        public String getCorpid() {
            return corpid;
        }

        public void setCorpid(String corpid) {
            this.corpid = corpid;
        }

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }
    }
}
