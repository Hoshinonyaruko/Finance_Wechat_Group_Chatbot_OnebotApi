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
import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.Map;


public class Getmessage {
	private static final String SEQ_FILE_PATH = "seq.txt";
	private static long currentSeq = 0L;
	private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
	//获取私钥
	private static String readPrivateKeyFromFile(String fileName) throws IOException {
        return new String(Files.readAllBytes(Path.of(fileName))).trim();
    }

    private static long sdkInstance;

    public static void main(String[] args) {
        currentSeq = readLastSeq(); // 读取seq 全局静态变量

        // 启动定期保存任务，这里设置为每10分钟保存一次
        scheduler.scheduleAtFixedRate(Getmessage::saveSeqToFile, 10, 10, TimeUnit.MINUTES);

        sdkInstance = initSdk();
        if (sdkInstance == 0) {
            System.out.println("SDK初始化失败");
            return;
        }

        while (true) { // 持续轮询
            try {
                // 使用currentSeq来获取加密数据
                String encryptedData = getEncryptedChatData(sdkInstance, (int) currentSeq);
                if (encryptedData == null) {
                    System.out.println("未获取到加密数据,结果为空");
                    Thread.sleep(200); // 每秒轮询5次
                    continue;
                }

                //System.out.println("获取到的加密数据：");
                //System.out.println(encryptedData);

                ObjectMapper mapper = new ObjectMapper();
                ResponseData responseData = mapper.readValue(encryptedData, ResponseData.class);

                if (responseData.getChatdata().isEmpty()) {
                    //System.out.println("未找到chatdata数据，跳过解密操作");
                    Thread.sleep(200); // 每秒轮询5次
                    continue;
                }

                // 获取最新的消息数据
                ChatData chatData = responseData.getChatdata().get(responseData.getChatdata().size() - 1);
                currentSeq = chatData.getSeq();
                String encryptRandomKey = chatData.getEncrypt_random_key();
                String encryptChatMsg = chatData.getEncrypt_chat_msg();

                // 从文件中读取私钥
                String privateKey = readPrivateKeyFromFile("pri.key");

                // 使用解密函数
                String message = RSAEncrypt.decryptRSA(encryptRandomKey, privateKey);
                long msg = Finance.NewSlice();
                Finance.DecryptData(sdkInstance, message, encryptChatMsg, msg);
                String plaintext = Finance.GetContentFromSlice(msg);
                System.out.println("获取明文数据:" + plaintext);
                System.out.println("currentSeq:" + currentSeq);
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

            try {
                Thread.sleep(200); // 每秒轮询5次
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
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
            Files.write(Paths.get(SEQ_FILE_PATH), String.valueOf(currentSeq).getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //初始化sdk
    private static long initSdk() {
        final String corpid = "";
        final String secret = "";
        
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
    private static ObjectMapper mapper = new ObjectMapper();
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
}
