package com.company;

import com.tencent.wework.Finance;
import java.io.File;
import java.io.FileOutputStream;

//10000	参数错误，请求参数错误
//10001	网络错误，网络请求错误
//10002	数据解析失败
//10003	系统失败
//10004	密钥错误导致加密失败
//10005	fileid错误
//10006	解密失败
//10007 找不到消息加密版本的私钥，需要重新传入私钥对
//10008 解析encrypt_key出错
//10009 ip非法
//10010 数据过期

public class Main {
    public static void main(String[] args){

        //seq 表示该企业存档消息序号，该序号单调递增，拉取序号建议设置为上次拉取返回结果中最大序号。首次拉取时seq传0，sdk会返回有效期内最早的消息。
        //limit 表示本次拉取的最大消息条数，取值范围为1~1000
        //proxy与passwd为代理参数，如果运行sdk的环境不能直接访问外网，需要配置代理参数。sdk访问的域名是"https://qyapi.weixin.qq.com"。
        //建议先通过curl访问"https://qyapi.weixin.qq.com"，验证代理配置正确后，再传入sdk。
        //timeout 为拉取会话存档的超时时间，单位为秒，建议超时时间设置为5s。
        //sdkfileid 媒体文件id，从解密后的会话存档中得到
        //savefile 媒体文件保存路径
        //encrypt_key 拉取会话存档返回的encrypt_random_key，使用配置在企业微信管理台的rsa公钥对应的私钥解密后得到encrypt_key。
        //encrypt_chat_msg 拉取会话存档返回的encrypt_chat_msg
        if (args.length < 2) {
            System.out.println("./sdktools 1(chatmsg) 2(mediadata) 3(decryptdata)\n");
            System.out.println("./sdktools 1 seq limit proxy passwd timeout\n");
            System.out.println("./sdktools 2 fileid proxy passwd timeout savefile\n");
            System.out.println("./sdktools 3 encrypt_key encrypt_chat_msg\n");
            return;
        }

        long ret = 0;
        //使用sdk前需要初始化，初始化成功后的sdk可以一直使用。
        //如需并发调用sdk，建议每个线程持有一个sdk实例。
        //初始化时请填入自己企业的corpid与secrectkey。
        long sdk = Finance.NewSdk();
        ret = Finance.Init(sdk, "wwd08c8e7c775ab44d", "zJ6k0naVVQ--gt9PUSSEvs03zW_nlDVmjLCTOTAfrew");
        if(ret != 0){
            Finance.DestroySdk(sdk);
            System.out.println("init sdk err ret " + ret);
            return;
        }

        if (args[0].equals("1")) {
            //拉取会话存档
            int seq = Integer.parseInt(args[1]);
            int limit = Integer.parseInt(args[2]);
            String proxy = args[3];
            String passwd = args[4];
            int timeout = Integer.parseInt(args[5]);

            //每次使用GetChatData拉取存档前需要调用NewSlice获取一个slice，在使用完slice中数据后，还需要调用FreeSlice释放。
            long slice = Finance.NewSlice();
            ret = Finance.GetChatData(sdk, seq, limit, proxy, passwd, timeout, slice);
            if (ret != 0) {
                System.out.println("getchatdata ret " + ret);
                Finance.FreeSlice(slice);
                return;
            }
            System.out.println("getchatdata :" + Finance.GetContentFromSlice(slice));
            Finance.FreeSlice(slice);
        } 
        else if (args[0].equals("2")) {
            //拉取媒体文件
            String sdkfileid = args[1];
            String proxy = args[2];
            String passwd = args[3];
            int timeout = Integer.parseInt(args[4]);
            String savefile = args[5];

            //媒体文件每次拉取的最大size为512k，因此超过512k的文件需要分片拉取。若该文件未拉取完整，sdk的IsMediaDataFinish接口会返回0，同时通过GetOutIndexBuf接口返回下次拉取需要传入GetMediaData的indexbuf。
            //indexbuf一般格式如右侧所示，”Range:bytes=524288-1048575“，表示这次拉取的是从524288到1048575的分片。单个文件首次拉取填写的indexbuf为空字符串，拉取后续分片时直接填入上次返回的indexbuf即可。
            String indexbuf = "";
            while(true){
                //每次使用GetMediaData拉取存档前需要调用NewMediaData获取一个media_data，在使用完media_data中数据后，还需要调用FreeMediaData释放。
                long media_data = Finance.NewMediaData();
                ret = Finance.GetMediaData(sdk, indexbuf, sdkfileid, proxy, passwd, timeout, media_data);
                if(ret!=0){
                    System.out.println("getmediadata ret:" + ret);
                    Finance.FreeMediaData(media_data);
                    return;
                }
                System.out.printf("getmediadata outindex len:%d, data_len:%d, is_finis:%d\n",Finance.GetIndexLen(media_data),Finance.GetDataLen(media_data), Finance.IsMediaDataFinish(media_data));
                try {
                    //大于512k的文件会分片拉取，此处需要使用追加写，避免后面的分片覆盖之前的数据。
                    FileOutputStream outputStream  = new FileOutputStream(new File(savefile), true);
                    outputStream.write(Finance.GetData(media_data));
                    outputStream.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                if(Finance.IsMediaDataFinish(media_data) == 1)
                {
                    //已经拉取完成最后一个分片
                    Finance.FreeMediaData(media_data);
                    break;
                }
                else
                {
                    //获取下次拉取需要使用的indexbuf
                    indexbuf = Finance.GetOutIndexBuf(media_data);
                    Finance.FreeMediaData(media_data);
                }
            }
        } 
        else if (args[0].equals("3")) {
            //解密会话存档内容
            //sdk不会要求用户传入rsa私钥，保证用户会话存档数据只有自己能够解密。
            //此处需要用户先用rsa私钥解密encrypt_random_key后，作为encrypt_key参数传入sdk来解密encrypt_chat_msg获取会话存档明文。
            String encrypt_key = args[1];
            String encrypt_chat_msg = args[2];

            //每次使用DecryptData解密会话存档前需要调用NewSlice获取一个slice，在使用完slice中数据后，还需要调用FreeSlice释放。
            long msg = Finance.NewSlice();
            ret = Finance.DecryptData(sdk, encrypt_key, encrypt_chat_msg, msg);
            if (ret != 0) {
                System.out.println("getchatdata ret " + ret);
                Finance.FreeSlice(msg);
                return;
            }
            System.out.println("decrypt ret:" + ret + " msg:" + Finance.GetContentFromSlice(msg));
            Finance.FreeSlice(msg);
        }
        else {
            System.out.println("wrong args " + args[0]);
        }
        Finance.DestroySdk(sdk);
    }
}

