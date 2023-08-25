from fastapi import FastAPI, Depends, Request, Response
import xml.etree.ElementTree as ET
from fastapi.responses import PlainTextResponse
from WXBizMsgCrypt3 import WXBizMsgCrypt
from pydantic import BaseModel
from typing import List,Optional,Union
import aiohttp
import asyncio
import json
import time
import base64
import hashlib
import mimetypes
import os
import random
import requests
import psycopg2
import hashlib
import yaml
import re


app = FastAPI()

class TextContent(BaseModel):
    content: str

class ImageContent(BaseModel):
    md5sum: str
    filesize: int
    sdkfileid: str

class MessageData(BaseModel):
    msgid: str
    action: str
    from_name: str
    tolist: Optional[List[str]]
    roomid: str
    msgtime: int
    msgtype: str
    text: Optional[TextContent]
    image: Optional[ImageContent]

class WrappedMessageData(BaseModel):
    plaintext: MessageData
    seq: int

# 从YAML文件中加载配置
with open('config.yaml', 'r') as config_file:
    config = yaml.safe_load(config_file)

TOKEN = config['token']
ENCODING_AES_KEY = config['encoding_aes_key']
CORP_ID = config['corp_id']
SECRET = config['secret']
GROUP_ID = config['group_id']
ws_url_b = config['ws_url_b']
bot_id = config['bot_id']
WEBHOOK_KEY = config['webhook_key']

wxcpt = WXBizMsgCrypt(TOKEN, ENCODING_AES_KEY, CORP_ID)

ws_connections = {}
waiting_for_response = None
global_flag = True

class WeChatData:
    def __init__(self, xml: str):
        self.xml = xml

# 连接到数据库
def connect_database():
    conn = psycopg2.connect(
        host=config['database']['host'],
        port=config['database']['port'],
        user=config['database']['user'],
        password=config['database']['password'],
        dbname=config['database']['dbname']
    )
    return conn

def hash_id(original_id):
    # 生成md5哈希值
    m = hashlib.md5()
    m.update(original_id.encode())
    hashed_value = m.hexdigest()
    
    # 去除所有字母后剩余的数字取前10位
    filtered_value = ''.join([char for char in hashed_value if char.isdigit()])[:10]
    
    return filtered_value

def long_to_short(conn, original_id):
    short_id = hash_id(original_id)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO id_map (original_id, shortened_id) VALUES (%s, %s)", (original_id, short_id))
        conn.commit()
    except psycopg2.IntegrityError:
        # 如果original_id已经存在，则查询其对应的shortened_id
        conn.rollback()
        cur.execute("SELECT shortened_id FROM id_map WHERE original_id = %s", (original_id,))
        result = cur.fetchone()
        if result:
            short_id = result[0]
        else:
            # 如果因其他原因导致的IntegrityError（例如shortened_id冲突），则处理该情况
            while True:
                short_id = hash_id(original_id + '1')
                try:
                    cur.execute("INSERT INTO id_map (original_id, shortened_id) VALUES (%s, %s)", (original_id, short_id))
                    conn.commit()
                    break
                except psycopg2.IntegrityError:
                    conn.rollback()
                    original_id += '1'  # 变化原始ID以重新计算
                    continue
    cur.close()
    return short_id

def short_to_long(conn, short_id):
    cur = conn.cursor()
    cur.execute("SELECT original_id FROM id_map WHERE shortened_id = %s", (short_id,))
    result = cur.fetchone()
    cur.close()
    if result:
        return result[0]
    else:
        return None

def toggle_flag(content):
    global global_flag
    if content == "切换模式":
        global_flag = not global_flag
        print(f"Content: {content}, Global Flag: {global_flag}")

async def get_xml_data(request: Request) -> WeChatData:
    raw_data = await request.body()
    return WeChatData(xml=raw_data)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(_setup_b(bot_id))

@app.get("/cgi-bin/wxpush")
def check_url(msg_signature: str, timestamp: str, nonce: str, echostr: str) -> Response:
    print(echostr)
    ret, sEchoStr = wxcpt.VerifyURL(msg_signature, timestamp, nonce, echostr)
    if ret != 0:
        return PlainTextResponse(f"Error: {ret}", status_code=403)
    sEchoStr_decoded = sEchoStr.decode("utf-8")  # 将bytes对象解码为字符串
    print(sEchoStr_decoded)
    return PlainTextResponse(sEchoStr_decoded)

@app.post("/cgi-bin/wxpush")
async def handle_post(msg_signature: str, timestamp: str, nonce: str, data: WeChatData = Depends(get_xml_data)):
    ret, xml_content = wxcpt.DecryptMsg(data.xml, msg_signature, timestamp, nonce)
    if ret != 0:
        return PlainTextResponse(f"Error: {ret}", status_code=403)

    # 调试将解密后的消息打印出来
    print(f"Decrypted Message: {xml_content}")
    decrypted_str = xml_content.decode('utf-8')
    root = ET.fromstring(decrypted_str)
    # 获取并打印各个字段
    to_user_name = root.find('ToUserName').text
    from_user_name = root.find('FromUserName').text
    create_time = root.find('CreateTime').text
    msg_type = root.find('MsgType').text
    content_element = root.find('Content')
    content = content_element.text if content_element is not None else None
    msg_id_element = root.find('MsgId')
    if msg_id_element is not None:
        msg_id = msg_id_element.text
        print(f"MsgId: {msg_id}")
    else:
        print("MsgId not found in the XML")
    agent_id = root.find('AgentID').text

    print(f"ToUserName: {to_user_name}")
    print(f"FromUserName: {from_user_name}")
    print(f"CreateTime: {create_time}")
    print(f"MsgType: {msg_type}")
    print(f"Content: {content}")
    print(f"AgentID: {agent_id}")
    #切换模式
    toggle_flag(content)

    # 使用转换函数转换数据格式
    transformed_message = transform_wechat_to_ws(decrypted_str)

    # 发送转换后的消息给WebSocket服务端
    print(transformed_message)
    ws_response = await send_to_ws_b_async(transformed_message)
    print("成功",ws_response)
    # 根据ws_response来构建XML响应
    response_content = await generate_xml_response(ws_response)
    print("返回值",response_content)
    return PlainTextResponse(content=response_content, media_type="text/xml", status_code=200)

@app.post("/group_message")
async def group_message(data: WrappedMessageData):
    # 打印收到的数据
    print(data.plaintext.msgid)
    if data.plaintext and data.plaintext.text:
        print(data.plaintext.text.content if data.plaintext.text.content else "Content is None")
    else:
        print("Plaintext or text is None")
    print(data.seq)
    # 使用转换函数转换数据格式
    transformed_message = transform_wrapped_to_ws(bot_id,data)
    # 发送转换后的消息给WebSocket服务端
    print(transformed_message)
    await send_to_ws_b(transformed_message)
    return {"message": "Data received successfully!"}

async def _setup_b(bot_id):
    async with aiohttp.ClientSession() as session:
        try:
            headers = {
                "User-Agent": "CQHttp/4.15.0",
                "X-Client-Role": "Universal",
                "X-Self-ID": str(bot_id)
            }
            async with session.ws_connect(ws_url_b, headers=headers) as ws_b:
                ws_connections["b"] = ws_b
                ws_connections["b.bot_id"] = bot_id
                message = {
                    "meta_event_type": "lifecycle",
                    "post_type": "meta_event",
                    "self_id": bot_id,
                    "sub_type": "connect",
                    "time": int(time.time())
                }
                await ws_b.send_str(json.dumps(message))
                
                # 创建心跳协程
                heartbeat_task = asyncio.create_task(send_heartbeat(ws_b, bot_id))

                async for msg in ws_b:
                    asyncio.create_task(recv_message_b(msg))

                # 取消心跳协程
                heartbeat_task.cancel()
        except aiohttp.ClientError as e:
            print(f"Failed to connect websocket B: {e}")

async def send_heartbeat(ws, bot_id):
    while True:
        message = {
            "post_type": "meta_event",
            "meta_event_type": "heartbeat",
            "time": int(time.time()),
            "self_id": bot_id,
            "interval": 5000
        }
        await ws.send_str(json.dumps(message))
        await asyncio.sleep(5)  # 等待5秒

async def send_to_ws_b(message, bot_id=None):
    if message == None:
       return
    bot_id = bot_id if bot_id is not None else message["self_id"]
    ws_conn = ws_connections["b"]
    print("给onebot发送了",message)
    if ws_conn:
        try:
            await ws_conn.send_str(json.dumps(message))
        except ConnectionResetError:
            await ws_conn.close()
            print("onebot断开正在重连ing")
            await _setup_b(bot_id)
            ws_conn = ws_connections["b"]
            await ws_conn.send_str(json.dumps(message))

async def send_to_ws_b_async(message):
    global waiting_for_response

    # 发送消息到WebSocket
    await send_to_ws_b(message)

    # 创建一个Future对象来等待响应
    waiting_for_response = asyncio.Future()

    try:
        # 等待响应，但设置一个超时限制，例如10秒
        ws_response = await asyncio.wait_for(waiting_for_response, timeout=10)
        return ws_response
    except asyncio.TimeoutError:
        # 当超时发生
        waiting_for_response = None  # 清除等待的Future对象
        print("等待超时")
        return None

def transform_wrapped_to_ws(bot_id,data: WrappedMessageData) -> dict:
    # 从WrappedMessageData中提取所需的信息
    msgid = data.plaintext.msgid
    conn = connect_database()
    from_name = long_to_short(conn, data.plaintext.from_name)
    roomid = long_to_short(conn, data.plaintext.roomid)
    conn.close()
    msgtime = int(data.plaintext.msgtime / 1000)  # 将13位时间戳转换为10位
    content = data.plaintext.text.content

    # 将Unicode转换为明文
    decoded_content = json.loads(f'"{content}"')

    # 构造发送者信息
    sender = {
        "user_id": from_name,  # 请注意，这里可能需要更合适的"user_id"，现在我们只是用name替代了。
        "nickname": from_name
    }

    # 构造返回的消息结构
    transformed_message = {
        "post_type": "message",
        "message_type": "group",
        "group_id": roomid,
        "user_id": from_name,  # 同上，此处可能需要更改
        "self_id": bot_id,  # 同上，此处可能需要更改
        "sender": sender,
        "message_seq": msgid,  # 此处假设msgid可以当作sequence使用
        "time": msgtime,
        "message_id": msgid,
        "raw_message": decoded_content,
        "message": decoded_content
    }

    return transformed_message

from xml.etree import ElementTree as ET

#这里是私聊信息转换
def transform_wechat_to_ws(xml_content: bytes) -> dict:
    root = ET.fromstring(xml_content)
    # Extract common details from XML
    to_user_name = root.find('ToUserName').text
    print("to_user_name",to_user_name)
    with connect_database() as conn:
        from_user_name = long_to_short(conn, root.find('FromUserName').text)
    create_time = int(root.find('CreateTime').text)
    msg_type = root.find('MsgType').text
    msg_id = root.find('MsgId').text if root.find('MsgId') else None

    # Extract specific data based on the message type
    if msg_type == 'text':
        raw_message = message_content = root.find('Content').text
    elif msg_type == 'image':
        media_id = root.find('Image/MediaId').text
        image_url = get_image_url_from_media_id(media_id)
        raw_message = message_content = f"[CQ:image,file={media_id}.image,url={image_url}]"
    else:
        return None

    sender = {
        "user_id": from_user_name,
        "nickname": from_user_name
    }

    # Define common fields
    transformed_message = {
        "post_type": "message",
        "message_type": "group" if global_flag else "private",
        "user_id": from_user_name,
        "self_id": bot_id,
        "sender": sender,
        "time": create_time,
        "message_id": msg_id,
        "raw_message": raw_message,
        "message": message_content
    }
    print("目前的私聊模式:",global_flag)
    if global_flag:
        transformed_message.update({"group_id": from_user_name, "message_seq": msg_id})
    else:
        transformed_message.update({"sub_type": "friend"})

    return transformed_message

#从onebot收到信息
async def recv_message_b(msg):
    message = json.loads(msg.data)
    print("从onebot收到了", str(message)[:200])

    global waiting_for_response

    if waiting_for_response:
        # 如果有一个等待响应的Future对象，设置它的结果
        waiting_for_response.set_result(message)
        waiting_for_response = None

    await call_webhook_from_dict(message)

#这是群聊回复逻辑
async def call_webhook_from_dict(message):
    async with aiohttp.ClientSession() as session:
        action = message['action']
        group_id = message['params']['group_id']
        content = message['params'].get('message', '')

        if group_id != GROUP_ID:
            print(f"Message not from expected group. GroupID: {group_id}")
            return

        if action != 'send_group_msg':
            print(f"Unsupported action: {action}")
            return

        webhook_url = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key='+WEBHOOK_KEY
        print("request webhook_url:"+webhook_url)
        headers = {'Content-Type': 'application/json'}
        payload = generate_payload_from_content(content)

        if payload:
            async with session.post(webhook_url, headers=headers, json=payload) as response:
                response_text = await response.text()
                print(response_text)
        else:
            print("Payload was not set, cannot send the webhook.")

#组合payload
def generate_payload_from_content(content):
    with connect_database() as conn:
        mentioned_list = [short_to_long(conn, user_id) for user_id in re.findall(r'\[CQ:at,qq=(\d+)\]', content)]
    
    cleaned_content = re.sub(r'\[CQ:at,qq=\d+\]', '', content)
    
    if "file:///" in cleaned_content or "http://" in cleaned_content:
        image_data = get_image_data_from_content(cleaned_content)
        if not image_data:
            print("Failed to retrieve image data.")
            return None

        image_md5 = hashlib.md5(image_data).hexdigest()
        image_base64 = base64.b64encode(image_data).decode()
        
        payload = {
            "msgtype": "image",
            "image": {"base64": image_base64, "md5": image_md5},
        }

        remaining_content = cleaned_content.split("]")[1]
        if remaining_content:
            payload.update({
                "msgtype": "news",
                "news": {"articles": [{"title": "Image with Text", "description": remaining_content, "picurl": f"data:image/png;base64,{image_base64}"}]},
            })
        return payload

    text_payload = {"content": cleaned_content}
    if mentioned_list:
        text_payload["mentioned_list"] = mentioned_list

    payload = {
        "msgtype": "text",
        "text": text_payload,
    }
    return payload

#获取图片数据 byte
def get_image_data_from_content(content):
    if "file:///" in content:
        file_path = content.split("file:///")[1].split("]")[0]
        with open(file_path, 'rb') as f:
            return f.read()
    elif "http://" in content:
        http_link = content.split("file=")[1].split("]")[0]
        response = requests.get(http_link)
        if response.status_code == 200:
            return response.content
    return None

async def get_image_base64_from_path(path: str) -> str:
    with open(path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

async def get_access_token() -> str:
    """获取access_token"""
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CORP_ID}&corpsecret={SECRET}"
    response = requests.get(url)
    data = response.json()
    return data["access_token"]

def get_image_url_from_media_id(media_id: str) -> str:
    """使用media_id获取图像URL"""
    access_token = get_access_token()
    image_url = f"https://qyapi.weixin.qq.com/cgi-bin/media/get?access_token={access_token}&media_id={media_id}"
    # 注意：这里返回的URL其实是下载图像的URL，而不是直接查看图像的URL。你可能需要保存这个图像并提供一个查看图像的URL。
    return image_url

#这是私聊回复和api逻辑 私聊没有at逻辑,所以过滤掉
async def generate_xml_response(ws_response):
    if not ws_response:
        return generate_default_error_xml()
    
    action = ws_response['action']
    conn = connect_database()
    user_id = None

    if action == 'send_private_msg':
        user_id = short_to_long(conn, ws_response['params']['user_id'])
    elif action == 'send_group_msg':
        user_id = short_to_long(conn, ws_response['params']['group_id'])

    conn.close()
    
    if not user_id:
        print("action not supported yet")
        return generate_default_error_xml()

    print("short_to_long_id:", user_id)

    content = ws_response['params']['message']
    # 使用正则表达式来查找和替换所有出现的[CQ:at,qq=数字]字符串
    content = re.sub(r'\[CQ:at,qq=\d+\]', '', content)

    if "file:///" in content:
        file_path = content.split("file:///")[1].split("]")[0]
        media_id = await upload_media(file_path, "image")
        xml_content = generate_xml(user_id, "image", media_id)

    elif "http://" in content or "https://" in content:
        if "file=" in content:
            http_link = content.split("file=")[1].split("]")[0]
        else:
            http_link = [s for s in content.split() if s.startswith("http://") or s.startswith("https://")][0]
        # Check if link ends with .jpg or .png
        if http_link.endswith('.jpg') or http_link.endswith('.png'):
            response = requests.get(http_link)
            
            # Check if the download was successful
            if response.status_code == 200:
                image_data = response.content
                media_id = await upload_media_from_data(image_data, "image")
                xml_content = generate_xml(user_id, "image", media_id)
            else:
                print("Failed to download the image from the link")
                xml_content = generate_xml(user_id, "text", "Failed to download the image from the provided link. Please check and try again.")
        else:
            # If the link is not an image link, treat it as normal text
            xml_content = generate_xml(user_id, "text", content)
        
    else:
        xml_content = generate_xml(user_id, "text", content)

    if xml_content is None:
            print("Failed to generate xml_content.")
            return generate_default_error_xml()

    ret, response_content = wxcpt.EncryptMsg(xml_content, str(random.randint(100000, 200000)), str(int(time.time())))
    
    if ret != 0:
        raise Exception("Error in encryption")
    
    return response_content

def generate_default_error_xml():
    return """
    <xml>
        <Encrypt><![CDATA[Default_Encrypted_Message_or_Error_Message]]></Encrypt>
        <MsgSignature><![CDATA[Default_Signature_or_Error_Signature]]></MsgSignature>
        <TimeStamp>Default_Timestamp_or_Error_Timestamp</TimeStamp>
        <Nonce><![CDATA[Default_Nonce_or_Error_Nonce]]></Nonce>
    </xml>
    """

def generate_xml(user_id, msg_type, content):
    if msg_type == "text":
        return f"""
        <xml>
            <ToUserName><![CDATA[{user_id}]]></ToUserName>
            <FromUserName><![CDATA[{CORP_ID}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[{content}]]></Content>
        </xml>
        """
    elif msg_type == "image":
        return f"""
        <xml>
            <ToUserName><![CDATA[{user_id}]]></ToUserName>
            <FromUserName><![CDATA[{CORP_ID}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[image]]></MsgType>
            <Image>
                <MediaId><![CDATA[{content}]]></MediaId>
            </Image>
        </xml>
        """

async def upload_media(file_path: str, file_type: str) -> str:
    """上传媒体文件并返回media_id"""

    # 获取access token
    access_token = await get_access_token()

    # 定义请求URL
    url = f"https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token={access_token}&type={file_type}"

    # 获取文件名, 文件大小, 和content-type
    filename = os.path.basename(file_path)
    filelength = os.path.getsize(file_path)
    content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'

    # 准备multipart/form-data请求数据
    data = aiohttp.FormData()
    data.add_field('media',
                   open(file_path, 'rb'),
                   filename=filename,
                   content_type=content_type)

    # 发送请求并获取结果
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data) as response:
            result = await response.json()
            if result.get("errcode") == 0:
                return result.get("media_id")
            else:
                raise Exception(f"Error uploading media: {result.get('errmsg')}")

async def upload_media_from_data(image_data: bytes, file_type: str, filename: str = "uploaded_image") -> str:
    """从给定的数据上传媒体文件返回media_id"""

    # 获取access token
    access_token = await get_access_token()

    # 定义请求URL
    url = f"https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token={access_token}&type={file_type}"

    # 设置content-type为application/octet-stream
    content_type = 'application/octet-stream'

    # 准备multipart/form-data请求数据
    data = aiohttp.FormData()
    data.add_field('media',
                   image_data,
                   filename=filename,
                   content_type=content_type)

    # 发送请求并获取结果
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data) as response:
            result = await response.json()
            if result.get("errcode") == 0:
                return result.get("media_id")
            else:
                raise Exception(f"Error uploading media: {result.get('errmsg')}")
