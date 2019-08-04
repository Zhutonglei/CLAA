# -*- coding:utf-8 -*-

import socket
import json
import time
import random
from Crypto.Hash import CMAC
from  Crypto.Cipher import AES
import sys
import struct
import re
import base64
import  datetime
import pymysql as mysqldb
import  configparser

#mysql
cf = configparser.ConfigParser()
cf.read("./config.ini")
host = cf.get(section="mysql",option="host")
port = cf.get(section="mysql",option="port")
port = int(port)
user = cf .get(section="mysql",option="user")
password =  cf .get(section="mysql",option="password")
db = cf .get(section="mysql",option="db")

config = {
    'host': host,
    'port': port,
    'user': user,
    'passwd': password,
    'db': db,
    'charset': 'utf8'
}
conn = mysqldb.connect(**config)
cursor = conn.cursor()
conn.autocommit(1)

def cut_text(text,lenth):
    textArr = re.findall('.{'+str(lenth)+'}', text)
    textArr.append(text[(len(textArr)*lenth):])
    return textArr

HOST_claa = cf.get(section="config",option="host")
PORT_claa = cf.get(section="config",option="port")
PORT_claa = int(PORT_claa)
HOST = HOST_claa  # The remote host
PORT = PORT_claa
rnd  =random.randint(0,4294967295)
num = rnd
#随机数产生challenge
appauthkey= "ffffffffffffffffffffffffffffffff"
rnd = str(hex(rnd)).split("0x")[1]
rnd = rnd.zfill(8)
appeui = "2c26c50001000001"

msg = appeui+str(rnd)+"00000000"
c = CMAC.new(appauthkey,msg,ciphermod=AES)
challenge = c.hexdigest()

dict_join={
"cmd": "join",
"cmdseq": 1,
"appeui": appeui,
"appnonce":num,
"challenge": challenge
}
message = json.dumps(dict_join)
message=message+"\0"
len_m =hex(len(message)).split("0x")[1]
header = "\n\1\2\0"
header = header.encode("hex")+str(hex(132)).split("0x")[1]

message =header+(message).encode("hex")
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 100) #心跳维护
client.connect((HOST, PORT))
client.send(message.decode("hex"))
#回复心跳包
heartbeat_ack={"cmd": "heartbeat_ack"}
heartbeat_ack =json.dumps(heartbeat_ack)+"\0"
len_heartbeat_ack = hex(len(heartbeat_ack)).split("0x")[1]
hearbeat_header = "\n\1\2\0"
hearbeat_header = hearbeat_header.encode("hex")+str(hex(25)).split("0x")[1]
heartbeat_ack = hearbeat_header+(heartbeat_ack).encode("hex")



length =0
while True:
    recvData =client.recv(1024)
    dict_info  = re.findall("{.*}",recvData)[0]
    dict_info=json.loads(dict_info)
    if dict_info["cmd"]=="heartbeat":
        client.send(heartbeat_ack.decode("hex"))
    if dict_info["cmd"]=="updata":
        length+=1
        print("------------count:{a}-------------".format(a=str(length)))
        print "Data:"+ str(dict_info)
        devEUI = dict_info["deveui"]
        detail =dict(dict_info["detail"])
        app = dict(detail["app"])
        gwrx=list(app["gwrx"])
        list_detail = dict(gwrx[0])
        rssi = list_detail["rssic"]
        loRaSNR = list_detail["lsnr"]
        motetx = dict(app["motetx"])
        frequency = motetx["freq"]
        KS = motetx["datr"]

        payload = dict_info["payload"]
        a = str(base64.b64decode(payload)).encode("hex")
        print "Payload:"+str(a)
        list_a = cut_text(str(a), 8)
        # 获取计数
        count_a = list_a[0]  # 获取data的数组
        count_b = cut_text(count_a, 2)
        count = count_b[3] + count_b[2] + count_b[1] + count_b[0]
        number = int(count, 16)
        # h获取version
        ver_a = list_a[1]
        ver_b = cut_text(ver_a, 2)
        version = ver_b[3] + ver_b[2] + ver_b[1] + ver_b[0]
        version_serial = int(version, 16)

        # 当前时间
        cur_time = time.time()
        n = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cur_time))
        total_micrsec = int((cur_time) * 1000)
        # 获取发送时间
        sendtime1 = list_a[2]
        sendtime2 = list_a[3]
        count_d = cut_text(sendtime2, 2)
        count_c = cut_text(sendtime1, 2)
        timesend = count_c[3] + count_c[2] + count_c[1] + count_c[0]
        timesend1 = count_d[1] + count_d[0]
        send_time = int(timesend, 16)
        send_time1 = int(timesend1, 16)
        if send_time1 <= 99 and send_time1 > 9:
            send_time1 = "0" + str(send_time1)
        if send_time1 <= 9:
            send_time1 = "00" + str(send_time1)
        sendtime_now = int(str(send_time) + str(send_time1))
        t = datetime.datetime.fromtimestamp(send_time)
        delay = total_micrsec - sendtime_now
        print "Sendtime:"+str(total_micrsec)
        print "Receivetime:"+str(sendtime_now)
        print "Interval:"+str(delay)

        excute_sql = "INSERT INTO receive_data VALUES('%(dev)s','%(count)s','%(version)s','%(starttime)s','%(nowtime)s','%(interval)s','%(rssi)s','%(loRaSNR)s','%(frequency)s','%(KS)s')" % {
            "dev": devEUI, "count": number, "version": version_serial, "starttime": t, "nowtime": n, "interval": delay,
            "rssi": rssi, "loRaSNR": loRaSNR, "frequency": frequency,"KS":KS}
        print excute_sql
        cursor.execute(excute_sql)








