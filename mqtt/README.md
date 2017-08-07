# Zephyr+FRDM-K64F+MQTT 接入中国移动 OneNET 云平台

- [云端操作](#云端操作)
    - [基本操作](#基本操作)
    - [设置数据流](#设置数据流)
    - [创建应用](#创建应用)
- [本地操作](#本地操作)
    - [硬件接线](#硬件接线)
    - [下载源码](#下载源码)
    - [修改配置](#修改配置)
    - [编译&烧写](#编译&烧写)
- [效果](#效果)

# 云端操作

## 基本操作
参考 [OneNET 官方文档](https://open.iot.10086.cn/doc/art253.html#68) 依次创建产品、设备，并设置鉴权信息，它们是 MQTT 协议中的三个抽象：
- 产品 ID 即 MQTT 的 username
- 设备 ID 即 MQTT 的 client id
- 鉴权信息即 MQTT 的 password

## 设置数据流

参考 [OneNET 官方文档](https://open.iot.10086.cn/doc/art242.html#65) 创建两个数据流。本仓库通过温湿度传感器 AM2320　采集温度和湿度，并将其采集结果上传至云平台，所以需要在 OneNET 上面创建两个数据流，其名称分别是 `temperature` 和　`humidity`。

## 创建应用

参考 [OneNET 官方文档](https://open.iot.10086.cn/doc/art242.html#65) 创建应用。创建应用的目的是将数据流以直观的图形形式展现出来。

# 本地操作

## 硬件接线

使用温湿度传感器 AM2320 采集并上传温湿度，其与 frdm-k64f 的接线为：

AM2320 | FRDM-K64F
------:|:--------
VDD    | J3-4
SDA    | J2-18
GND    | J3-14
SCL    | J2-20

**如果没有传感器 AM2320，请修改源代码 `src/main.c` 中的函数 `prepare_mqtt_publish_msg`，上传固定的温湿度值，例如**：
```bash
static void prepare_mqtt_publish_msg(struct mqtt_publish_msg *pub_msg,
                 enum mqtt_qos qos)
{
    static char buf[128];
    
    memset(buf, 0, sizeof(buf));

    //sensor_read();
    
    sprintf(&buf[3], "{\"%s\":%d.%1d,\"%s\":%d.%1d}", 
            "temperature", 25, 3, "humidity", 46, 7);
    printk("%s\n", &buf[3]);
    uint16_t len = strlen(&buf[3]);
    buf[0] = 0x03;
    buf[1] = len >> 8;
    buf[2] = len & 0xFF;
    pub_msg->msg = buf;
    pub_msg->msg_len = len + 3;

    pub_msg->topic = "$dp";
    pub_msg->topic_len = strlen(client_ctx.pub_msg.topic);
    pub_msg->qos = qos;
    pub_msg->pkt_id = sys_rand32_get();
}

```
## 下载源码

下载本仓库源码：
```bash
$ git clone https://github.com/tidyjiang8/zephyr-cloud.git
$ cd zephyr-cloud/mqtt
```

## 修改配置

根据云端的产品、设备、鉴权信息修改源代码的配置信息，需要修改的文件是 `include/config.h`，需要修改的内容是：
```c
#define MQTT_CLIENTID 	"your_device_id"
#define MQTT_USERNAME	"your_project_id"
#define MQTT_PASSWORD	"your_auth_info"
```

## 编译&烧写

进入你的 zephyr 的根目录，执行操作：
```bash
$ source zephyr-env.sh
```

然后再进入本仓库的目录（即 `zephyr-cloud/mqtt/`），然后编译并烧写：
```bash
$ make flash
```

# 效果

<center>

![](img/onenet-mqtt.png)

</center>


