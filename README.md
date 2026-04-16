# BW16-WiFi-Scan-WebUI

BW16 (RTL8720DN) WiFi 扫描与Deauther工具 — Web UI版

手机连接AP热点即可操作，支持WiFi扫描、目标选择、多种攻击模式，无需OLED屏幕。

## 功能

- 📶 WiFi 扫描（2.4G/5G）
- 🎯 目标选择（单选/多选/全选）
- ⚔️ 多种攻击模式：单一/多重/全网/信标/随机信标/混合
- 📱 手机/电脑浏览器直接操作
- 🔄 实时状态轮询（发包数、运行状态）

## 使用

1. 上传固件到 BW16 开发板
2. 手机/电脑连接 WiFi `BW16-Deauther`（密码 `12345678`）
3. 浏览器打开串口提示的 AP IP 地址（通常 `http://192.168.43.1`）
4. 点击"扫描"→ 选择目标 → 开始攻击

## 依赖

- Arduino IDE + AmebaD BSP
- BW16 (RTL8720DN) 开发板

## 致谢

- 原项目：[BW16-deauther](https://github.com/david-gh/BW16-deauther)
- Web 参考项目：[BW16-WebControl](https://github.com/xiaohe4966/BW16-WebControl)

## ⚠️ 免责声明

本项目仅供学习研究使用，请勿用于非法用途。使用本工具所产生的一切法律后果由使用者自行承担。
