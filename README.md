# BoB_network_gilgil
BoB 13기 3차 교육(공통)에서 '무선 네트워크' 수업의 내용을 담고 있습니다. 


Deeply Thanks to Best of the Best, KITRI, gilgil_mentor

https://gitlab.com/gilgil/sns/-/wikis/dot11-frame/report-airodump

https://gitlab.com/gilgil/sns/-/wikis/dot11-frame/report-beacon-flood


## 1. 무선 네트워크의 기본 개념

### 무선 네트워크란?

- *무선 네트워크(Wi-Fi)**는 유선 케이블 대신 전파(라디오 주파수)를 통해 데이터를 주고받는 네트워크입니다.
- *액세스 포인트(AP)**라는 장치가 주변에 무선 신호를 브로드캐스트(전송)하며, 스마트폰, 노트북, 태블릿 등의 클라이언트가 이 신호를 받아 인터넷에 접속합니다.

### 주요 구성요소

- **액세스 포인트(AP):**
    
    네트워크 신호를 전송하고 관리하는 장비로, 주변에 신호(SSID)를 브로드캐스트합니다.
    
- **클라이언트:**
    
    무선 네트워크에 접속하는 기기(예: 스마트폰, 노트북 등)이며, AP가 전송하는 신호를 수신합니다.
    
- **SSID (Service Set Identifier):**
    
    네트워크 이름을 의미합니다. 사용자가 Wi-Fi 목록에서 선택하는 이름으로, Beacon 프레임에 포함되어 있습니다.
    

---

## 2. 무선 네트워크 보안

무선 네트워크 보안은 데이터를 안전하게 전송하고, 무단 접근을 방지하는 여러 기술과 프로토콜을 포함합니다.

### 주요 보안 프로토콜

- **WEP (Wired Equivalent Privacy):**
    
    초기 무선 보안 방식이나, 현재는 매우 취약하여 사용되지 않습니다.
    
- **WPA/WPA2 (Wi-Fi Protected Access):**
    
    향상된 암호화 방법을 사용하여 보안을 강화한 프로토콜입니다.
    
    특히 WPA2는 현재 대부분의 무선 네트워크에서 사용되며, 802.1X 기반 인증 방식을 도입하여 네트워크에 접속하기 전에 사용자가 올바른 자격 증명을 제공하도록 합니다.
    

### 802.1X 인증 시스템과 EAP

- **802.1X 인증:**
    
    네트워크에 접속하기 전에 클라이언트가 인증을 거치도록 하는 표준입니다.
    
- **EAP (Extensible Authentication Protocol):**
    
    802.1X 인증 과정 중 클라이언트와 인증 서버(보통 RADIUS 서버) 사이에서 사용되는 프로토콜입니다.
    
    - **EAP 요청/응답:**
        
        클라이언트와 서버가 주고받는 메시지로, 올바른 자격 증명이 있는지 확인합니다.
        
        이 과정을 분석하면, 인증 과정 중 발생하는 문제(예: 타이밍 오류, 프로토콜 미스매치 등)를 파악할 수 있습니다.




## 3. 무선 네트워크 모니터링 및 테스트 도구

네트워크 보안을 점검하거나 취약점을 확인하기 위해 아래와 같은 도구들을 사용합니다.

### 3.1. airmon-ng

- **기능:**
    
    무선 네트워크 어댑터를 모니터 모드로 전환해 주는 도구입니다.
    
- **모니터 모드란?**
    
    일반적인 “Managed 모드”에서는 AP와의 연결이 필요하지만, 모니터 모드에서는 주변의 모든 무선 패킷(관리, 제어, 데이터 프레임)을 수신할 수 있습니다.
    
- **사용 예:**
    
    ```bash
    
    sudo airmon-ng start wlan0
    ```
    
    위 명령어로 wlan0 인터페이스를 모니터 모드로 전환하게 되면, 보통 인터페이스 이름이 “mon0”처럼 바뀝니다.
    

### 3.2. airodump-ng

- **기능:**
    
    모니터 모드 상태의 무선 인터페이스에서 지나가는 패킷들을 실시간으로 캡처하고, AP와 클라이언트의 정보를 표시하는 도구입니다.
    
- **주요 용도:**
    - 주변 AP의 SSID, BSSID(메인 MAC 주소), 채널, 신호 강도 등의 정보를 확인할 수 있습니다.
    - **EAP 핸드셰이크 캡처:**
        
        802.1X 인증 시스템에서 발생하는 EAP 요청과 응답을 포함한 인증 핸드셰이크를 캡처하여 분석할 수 있습니다.
        
- **사용 예:**
    
    ```bash
    sudo airodump-ng mon0
    
    ```
    
    이렇게 실행하면 네트워크 내 AP와 클라이언트의 정보가 화면에 나타납니다.
    

### 3.3. MDK3

- **개요:**
    
    MDK3는 무선 네트워크의 취약점을 스트레스 테스트하는 도구로, 다양한 테스트 모드를 제공합니다.
    
- **주요 테스트 모드:**
    - **Beacon Flooding (b):**
        
        가짜 AP를 다수 생성해 Beacon 프레임을 전송함으로써, 네트워크 스캐너나 클라이언트 기기를 혼란스럽게 만듭니다.
        
    - **Authentication DoS (a):**
        
        주변의 AP에 대량의 인증 요청을 보내 AP나 클라이언트의 정상 동작을 방해합니다.
        
    - **Deauthentication (d):**
        
        AP에 연결된 모든 클라이언트를 강제로 로그아웃 시켜 네트워크 접속을 방해합니다.
        
    - **WPA Downgrade (g):**
        
        WPA 암호화된 네트워크의 장비에 대해 탈인증 공격을 수행하여, 보안 설정을 낮추도록 유도할 수 있습니다.
        
- **사용 예:**
    - Beacon Flooding 공격은 다음과 같이 실행합니다.
        
        ```bash
        
        sudo mdk3 mon0 b
        
        ```
        
    - Deauthentication 공격의 경우, 특정 채널에서 대상 AP의 클라이언트를 끊고자 할 때:
        
        ```bash
        
        sudo mdk3 mon0 d -c 6
        
        ```
        
        위 명령어는 채널 6에서 모든 클라이언트에 탈인증(로그아웃) 프레임을 전송합니다.


 ```bash
         [Client (Supplicant)]
                   │
  (EAPOL-Start/ EAP-Response)
                   │
                   ▼
         [Authenticator (AP/Switch)]
                   │
        (Forwards EAP messages)
                   │
                   ▼
    [Authentication Server (RADIUS)]

```
