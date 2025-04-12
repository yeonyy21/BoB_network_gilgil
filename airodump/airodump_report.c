/******************************************************************************
 *  Compile:  gcc -o airodump airodump.c -lpthread
 *  Usage:    sudo ./airodump -i mon0 [-t hop_interval] [-m max_channel]
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <errno.h>
#include <getopt.h>

// default settings
#define DEFAULT_MAX_CHANNEL 14
#define DEFAULT_HOP_INTERVAL 1
#define MAX_AP_LIST 256

// AP structure
typedef struct _ap_info {
    unsigned char bssid[6]; // BSSID (MAC 주소)
    char essid[33];         // ESSID (최대 32바이트 + NULL)
    int beacon_count;       // 비콘 프레임 수신 횟수
    int data_count;         // 데이터 프레임 수신 횟수 (확장 가능)
    int pwr;                // 신호 세기(dBm)
    char enc[32];           // 암호화 방식 (예: "WEP", "WPA2")
} ap_info;

static ap_info g_ap_list[MAX_AP_LIST]; // AP 정보를 저장하는 리스트
static int g_ap_count = 0;             // 현재 저장된 AP 개수

static char g_iface[IFNAMSIZ] = {0};   // 무선 인터페이스 이름
static int g_stop_hopping = 0;         // 채널 호핑 중지 플래그
static int g_current_channel = 1;      // 현재 채널 번호
static int g_max_channel = DEFAULT_MAX_CHANNEL;
static int g_hop_interval = DEFAULT_HOP_INTERVAL;

pthread_mutex_t ap_list_mutex = PTHREAD_MUTEX_INITIALIZER; // AP 리스트 보호용 mutex

// BSSID -> (XX:XX:XX:XX:XX:XX)
void bssid_to_str(unsigned char *bssid, char *str, size_t size) {
    snprintf(str, size, "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2],
             bssid[3], bssid[4], bssid[5]);
}

// find BSSID in AP list
ap_info *find_or_insert_ap(unsigned char *bssid) {
    pthread_mutex_lock(&ap_list_mutex);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            pthread_mutex_unlock(&ap_list_mutex);
            return &g_ap_list[i];
        }
    }
    if (g_ap_count < MAX_AP_LIST) {
        ap_info *new_ap = &g_ap_list[g_ap_count++];
        memset(new_ap, 0, sizeof(ap_info));
        memcpy(new_ap->bssid, bssid, 6);
        strcpy(new_ap->essid, "<unknown>");
        strcpy(new_ap->enc, "unknown"); // 추후 암호화 정보 파싱 추가 가능
        pthread_mutex_unlock(&ap_list_mutex);
        return new_ap;
    }
    pthread_mutex_unlock(&ap_list_mutex);
    return NULL; // 리스트가 가득 찼을 경우
}

// does channel_hopping 
void *channel_hopper(void *arg) {
    int channel = 1;
    char cmd[128];
    while (!g_stop_hopping) {
        snprintf(cmd, sizeof(cmd), "iw dev %s set channel %d", g_iface, channel);
        system(cmd); // 채널 변경 (오류 체크는 추후 보강 가능)
        g_current_channel = channel;
        channel = (channel % g_max_channel) + 1;
        sleep(g_hop_interval);
    }
    pthread_exit(NULL);
}

// Radiotap header -> RSSI
int parse_radiotap_header(const unsigned char *packet, int *dbm_signal) {
    // Radiotap 헤더 길이는 3번째, 4번째 바이트에 저장 (리틀엔디언)
    unsigned short radiotap_len = packet[2] + (packet[3] << 8);
    // 간단한 예제로 특정 오프셋(22번)이 dBm 값이라고 가정
    *dbm_signal = (radiotap_len > 22) ? (int)((signed char)packet[22]) : 0;
    return radiotap_len;
}

// 802.11 Beacon 프레임을 분석하여 AP 정보를 업데이트하는 함수
// 추가로 데이터 프레임이나 암호화 방식 분석 로직을 확장할 수 있음.
void parse_beacon_frame(const unsigned char *ieee80211, int length, int dbm_signal) {
    // Beacon 프레임 구조: 802.11 header (24바이트) + Fixed Params (12바이트) 이후 Tagged Parameters
    const unsigned char *bssid = &ieee80211[16];
    ap_info *ap = find_or_insert_ap((unsigned char *)bssid);
    if (!ap)
        return;

    ap->pwr = dbm_signal;
    ap->beacon_count++;

    // Fixed header 이후의 offset: 24 (header) + 12 (fixed) = 36
    int offset = 36;
    while (offset + 2 < length) {
        unsigned char tag_number = ieee80211[offset];
        unsigned char tag_len = ieee80211[offset + 1];
        offset += 2;
        if (offset + tag_len > length)
            break;
        if (tag_number == 0) { // SSID 태그
            memset(ap->essid, 0, sizeof(ap->essid));
            if (tag_len > 0 && tag_len < sizeof(ap->essid)) {
                memcpy(ap->essid, &ieee80211[offset], tag_len);
                ap->essid[tag_len] = '\0';
            } else {
                strcpy(ap->essid, "<hidden>");
            }
            // 필요 시 암호화 정보 (예: RSN 태그 48번)도 여기서 파싱 가능
            break;
        }
        offset += tag_len;
    }
}

// 데이터 프레임 파싱: 802.11 데이터 프레임의 헤더를 분석하여 AP의 BSSID를 추출한 후, 해당 AP의 데이터 프레임 카운트를 증가시킵니다.
void parse_data_frame(const unsigned char *ieee80211, int length) {
    if (length < 24)
        return; // 헤더 길이가 24바이트 미만이면 올바른 802.11 프레임이 아님

    // Frame Control 필드 (2바이트) 읽기
    unsigned short frame_control = ieee80211[0] | (ieee80211[1] << 8);

    // To DS와 From DS 비트 추출
    int to_ds = (frame_control & 0x0100) ? 1 : 0;
    int from_ds = (frame_control & 0x0200) ? 1 : 0;

    const unsigned char *bssid = NULL;

    /*
        일반적인 데이터 프레임의 경우:
        - "From DS" = 1, "To DS" = 0 : AP에서 STA로 전송되는 프레임 -> BSSID는 Address 2 (offset 10)
        - "To DS" = 1, "From DS" = 0 : STA에서 AP로 전송되는 프레임 -> BSSID는 Address 1 (offset 4)
        - "To DS" = 0, "From DS" = 0 : Ad hoc 모드 (IBSS) -> BSSID는 Address 3 (offset 16)로 사용하거나 상황에 맞게 처리
        - "To DS" = 1, "From DS" = 1 : WDS (Wireless Distribution System) 등 -> 여기서는 간단하게 Address 3 (offset 16)을 사용
    */
    if (from_ds && !to_ds) {
        // AP가 전송한 프레임인 경우: Address 2가 AP의 MAC 주소임 (offset 10)
        bssid = ieee80211 + 10;
    } else if (to_ds && !from_ds) {
        // STA가 AP로 전송한 프레임: Address 1이 AP의 MAC 주소임 (offset 4)
        bssid = ieee80211 + 4;
    } else if (!to_ds && !from_ds) {
        // Ad hoc 모드 등: 일반적으로 Address 3를 사용 (offset 16)
        bssid = ieee80211 + 16;
    } else {
        // 복합 경우 (To DS && From DS): 여기서는 기본적으로 Address 3를 사용
        bssid = ieee80211 + 16;
    }

    // 추출한 BSSID를 기반으로 AP 리스트에 해당 AP를 찾거나 새로 추가
    ap_info *ap = find_or_insert_ap((unsigned char *)bssid);
    if (ap) {
        ap->data_count++;  // 데이터 프레임 카운트 증가
    }
}


void print_ap_list() {
    system("clear");
    printf("[ Channel Hopping: Current Channel = %d ]\n", g_current_channel);
    printf(" BSSID              PWR   Beacons   ESSID                ENC\n");
    printf("------------------------------------------------------------------\n");

    pthread_mutex_lock(&ap_list_mutex);
    for (int i = 0; i < g_ap_count; i++) {
        char bssid_str[18];
        bssid_to_str(g_ap_list[i].bssid, bssid_str, sizeof(bssid_str));
        printf(" %-17s  %-4d  %-8d  %-20s  %s\n",
               bssid_str,
               g_ap_list[i].pwr,
               g_ap_list[i].beacon_count,
               g_ap_list[i].essid,
               g_ap_list[i].enc);
    }
    pthread_mutex_unlock(&ap_list_mutex);
}

int main(int argc, char *argv[]) {
    int opt;
    // 명령행 인자로 인터페이스, 채널 개수, 채널 전환 주기를 받을 수 있도록 처리
    while ((opt = getopt(argc, argv, "i:t:m:")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(g_iface, optarg, IFNAMSIZ - 1);
                break;
            case 't':
                g_hop_interval = atoi(optarg);
                break;
            case 'm':
                g_max_channel = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s -i <interface> [-t hop_interval] [-m max_channel]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (strlen(g_iface) == 0) {
        fprintf(stderr, "Interface is required. Usage: %s -i <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Raw 소켓 생성
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    // 인터페이스 인덱스 가져오기
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, g_iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl-SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }

    // 소켓 바인딩
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    // 채널 호핑 쓰레드 시작
    pthread_t tid;
    if (pthread_create(&tid, NULL, channel_hopper, NULL) != 0) {
        perror("pthread_create");
        close(sockfd);
        return -1;
    }

    unsigned char buffer[2048];
    ssize_t n;
    while (1) {
        n = recv(sockfd, buffer, sizeof(buffer), 0);
        if (n <= 0) {
            perror("recv");
            break;
        }
        if (n < 36)
            continue;
        
        int dbm_signal = 0;
        int radiotap_len = parse_radiotap_header(buffer, &dbm_signal);
        if (radiotap_len < 0 || radiotap_len > n)
            continue;
        
        // 802.11 헤더 시작
        const unsigned char *ieee80211 = buffer + radiotap_len;
        int ieee80211_len = n - radiotap_len;
        if (ieee80211_len < 24)
            continue;
        
        unsigned char frame_control = ieee80211[0];
        unsigned char type = (frame_control & 0x0C) >> 2;
        unsigned char subtype = (frame_control & 0xF0) >> 4;
        
        // 관리 프레임 & Beacon (type 0, subtype 8)
        if (type == 0 && subtype == 8) {
            parse_beacon_frame(ieee80211, ieee80211_len, dbm_signal);
        }
        // 데이터 프레임 (필요 시 type == 2 등) 예제에서는 생략
        // else if (type == 2) { parse_data_frame(ieee80211, ieee80211_len); }
        
        // 일정 주기로 출력 업데이트 (간단 예로, 매 패킷마다 출력)
        print_ap_list();
    }

    g_stop_hopping = 1;
    pthread_join(tid, NULL);
    close(sockfd);
    return 0;
}
