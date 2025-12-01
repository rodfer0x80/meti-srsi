#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

// --- Configuration ---
#define WIFI_SSID                  "WIFI_SSID"
#define WIFI_PASS                  "WIFI_PASS"
#define HOST_IP_ADDR               "192.168.1.106"
#define PORT                       5666
#define BLOCK_SIZE                 51 
#define TEST_DURATION_SEC          60

#define MAX_BLOCK_SIZE             4096
#define DATA_LEN                   BLOCK_SIZE - HEADER_SIZE
#define HEADER_SIZE                4

static const char *TAG = "ESP32_CLEARTEXT";
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

// Wifi Handler
static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));
    wifi_config_t wifi_config = { .sta = { .ssid = WIFI_SSID, .password = WIFI_PASS } };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

// Network Helper: Sends [4-byte Len] + [Data]
int send_frame(int sock, uint8_t *data, size_t len) {
    uint32_t net_len = htonl((uint32_t)len);
    // Send Header
    if (send(sock, &net_len, 4, 0) < 0) return -1;
    
    // Send Payload
    int sent = 0;
    while(sent < len) {
        int r = send(sock, data + sent, len - sent, 0);
        if (r < 0) return -1;
        sent += r;
    }
    return sent;
}

void tcp_client_task(void *pvParameters) {
    ESP_LOGI(TAG, "Waiting for Wi-Fi...");
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    ESP_LOGI(TAG, "Wi-Fi Connected! Connecting to %s:%d", HOST_IP_ADDR, PORT);

    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = inet_addr(HOST_IP_ADDR);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket");
        vTaskDelete(NULL);
        return;
    }
    
    // Attempt Connection
    if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0) {
        ESP_LOGE(TAG, "Connection failed.");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Connected.");

    // Buffer Setup
    uint8_t *data_buffer = malloc(BLOCK_SIZE);
    if (!data_buffer) {
        ESP_LOGE(TAG, "Malloc failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    memset(data_buffer, 'A', DATA_LEN);

    int64_t start_time = esp_timer_get_time();
    int64_t duration_us = TEST_DURATION_SEC * 1000000LL;
    uint32_t packet_count = 0;

    ESP_LOGW(TAG, ">>> STARTING FIXED SIZE STREAM (Data: %d + HEADER: %d = %d Total) <<<", 
             DATA_LEN, HEADER_SIZE, BLOCK_SIZE);
    while ((esp_timer_get_time() - start_time) < duration_us) {
        
        // Send raw data with the length header (BLOCK_SIZE = DATA_LEN + HEADER_SIZE)
        if (send_frame(sock, data_buffer, BLOCK_SIZE) < 0) {
            ESP_LOGE(TAG, "Send failed");
            break;
        }
        packet_count++;
        
        // Optional: Yield slightly to prevent Watchdog trigger on very tight loops
        // vTaskDelay(1); 
    }
    
    free(data_buffer);
    close(sock);
    vTaskDelete(NULL);
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    wifi_init_sta();
    xTaskCreate(tcp_client_task, "tcp_client", MAX_BLOCK_SIZE*2, NULL, 5, NULL);
}
