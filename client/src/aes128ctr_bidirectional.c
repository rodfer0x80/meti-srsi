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
#include "mbedtls/aes.h"
#include "mbedtls/dhm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"

// Configs
#define WIFI_SSID                  "WIFI_SSID"
#define WIFI_PASS                  "WIFI_PASS"
#define HOST_IP_ADDR               "192.168.1.106"
#define PORT                       5666
#define BLOCK_SIZE                 4096
#define DEBUG                      false
#define TEST_DURATION_SEC          60
// ----

#define HMAC_SIZE                  32
#define HEADER_SIZE                4
#define DATA_LEN                   (BLOCK_SIZE - HMAC_SIZE - HEADER_SIZE)
#define PAYLOAD_SIZE               (BLOCK_SIZE - HEADER_SIZE)
#define MAX_BLOCK_SIZE             4096

static const char *TAG = "ESP32_AES128_BIDIRECTIONAL";
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

const char *P_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
const char *G_HEX = "2";

mbedtls_aes_context aes_ctx;
uint8_t tx_nonce[16];
size_t tx_nc_off = 0;
uint8_t tx_stream_block[16];

uint8_t rx_nonce[16];
size_t rx_nc_off = 0;
uint8_t rx_stream_block[16];

uint8_t hmac_key[32];

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
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS
        }
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

int send_frame(int sock, uint8_t *data, size_t len) {
    // Sends: [4-byte Length][Payload]  
    uint32_t net_len = htonl((uint32_t)len);
    if (send(sock, &net_len, 4, 0) < 0) return -1;
    int sent = 0;
    while(sent < len) {
        int r = send(sock, data + sent, len - sent, 0);
        if (r < 0) return -1;
        sent += r;
    }
    return sent;
}

int recv_frame(int sock, uint8_t **out_buf, size_t *out_len) {
    uint32_t net_len = 0;
    
    // Receive 4-byte header
    size_t header_received = 0;
    uint8_t *header_ptr = (uint8_t*)&net_len;
    while(header_received < 4) {
        int r = recv(sock, header_ptr + header_received, 4 - header_received, 0);
        if (r <= 0) return -1;
        header_received += r;
    }

    *out_len = ntohl(net_len);
    
    // Safety check for overflow length
    if (*out_len > MAX_BLOCK_SIZE*4) { 
        ESP_LOGE(TAG, "Packet too large: %d", *out_len);
        return -1; 
    }

    *out_buf = malloc(*out_len);
    if (!*out_buf) return -1;
    
    // Force recv loop until ALL bytes arrive
    size_t total_received = 0;
    while (total_received < *out_len) {
        int r = recv(sock, *out_buf + total_received, *out_len - total_received, 0);
        if (r <= 0) {
            free(*out_buf);
            return -1;
        }
        total_received += r;
    }
    
    return 0;
}


int perform_handshake(int sock) {
    ESP_LOGI(TAG, "Starting Handshake...");
    
    mbedtls_dhm_context dhm;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_dhm_init(&dhm);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    const char *pers = "esp32";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

    // Set up DH parameters (RFC 3526 Group 14)
    mbedtls_mpi P, G;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_read_string(&P, 16, P_HEX);
    mbedtls_mpi_read_string(&G, 16, G_HEX);
    mbedtls_dhm_set_group(&dhm, &P, &G);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&G);

    // 1. Receive Server Public Key 
    uint8_t *srv_key = NULL;
    size_t srv_len = 0;
    if (recv_frame(sock, &srv_key, &srv_len) < 0) {
        ESP_LOGE(TAG, "Failed to receive server public key");
        return -1;
    }
    ESP_LOGI(TAG, "Received server public key (%u bytes)", srv_len);
    mbedtls_dhm_read_public(&dhm, srv_key, srv_len);
    free(srv_key);

    // Generate and Send Client Public Key 
    size_t pub_len = mbedtls_dhm_get_len(&dhm);
    uint8_t *pub_buf = malloc(pub_len);
    if (!pub_buf) {
        ESP_LOGE(TAG, "Failed to allocate public key buffer");
        return -1;
    }
    mbedtls_dhm_make_public(&dhm, (int)pub_len, pub_buf, pub_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    ESP_LOGI(TAG, "Sending client public key (%u bytes)", pub_len);
    send_frame(sock, pub_buf, pub_len);
    free(pub_buf);

    // Calculate Shared Secret
    size_t dhm_len = mbedtls_dhm_get_len(&dhm);  
    uint8_t *final_secret = malloc(dhm_len);
    if (!final_secret) {
        ESP_LOGE(TAG, "Failed to allocate secret buffer");
        mbedtls_dhm_free(&dhm);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return -1;
    }
    
    size_t act_len;
    mbedtls_dhm_calc_secret(&dhm, final_secret, dhm_len, &act_len, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (DEBUG){
        ESP_LOGW(TAG, ">>> SHARED SECRET DEBUG <<<");
        ESP_LOGI(TAG, "Shared secret actual length: %u bytes", act_len);
    }

    // Key Derivation using SHA256
    uint8_t hash1[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0); 
    mbedtls_sha256_update(&sha_ctx, final_secret, act_len);
    mbedtls_sha256_finish(&sha_ctx, hash1);
    mbedtls_sha256_free(&sha_ctx);
    
    uint8_t hash2[32];
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, hash1, 32);
    mbedtls_sha256_finish(&sha_ctx, hash2);
    mbedtls_sha256_free(&sha_ctx);

    uint8_t hash3[32];
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, hash2, 32);
    mbedtls_sha256_finish(&sha_ctx, hash3);
    mbedtls_sha256_free(&sha_ctx);
    
    uint8_t derived[64];
    memcpy(derived, hash1, 32);
    memcpy(derived + 32, hash2, 32);
    
    memcpy(hmac_key, hash3, 32);
    
    free(final_secret);
    
    // Extract nonces
    memset(tx_nonce, 0, 16);
    memcpy(tx_nonce, derived + 32, 8);
    
    memset(rx_nonce, 0, 16);
    memcpy(rx_nonce, derived + 40, 8);
   
    if (DEBUG){
        ESP_LOG_BUFFER_HEX("TX NONCE FULL (16)", tx_nonce, 16);
        ESP_LOG_BUFFER_HEX("RX NONCE FULL (16)", rx_nonce, 16);
    }

    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, derived, 128); 
    
    tx_nc_off = 0;
    rx_nc_off = 0;

    mbedtls_dhm_free(&dhm);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    ESP_LOGI(TAG, "Handshake complete - Encryption Tunnel Active");
    return 0;
}

void tcp_client_task(void *pvParameters) {
    ESP_LOGI(TAG, "Waiting for Wi-Fi...");
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    ESP_LOGI(TAG, "Wi-Fi Connected! Starting TCP setup...");

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
    
    if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0) {
        ESP_LOGE(TAG, "Connect failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    
    ESP_LOGI(TAG, "Connected to server");
    
    if (perform_handshake(sock) != 0) {
        ESP_LOGE(TAG, "Handshake failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    int64_t start_time = esp_timer_get_time(); 
    int64_t duration_us = TEST_DURATION_SEC * 1000000LL; 
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);  

    uint8_t *raw_data = malloc(DATA_LEN);
    uint8_t *packet = malloc(PAYLOAD_SIZE);
    uint8_t *decrypted_rx = malloc(PAYLOAD_SIZE);

    if (!raw_data || !packet || !decrypted_rx) {
        ESP_LOGE(TAG, "Failed to allocate heap memory for buffers");
        if(raw_data) free(raw_data);
        if(packet) free(packet);
        if(decrypted_rx) free(decrypted_rx);
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    memset(raw_data, 'A', DATA_LEN);
    
    ESP_LOGW(TAG, ">>> STARTING AES128 BIDIRECTIONAL (Data: %d + HMAC: %d  + HEADER: %d = %d Total) <<<", 
             DATA_LEN, HMAC_SIZE, HEADER_SIZE, BLOCK_SIZE);

    while ((esp_timer_get_time() - start_time) < duration_us) {
        
        // SENDING
        mbedtls_aes_crypt_ctr(&aes_ctx, DATA_LEN, &tx_nc_off, tx_nonce, tx_stream_block, 
                              raw_data, packet);
        
        // HMAC
        mbedtls_md_hmac(md_info, hmac_key, 32, packet, DATA_LEN, packet + DATA_LEN);
        
        // [Header: 4 bytes | Data: DATA_LEN bytes | HMAC: 32 bytes]
        if (send_frame(sock, packet, PAYLOAD_SIZE) < 0) {
            ESP_LOGE(TAG, "Send failed");
            break;
        }

        // RECEIVING
        uint8_t *rx_buf = NULL;
        size_t rx_len = 0;
        
        // Block until server replies
        if (recv_frame(sock, &rx_buf, &rx_len) < 0) {
            ESP_LOGE(TAG, "Recv failed or Server closed");
            break;
        }

        // HMAC check
        if (rx_len > HMAC_SIZE) {
            size_t data_size = rx_len - HMAC_SIZE;
 
            uint8_t expected_hmac[32];
            mbedtls_md_hmac(md_info, hmac_key, 32, rx_buf, data_size, expected_hmac);
            
            if (memcmp(expected_hmac, rx_buf + data_size, 32) != 0) {
                ESP_LOGE(TAG, "RX HMAC Mismatch!");
                break;
            }

            // Decrypt - advance RX Nonce
            mbedtls_aes_crypt_ctr(&aes_ctx, data_size, &rx_nc_off, rx_nonce, rx_stream_block, 
                                  rx_buf, decrypted_rx);
        } else {
             ESP_LOGW(TAG, "Packet too small for HMAC");
        }

        free(rx_buf); 
    }
    
    
    free(raw_data);
    free(packet);
    free(decrypted_rx);
    close(sock);
    vTaskDelete(NULL);
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    wifi_init_sta();
    
    if (BLOCK_SIZE < 4096) {
         xTaskCreate(tcp_client_task, "tcp_client", MAX_BLOCK_SIZE*4, NULL, 5, NULL);
    } else {
        xTaskCreate(tcp_client_task, "tcp_client", MAX_BLOCK_SIZE*8, NULL, 5, NULL);
    }
}