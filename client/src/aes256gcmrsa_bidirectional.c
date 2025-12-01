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
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

// Configs
#define WIFI_SSID                  "WIFI_SSID"
#define WIFI_PASS                  "WIFI_PASS"
#define HOST_IP_ADDR               "192.168.1.106"
#define PORT                       5666
#define BLOCK_SIZE                 51
#define TEST_DURATION_SEC          60

// AES-GCM Constants
#define AES_KEY_BITS               256
#define AES_KEY_LEN_BYTES          (AES_KEY_BITS / 8) // 32 bytes
#define GCM_IV_LEN                 12
#define GCM_TAG_LEN                16

// Packet Structure Calculation
// Packet = [IV (12)] + [Ciphertext (N)] + [Tag (16)]
#define PAYLOAD_OVERHEAD           (GCM_IV_LEN + GCM_TAG_LEN)
#define PLAINTEXT_LEN              (BLOCK_SIZE - PAYLOAD_OVERHEAD)
#define MAX_BLOCK_SIZE             4096

static const char *TAG = "ESP32_GCM_CLIENT";
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

// Global Contexts
mbedtls_gcm_context gcm_ctx;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
uint8_t session_key[AES_KEY_LEN_BYTES]; // 32 bytes

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

// Network Helpers
int send_frame(int sock, uint8_t *data, size_t len) {
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
    int r = recv(sock, &net_len, 4, MSG_WAITALL);
    if (r <= 0) return -1;
    *out_len = ntohl(net_len);
    
    // Safety check for malloc
    if (*out_len > MAX_BLOCK_SIZE * 2) {
        ESP_LOGE(TAG, "Frame too large: %u", *out_len);
        return -1;
    }

    *out_buf = malloc(*out_len + 1); // +1 for null terminator safety
    if (!*out_buf) return -1;
    
    r = recv(sock, *out_buf, *out_len, MSG_WAITALL);
    if (r <= 0) {
        free(*out_buf);
        return -1;
    }
    (*out_buf)[*out_len] = '\0'; // Null terminate safely
    return 0;
}

// Handshake: RSA Exchange
int perform_handshake(int sock) {
    ESP_LOGI(TAG, "Starting RSA Handshake...");
    int ret;
    mbedtls_pk_context srv_pub_key;
    
    mbedtls_pk_init(&srv_pub_key);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_gcm_init(&gcm_ctx);

    const char *pers = "esp32_gcm";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

    // 1. Receive Server Public Key (PEM format)
    uint8_t *pem_buf = NULL;
    size_t pem_len = 0;
    if (recv_frame(sock, &pem_buf, &pem_len) < 0) {
        ESP_LOGE(TAG, "Failed to receive server public key");
        return -1;
    }
    ESP_LOGI(TAG, "Received Server Key (%u bytes)", pem_len);

    // 2. Parse Public Key
    ret = mbedtls_pk_parse_public_key(&srv_pub_key, pem_buf, pem_len + 1);
    free(pem_buf); 
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to parse public key -0x%04x", -ret);
        return -1;
    }

    // 3. Configure Padding to OAEP
    if (mbedtls_pk_get_type(&srv_pub_key) == MBEDTLS_PK_RSA) {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(srv_pub_key);
        mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    } else {
        ESP_LOGE(TAG, "Server key is not RSA");
        return -1;
    }

    // 4. Generate Random Session Key
    mbedtls_ctr_drbg_random(&ctr_drbg, session_key, AES_KEY_LEN_BYTES);
    ESP_LOGI(TAG, "Generated Session Key");

    // 5. Encrypt Session Key
    uint8_t encrypted_key[512]; 
    size_t encrypted_len = 0;

    ret = mbedtls_pk_encrypt(&srv_pub_key, 
                             session_key, AES_KEY_LEN_BYTES, 
                             encrypted_key, &encrypted_len, sizeof(encrypted_key),
                             mbedtls_ctr_drbg_random, &ctr_drbg);
    
    if (ret != 0) {
        ESP_LOGE(TAG, "RSA Encrypt failed -0x%04x", -ret);
        return -1;
    }

    // 6. Send Encrypted Session Key
    ESP_LOGI(TAG, "Sending Encrypted Session Key (%u bytes)", encrypted_len);
    send_frame(sock, encrypted_key, encrypted_len);

    // 7. Initialize AES-GCM Context
    ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, session_key, AES_KEY_BITS);
    if (ret != 0) {
        ESP_LOGE(TAG, "GCM Setkey failed");
        return -1;
    }

    mbedtls_pk_free(&srv_pub_key);
    ESP_LOGI(TAG, "Handshake Complete - AES-256-GCM Active");
    return 0;
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
    
    if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0) {
        ESP_LOGE(TAG, "Connect failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    
    if (perform_handshake(sock) != 0) {
        ESP_LOGE(TAG, "Handshake failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    // --- Bidirectional Loop ---
    int64_t start_time = esp_timer_get_time();
    int64_t duration_us = TEST_DURATION_SEC * 1000000LL;

    // Buffers
    uint8_t *plaintext_out = malloc(PLAINTEXT_LEN);
    memset(plaintext_out, 'A', PLAINTEXT_LEN);

    uint8_t *tx_buffer = malloc(BLOCK_SIZE);
    
    // Buffer to hold decrypted response
    // Must be large enough for largest expected response
    uint8_t *decrypted_in = malloc(MAX_BLOCK_SIZE);

    ESP_LOGW(TAG, "Starting Bidirectional GCM. BlockSize: %d", BLOCK_SIZE);

    while ((esp_timer_get_time() - start_time) < duration_us) {
        
        // --- 1. ENCRYPT & SEND ---
        uint8_t *p_iv = tx_buffer; 
        uint8_t *p_ciphertext = tx_buffer + GCM_IV_LEN; 
        uint8_t *p_tag = tx_buffer + GCM_IV_LEN + PLAINTEXT_LEN;

        // Generate IV
        mbedtls_ctr_drbg_random(&ctr_drbg, p_iv, GCM_IV_LEN);

        // Encrypt
        int ret = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, 
                                            PLAINTEXT_LEN, 
                                            p_iv, GCM_IV_LEN, 
                                            NULL, 0, // AAD
                                            plaintext_out, p_ciphertext, 
                                            GCM_TAG_LEN, p_tag);
        if (ret != 0) {
            ESP_LOGE(TAG, "Encrypt failed");
            break;
        }

        if (send_frame(sock, tx_buffer, BLOCK_SIZE) < 0) {
            ESP_LOGE(TAG, "Send failed");
            break;
        }

        // --- 2. RECEIVE & DECRYPT ---
        uint8_t *rx_buf = NULL;
        size_t rx_len = 0;

        if (recv_frame(sock, &rx_buf, &rx_len) < 0) {
            ESP_LOGE(TAG, "Recv failed");
            break;
        }

        // Sanity Check Length
        if (rx_len < PAYLOAD_OVERHEAD) {
            ESP_LOGE(TAG, "RX Packet too short");
            free(rx_buf);
            break;
        }

        // Parse Structure: [IV (12)] + [Ciphertext (Len-28)] + [Tag (16)]
        size_t rx_cipher_len = rx_len - PAYLOAD_OVERHEAD;
        uint8_t *rx_iv = rx_buf;
        uint8_t *rx_ciphertext = rx_buf + GCM_IV_LEN;
        uint8_t *rx_tag = rx_buf + GCM_IV_LEN + rx_cipher_len;

        ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, rx_cipher_len,
                                       rx_iv, GCM_IV_LEN,
                                       NULL, 0, // AAD
                                       rx_tag, GCM_TAG_LEN,
                                       rx_ciphertext, decrypted_in);
        
        if (ret != 0) {
            ESP_LOGE(TAG, "Decrypt/Auth Failed: -0x%04x", -ret);
            free(rx_buf);
            break;
        }

        // Null terminate and print
        if (rx_cipher_len < MAX_BLOCK_SIZE) {
            decrypted_in[rx_cipher_len] = '\0';
            //ESP_LOGI(TAG, "RX Decrypted: %s", decrypted_in);
        }

        free(rx_buf);
    }
    
    free(plaintext_out);
    free(decrypted_in);
    free(tx_buffer);
    mbedtls_gcm_free(&gcm_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    close(sock);
    vTaskDelete(NULL);
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    wifi_init_sta();
    if (BLOCK_SIZE < MAX_BLOCK_SIZE) {
        xTaskCreate(tcp_client_task, "tcp_client", MAX_BLOCK_SIZE*4, NULL, 5, NULL);
    } else {
        xTaskCreate(tcp_client_task, "tcp_client", MAX_BLOCK_SIZE*8, NULL, 5, NULL);
    }
}
