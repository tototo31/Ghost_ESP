#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"

#ifdef __cplusplus
extern "C" {
#endif

// LoRa configuration structure
typedef struct {
    gpio_num_t spi_mosi_pin;
    gpio_num_t spi_miso_pin;
    gpio_num_t spi_clk_pin;
    gpio_num_t spi_cs_pin;
    gpio_num_t reset_pin;
    gpio_num_t busy_pin;
    gpio_num_t dio1_pin;
    spi_host_device_t spi_host;
    uint32_t frequency_hz;      // Frequency in Hz (e.g., 915000000 for 915 MHz)
    uint8_t spreading_factor;   // 6-12
    uint8_t bandwidth;          // 0=7.8kHz, 1=10.4kHz, 2=15.6kHz, 3=20.8kHz, 4=31.25kHz, 5=41.7kHz, 6=62.5kHz, 7=125kHz, 8=250kHz, 9=500kHz
    uint8_t coding_rate;        // 1-4 (coding rate = 4/(coding_rate+1))
    uint8_t tx_power;          // 0-22 dBm
    bool crc_enabled;
    bool implicit_header;
    uint8_t preamble_length;   // Default 8
} lora_config_t;

// LoRa packet structure
typedef struct {
    uint8_t data[255];
    uint8_t length;
    int16_t rssi;
    float snr;
    uint32_t frequency_error;
} lora_packet_t;

// Initialize LoRa manager with configuration
esp_err_t lora_manager_init(const lora_config_t *config);

// Deinitialize LoRa manager
void lora_manager_deinit(void);

// Check if LoRa is initialized
bool lora_manager_is_initialized(void);

// Set frequency (in Hz)
esp_err_t lora_manager_set_frequency(uint32_t frequency_hz);

// Set spreading factor (6-12)
esp_err_t lora_manager_set_spreading_factor(uint8_t sf);

// Set bandwidth (0-9, see lora_config_t for mapping)
esp_err_t lora_manager_set_bandwidth(uint8_t bw);

// Set coding rate (1-4)
esp_err_t lora_manager_set_coding_rate(uint8_t cr);

// Set TX power (0-22 dBm)
esp_err_t lora_manager_set_tx_power(uint8_t power);

// Start receiving packets
esp_err_t lora_manager_start_receive(void);

// Stop receiving packets
void lora_manager_stop_receive(void);

// Check if receiving
bool lora_manager_is_receiving(void);

// Send a packet (blocking)
esp_err_t lora_manager_send_packet(const uint8_t *data, uint8_t length);

// Send a packet (non-blocking, returns immediately)
esp_err_t lora_manager_send_packet_async(const uint8_t *data, uint8_t length);

// Check if packet is available
bool lora_manager_packet_available(void);

// Read received packet (non-blocking)
esp_err_t lora_manager_read_packet(lora_packet_t *packet);

// Set callback for received packets
typedef void (*lora_rx_callback_t)(const lora_packet_t *packet);
void lora_manager_set_rx_callback(lora_rx_callback_t callback);

// Get RSSI of last received packet
int16_t lora_manager_get_last_rssi(void);

// Get SNR of last received packet
float lora_manager_get_last_snr(void);

// Put radio in sleep mode
esp_err_t lora_manager_sleep(void);

// Wake radio from sleep
esp_err_t lora_manager_wake(void);

// Get current configuration
esp_err_t lora_manager_get_config(lora_config_t *config);

#ifdef __cplusplus
}
#endif
