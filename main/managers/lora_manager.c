#include "managers/lora_manager.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "LORA";

// SX1262 Register definitions
#define SX1262_REG_WRITE_REGISTER          0x0D
#define SX1262_REG_READ_REGISTER           0x1D
#define SX1262_REG_WRITE_BUFFER            0x0E
#define SX1262_REG_READ_BUFFER             0x1E
#define SX1262_REG_SET_SLEEP               0x84
#define SX1262_REG_SET_STANDBY             0x80
#define SX1262_REG_SET_RX                  0x82
#define SX1262_REG_SET_TX                  0x83
#define SX1262_REG_SET_RF_FREQUENCY         0x86
#define SX1262_REG_SET_PACKET_TYPE         0x8A
#define SX1262_REG_SET_MODULATION_PARAMS   0x8B
#define SX1262_REG_SET_PACKET_PARAMS       0x8C
#define SX1262_REG_SET_TX_PARAMS           0x8E
#define SX1262_REG_SET_DIO_IRQ_PARAMS      0x08
#define SX1262_REG_GET_IRQ_STATUS          0x12
#define SX1262_REG_CLEAR_IRQ_STATUS        0x02
#define SX1262_REG_GET_STATUS              0xC0
#define SX1262_REG_GET_RSSI_INST           0x15
#define SX1262_REG_GET_PACKET_STATUS       0x14

// IRQ masks
#define SX1262_IRQ_TX_DONE                 0x01
#define SX1262_IRQ_RX_DONE                 0x02
#define SX1262_IRQ_PREAMBLE_DETECTED       0x04
#define SX1262_IRQ_SYNC_WORD_VALID         0x08
#define SX1262_IRQ_HEADER_VALID            0x10
#define SX1262_IRQ_HEADER_ERROR            0x20
#define SX1262_IRQ_CRC_ERROR               0x40
#define SX1262_IRQ_RX_TIMEOUT              0x80
#define SX1262_IRQ_ALL                     0xFF

// Status
#define SX1262_STATUS_MODE_MASK             0x70
#define SX1262_STATUS_MODE_STANDBY_RC       0x20
#define SX1262_STATUS_MODE_STANDBY_XOSC     0x30
#define SX1262_STATUS_MODE_FS               0x40
#define SX1262_STATUS_MODE_RX               0x50
#define SX1262_STATUS_MODE_TX               0x60

// Packet types
#define SX1262_PACKET_TYPE_GFSK             0x00
#define SX1262_PACKET_TYPE_LORA            0x01

// Standby modes
#define SX1262_STANDBY_RC                  0x00
#define SX1262_STANDBY_XOSC                0x01

// Buffer size
#define SX1262_BUFFER_SIZE                 256

// Static state
static struct {
    bool initialized;
    lora_config_t config;
    spi_device_handle_t spi_device;
    SemaphoreHandle_t spi_mutex;
    TaskHandle_t rx_task_handle;
    QueueHandle_t rx_queue;
    volatile bool receiving;
    lora_rx_callback_t rx_callback;
    lora_packet_t last_packet;
    SemaphoreHandle_t tx_sem;
    volatile bool tx_done;
} s_lora = {0};

// Forward declarations
static esp_err_t sx1262_write_register(uint16_t address, uint8_t *data, uint8_t length);
static esp_err_t sx1262_read_register(uint16_t address, uint8_t *data, uint8_t length);
static esp_err_t sx1262_write_command(uint8_t command, uint8_t *data, uint8_t length);
static esp_err_t sx1262_read_command(uint8_t command, uint8_t *data, uint8_t length);
static void sx1262_wait_for_busy(void);
static esp_err_t sx1262_reset(void);
static void dio1_isr_handler(void *arg);
static void lora_rx_task(void *arg);

// Wait for BUSY pin to go low
static void sx1262_wait_for_busy(void) {
    if (s_lora.config.busy_pin != GPIO_NUM_NC) {
        int timeout = 1000; // 1 second timeout
        while (gpio_get_level(s_lora.config.busy_pin) == 1 && timeout-- > 0) {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    } else {
        // If no BUSY pin, use a small delay
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

// SPI transaction helper
static esp_err_t sx1262_spi_transfer(uint8_t *tx_data, uint8_t *rx_data, size_t length) {
    if (xSemaphoreTake(s_lora.spi_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    sx1262_wait_for_busy();

    spi_transaction_t trans = {
        .length = length * 8,
        .tx_buffer = tx_data,
        .rx_buffer = rx_data,
    };

    esp_err_t ret = spi_device_transmit(s_lora.spi_device, &trans);
    xSemaphoreGive(s_lora.spi_mutex);
    return ret;
}

// Write register (kept for future debugging/advanced features)
__attribute__((unused)) static esp_err_t sx1262_write_register(uint16_t address, uint8_t *data, uint8_t length) {
    uint8_t tx_buf[4 + length];
    tx_buf[0] = SX1262_REG_WRITE_REGISTER;
    tx_buf[1] = (address >> 8) & 0xFF;
    tx_buf[2] = address & 0xFF;
    memcpy(&tx_buf[3], data, length);
    
    return sx1262_spi_transfer(tx_buf, NULL, 3 + length);
}

// Read register (kept for future debugging/advanced features)
__attribute__((unused)) static esp_err_t sx1262_read_register(uint16_t address, uint8_t *data, uint8_t length) {
    uint8_t tx_buf[4] = {SX1262_REG_READ_REGISTER, (address >> 8) & 0xFF, address & 0xFF, 0};
    uint8_t rx_buf[4 + length];
    
    esp_err_t ret = sx1262_spi_transfer(tx_buf, rx_buf, 4 + length);
    if (ret == ESP_OK) {
        memcpy(data, &rx_buf[4], length);
    }
    return ret;
}

// Write command
static esp_err_t sx1262_write_command(uint8_t command, uint8_t *data, uint8_t length) {
    uint8_t tx_buf[1 + length];
    tx_buf[0] = command;
    if (data && length > 0) {
        memcpy(&tx_buf[1], data, length);
    }
    return sx1262_spi_transfer(tx_buf, NULL, 1 + length);
}

// Read command
static esp_err_t sx1262_read_command(uint8_t command, uint8_t *data, uint8_t length) {
    uint8_t tx_buf[1] = {command};
    uint8_t rx_buf[1 + length];
    
    esp_err_t ret = sx1262_spi_transfer(tx_buf, rx_buf, 1 + length);
    if (ret == ESP_OK && data) {
        memcpy(data, &rx_buf[1], length);
    }
    return ret;
}

// Reset the SX1262
static esp_err_t sx1262_reset(void) {
    if (s_lora.config.reset_pin == GPIO_NUM_NC) {
        ESP_LOGW(TAG, "Reset pin not configured, skipping hardware reset");
        return ESP_OK;
    }

    gpio_set_level(s_lora.config.reset_pin, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(s_lora.config.reset_pin, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
    sx1262_wait_for_busy();
    
    return ESP_OK;
}

// DIO1 interrupt handler
static void IRAM_ATTR dio1_isr_handler(void *arg) {
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    if (s_lora.rx_queue) {
        uint8_t dummy = 1;
        xQueueSendFromISR(s_lora.rx_queue, &dummy, &xHigherPriorityTaskWoken);
    }
    if (xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
}

// RX task
static void lora_rx_task(void *arg) {
    uint8_t dummy;
    uint16_t irq_status;
    uint8_t packet_status[3];
    uint8_t buffer[256];
    uint8_t rx_length;
    
    while (s_lora.receiving) {
        if (xQueueReceive(s_lora.rx_queue, &dummy, pdMS_TO_TICKS(100)) == pdTRUE) {
            // Read IRQ status
            sx1262_read_command(SX1262_REG_GET_IRQ_STATUS, (uint8_t *)&irq_status, 2);
            
            if (irq_status & SX1262_IRQ_RX_DONE) {
                // Get packet status
                sx1262_read_command(SX1262_REG_GET_PACKET_STATUS, packet_status, 3);
                
                // Read packet length
                sx1262_read_command(SX1262_REG_READ_BUFFER, buffer, 1);
                rx_length = buffer[0];
                
                if (rx_length > 0) {
                    // Read packet data
                    sx1262_read_command(SX1262_REG_READ_BUFFER, buffer, rx_length + 1);
                    
                    lora_packet_t packet;
                    packet.length = rx_length;
                    memcpy(packet.data, &buffer[1], rx_length);
                    packet.rssi = -(int16_t)packet_status[0] / 2;
                    packet.snr = (int8_t)packet_status[1] / 4.0f;
                    packet.frequency_error = 0; // Would need additional register read
                    
                    s_lora.last_packet = packet;
                    
                    if (s_lora.rx_callback) {
                        s_lora.rx_callback(&packet);
                    }
                }
                
                // Clear IRQ and restart RX
                sx1262_write_command(SX1262_REG_CLEAR_IRQ_STATUS, (uint8_t *)&irq_status, 2);
                sx1262_write_command(SX1262_REG_SET_RX, (uint8_t[]){0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 7);
            }
            
            if (irq_status & SX1262_IRQ_TX_DONE) {
                s_lora.tx_done = true;
                if (s_lora.tx_sem) {
                    xSemaphoreGive(s_lora.tx_sem);
                }
                sx1262_write_command(SX1262_REG_CLEAR_IRQ_STATUS, (uint8_t *)&irq_status, 2);
            }
            
            if (irq_status & (SX1262_IRQ_CRC_ERROR | SX1262_IRQ_HEADER_ERROR | SX1262_IRQ_RX_TIMEOUT)) {
                // Clear error and restart RX
                sx1262_write_command(SX1262_REG_CLEAR_IRQ_STATUS, (uint8_t *)&irq_status, 2);
                if (s_lora.receiving) {
                    sx1262_write_command(SX1262_REG_SET_RX, (uint8_t[]){0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 7);
                }
            }
        }
    }
    
    vTaskDelete(NULL);
}

// Initialize LoRa manager
esp_err_t lora_manager_init(const lora_config_t *config) {
    if (s_lora.initialized) {
        ESP_LOGW(TAG, "LoRa manager already initialized");
        return ESP_OK;
    }
    
    if (!config) {
        return ESP_ERR_INVALID_ARG;
    }
    
    memcpy(&s_lora.config, config, sizeof(lora_config_t));
    
    // Create mutex
    s_lora.spi_mutex = xSemaphoreCreateMutex();
    if (!s_lora.spi_mutex) {
        return ESP_ERR_NO_MEM;
    }
    
    // Create RX queue
    s_lora.rx_queue = xQueueCreate(10, sizeof(uint8_t));
    if (!s_lora.rx_queue) {
        vSemaphoreDelete(s_lora.spi_mutex);
        return ESP_ERR_NO_MEM;
    }
    
    // Create TX semaphore
    s_lora.tx_sem = xSemaphoreCreateBinary();
    if (!s_lora.tx_sem) {
        vQueueDelete(s_lora.rx_queue);
        vSemaphoreDelete(s_lora.spi_mutex);
        return ESP_ERR_NO_MEM;
    }
    
    // Configure reset pin
    if (s_lora.config.reset_pin != GPIO_NUM_NC) {
        gpio_reset_pin(s_lora.config.reset_pin);
        gpio_set_direction(s_lora.config.reset_pin, GPIO_MODE_OUTPUT);
        gpio_set_level(s_lora.config.reset_pin, 1);
    }
    
    // Configure BUSY pin
    if (s_lora.config.busy_pin != GPIO_NUM_NC) {
        gpio_reset_pin(s_lora.config.busy_pin);
        gpio_set_direction(s_lora.config.busy_pin, GPIO_MODE_INPUT);
    }
    
    // Configure DIO1 pin
    if (s_lora.config.dio1_pin != GPIO_NUM_NC) {
        gpio_reset_pin(s_lora.config.dio1_pin);
        gpio_set_direction(s_lora.config.dio1_pin, GPIO_MODE_INPUT);
        gpio_set_intr_type(s_lora.config.dio1_pin, GPIO_INTR_POSEDGE);
        gpio_install_isr_service(0);
        gpio_isr_handler_add(s_lora.config.dio1_pin, dio1_isr_handler, NULL);
    }
    
    // Configure SPI
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = s_lora.config.spi_mosi_pin,
        .miso_io_num = s_lora.config.spi_miso_pin,
        .sclk_io_num = s_lora.config.spi_clk_pin,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    
    esp_err_t ret = spi_bus_initialize(s_lora.config.spi_host, &bus_cfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize SPI bus: %s", esp_err_to_name(ret));
        goto cleanup;
    }
    
    spi_device_interface_config_t dev_cfg = {
        .clock_speed_hz = 10000000, // 10 MHz
        .mode = 0,
        .spics_io_num = s_lora.config.spi_cs_pin,
        .queue_size = 1,
    };
    
    ret = spi_bus_add_device(s_lora.config.spi_host, &dev_cfg, &s_lora.spi_device);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add SPI device: %s", esp_err_to_name(ret));
        spi_bus_free(s_lora.config.spi_host);
        goto cleanup;
    }
    
    // Reset the chip
    ret = sx1262_reset();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to reset SX1262");
        goto cleanup;
    }
    
    // Set standby mode
    sx1262_write_command(SX1262_REG_SET_STANDBY, (uint8_t[]){SX1262_STANDBY_XOSC}, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
    
    // Set packet type to LoRa
    sx1262_write_command(SX1262_REG_SET_PACKET_TYPE, (uint8_t[]){SX1262_PACKET_TYPE_LORA}, 1);
    
    // Set RF frequency
    uint32_t freq_reg = (uint32_t)((double)s_lora.config.frequency_hz / 32000000.0 * (1 << 25));
    uint8_t freq_buf[4] = {
        (freq_reg >> 24) & 0xFF,
        (freq_reg >> 16) & 0xFF,
        (freq_reg >> 8) & 0xFF,
        freq_reg & 0xFF
    };
    sx1262_write_command(SX1262_REG_SET_RF_FREQUENCY, freq_buf, 4);
    
    // Set modulation parameters
    uint8_t mod_params[4] = {
        s_lora.config.spreading_factor,
        s_lora.config.bandwidth,
        s_lora.config.coding_rate,
        0 // LowDataRateOptimize (auto)
    };
    sx1262_write_command(SX1262_REG_SET_MODULATION_PARAMS, mod_params, 4);
    
    // Set packet parameters
    uint8_t packet_params[6] = {
        0, // Preamble length MSB
        s_lora.config.preamble_length, // Preamble length LSB
        s_lora.config.implicit_header ? 1 : 0, // Header type
        255, // Payload length (explicit header) or max (implicit)
        0, // CRC disabled (will set below)
        0 // InvertIQ
    };
    if (s_lora.config.crc_enabled) {
        packet_params[4] = 1;
    }
    sx1262_write_command(SX1262_REG_SET_PACKET_PARAMS, packet_params, 6);
    
    // Set TX parameters
    uint8_t tx_params[2] = {
        s_lora.config.tx_power,
        0 // Ramp time
    };
    sx1262_write_command(SX1262_REG_SET_TX_PARAMS, tx_params, 2);
    
    // Set DIO IRQ parameters
    uint16_t irq_mask = SX1262_IRQ_TX_DONE | SX1262_IRQ_RX_DONE | 
                        SX1262_IRQ_CRC_ERROR | SX1262_IRQ_HEADER_ERROR | 
                        SX1262_IRQ_RX_TIMEOUT;
    uint8_t dio_params[8] = {
        (irq_mask >> 8) & 0xFF, irq_mask & 0xFF, // IRQ mask
        0, 0, 0, 0, 0, 0 // DIO pin masks (all 0 for now)
    };
    if (s_lora.config.dio1_pin != GPIO_NUM_NC) {
        dio_params[2] = 0x02; // DIO1 for IRQ
    }
    sx1262_write_command(SX1262_REG_SET_DIO_IRQ_PARAMS, dio_params, 8);
    
    s_lora.initialized = true;
    ESP_LOGI(TAG, "LoRa manager initialized successfully");
    return ESP_OK;
    
cleanup:
    if (s_lora.spi_device) {
        spi_bus_remove_device(s_lora.spi_device);
    }
    if (s_lora.config.spi_host >= 0) {
        spi_bus_free(s_lora.config.spi_host);
    }
    if (s_lora.tx_sem) {
        vSemaphoreDelete(s_lora.tx_sem);
        s_lora.tx_sem = NULL;
    }
    if (s_lora.rx_queue) {
        vQueueDelete(s_lora.rx_queue);
        s_lora.rx_queue = NULL;
    }
    if (s_lora.spi_mutex) {
        vSemaphoreDelete(s_lora.spi_mutex);
        s_lora.spi_mutex = NULL;
    }
    return ret;
}

// Deinitialize
void lora_manager_deinit(void) {
    if (!s_lora.initialized) {
        return;
    }
    
    lora_manager_stop_receive();
    
    // Put radio in sleep
    sx1262_write_command(SX1262_REG_SET_SLEEP, (uint8_t[]){0x00}, 1);
    
    // Cleanup SPI
    if (s_lora.spi_device) {
        spi_bus_remove_device(s_lora.spi_device);
        s_lora.spi_device = NULL;
    }
    if (s_lora.config.spi_host >= 0) {
        spi_bus_free(s_lora.config.spi_host);
    }
    
    // Remove ISR
    if (s_lora.config.dio1_pin != GPIO_NUM_NC) {
        gpio_isr_handler_remove(s_lora.config.dio1_pin);
    }
    
    // Cleanup resources
    if (s_lora.tx_sem) {
        vSemaphoreDelete(s_lora.tx_sem);
        s_lora.tx_sem = NULL;
    }
    if (s_lora.rx_queue) {
        vQueueDelete(s_lora.rx_queue);
        s_lora.rx_queue = NULL;
    }
    if (s_lora.spi_mutex) {
        vSemaphoreDelete(s_lora.spi_mutex);
        s_lora.spi_mutex = NULL;
    }
    
    s_lora.initialized = false;
    ESP_LOGI(TAG, "LoRa manager deinitialized");
}

bool lora_manager_is_initialized(void) {
    return s_lora.initialized;
}

// Set frequency
esp_err_t lora_manager_set_frequency(uint32_t frequency_hz) {
    if (!s_lora.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    s_lora.config.frequency_hz = frequency_hz;
    uint32_t freq_reg = (uint32_t)((double)frequency_hz / 32000000.0 * (1 << 25));
    uint8_t freq_buf[4] = {
        (freq_reg >> 24) & 0xFF,
        (freq_reg >> 16) & 0xFF,
        (freq_reg >> 8) & 0xFF,
        freq_reg & 0xFF
    };
    return sx1262_write_command(SX1262_REG_SET_RF_FREQUENCY, freq_buf, 4);
}

// Set spreading factor
esp_err_t lora_manager_set_spreading_factor(uint8_t sf) {
    if (!s_lora.initialized || sf < 6 || sf > 12) {
        return ESP_ERR_INVALID_ARG;
    }
    
    s_lora.config.spreading_factor = sf;
    uint8_t mod_params[4] = {
        sf,
        s_lora.config.bandwidth,
        s_lora.config.coding_rate,
        0
    };
    return sx1262_write_command(SX1262_REG_SET_MODULATION_PARAMS, mod_params, 4);
}

// Set bandwidth
esp_err_t lora_manager_set_bandwidth(uint8_t bw) {
    if (!s_lora.initialized || bw > 9) {
        return ESP_ERR_INVALID_ARG;
    }
    
    s_lora.config.bandwidth = bw;
    uint8_t mod_params[4] = {
        s_lora.config.spreading_factor,
        bw,
        s_lora.config.coding_rate,
        0
    };
    return sx1262_write_command(SX1262_REG_SET_MODULATION_PARAMS, mod_params, 4);
}

// Set coding rate
esp_err_t lora_manager_set_coding_rate(uint8_t cr) {
    if (!s_lora.initialized || cr < 1 || cr > 4) {
        return ESP_ERR_INVALID_ARG;
    }
    
    s_lora.config.coding_rate = cr;
    uint8_t mod_params[4] = {
        s_lora.config.spreading_factor,
        s_lora.config.bandwidth,
        cr,
        0
    };
    return sx1262_write_command(SX1262_REG_SET_MODULATION_PARAMS, mod_params, 4);
}

// Set TX power
esp_err_t lora_manager_set_tx_power(uint8_t power) {
    if (!s_lora.initialized || power > 22) {
        return ESP_ERR_INVALID_ARG;
    }
    
    s_lora.config.tx_power = power;
    uint8_t tx_params[2] = {power, 0};
    return sx1262_write_command(SX1262_REG_SET_TX_PARAMS, tx_params, 2);
}

// Start receive
esp_err_t lora_manager_start_receive(void) {
    if (!s_lora.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (s_lora.receiving) {
        return ESP_OK;
    }
    
    s_lora.receiving = true;
    
    // Clear IRQ status
    uint16_t irq_mask = 0xFFFF;
    sx1262_write_command(SX1262_REG_CLEAR_IRQ_STATUS, (uint8_t *)&irq_mask, 2);
    
    // Start RX task
    xTaskCreate(lora_rx_task, "lora_rx", 4096, NULL, 5, &s_lora.rx_task_handle);
    
    // Set RX mode
    uint8_t rx_params[7] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // Continuous RX
    return sx1262_write_command(SX1262_REG_SET_RX, rx_params, 7);
}

// Stop receive
void lora_manager_stop_receive(void) {
    if (!s_lora.receiving) {
        return;
    }
    
    s_lora.receiving = false;
    
    // Set standby
    sx1262_write_command(SX1262_REG_SET_STANDBY, (uint8_t[]){SX1262_STANDBY_XOSC}, 1);
    
    // Wait for task to finish
    if (s_lora.rx_task_handle) {
        vTaskDelay(pdMS_TO_TICKS(100));
        s_lora.rx_task_handle = NULL;
    }
}

bool lora_manager_is_receiving(void) {
    return s_lora.receiving;
}

// Send packet (blocking)
esp_err_t lora_manager_send_packet(const uint8_t *data, uint8_t length) {
    if (!s_lora.initialized || !data || length == 0 || length > 255) {
        return ESP_ERR_INVALID_ARG;
    }
    
    // Stop RX if active
    bool was_receiving = s_lora.receiving;
    if (was_receiving) {
        lora_manager_stop_receive();
    }
    
    // Clear IRQ
    uint16_t irq_mask = 0xFFFF;
    sx1262_write_command(SX1262_REG_CLEAR_IRQ_STATUS, (uint8_t *)&irq_mask, 2);
    
    // Write packet to buffer
    uint8_t write_buf[1 + length];
    write_buf[0] = 0; // Offset
    memcpy(&write_buf[1], data, length);
    sx1262_write_command(SX1262_REG_WRITE_BUFFER, write_buf, 1 + length);
    
    // Set packet length
    uint8_t packet_params[6];
    sx1262_read_command(SX1262_REG_SET_PACKET_PARAMS, packet_params, 6);
    packet_params[3] = length;
    sx1262_write_command(SX1262_REG_SET_PACKET_PARAMS, packet_params, 6);
    
    // Start TX
    s_lora.tx_done = false;
    uint8_t tx_params[3] = {0x00, 0x00, 0x00}; // No timeout
    sx1262_write_command(SX1262_REG_SET_TX, tx_params, 3);
    
    // Wait for TX done
    if (xSemaphoreTake(s_lora.tx_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGW(TAG, "TX timeout");
        return ESP_ERR_TIMEOUT;
    }
    
    // Restart RX if it was active
    if (was_receiving) {
        lora_manager_start_receive();
    }
    
    return ESP_OK;
}

// Send packet (async)
esp_err_t lora_manager_send_packet_async(const uint8_t *data, uint8_t length) {
    if (!s_lora.initialized || !data || length == 0 || length > 255) {
        return ESP_ERR_INVALID_ARG;
    }
    
    // Similar to blocking but don't wait
    bool was_receiving = s_lora.receiving;
    if (was_receiving) {
        lora_manager_stop_receive();
    }
    
    uint16_t irq_mask = 0xFFFF;
    sx1262_write_command(SX1262_REG_CLEAR_IRQ_STATUS, (uint8_t *)&irq_mask, 2);
    
    uint8_t write_buf[1 + length];
    write_buf[0] = 0;
    memcpy(&write_buf[1], data, length);
    sx1262_write_command(SX1262_REG_WRITE_BUFFER, write_buf, 1 + length);
    
    uint8_t packet_params[6];
    sx1262_read_command(SX1262_REG_SET_PACKET_PARAMS, packet_params, 6);
    packet_params[3] = length;
    sx1262_write_command(SX1262_REG_SET_PACKET_PARAMS, packet_params, 6);
    
    s_lora.tx_done = false;
    uint8_t tx_params[3] = {0x00, 0x00, 0x00};
    sx1262_write_command(SX1262_REG_SET_TX, tx_params, 3);
    
    if (was_receiving) {
        lora_manager_start_receive();
    }
    
    return ESP_OK;
}

bool lora_manager_packet_available(void) {
    return s_lora.last_packet.length > 0;
}

esp_err_t lora_manager_read_packet(lora_packet_t *packet) {
    if (!packet) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (s_lora.last_packet.length == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    
    *packet = s_lora.last_packet;
    s_lora.last_packet.length = 0; // Clear after read
    
    return ESP_OK;
}

void lora_manager_set_rx_callback(lora_rx_callback_t callback) {
    s_lora.rx_callback = callback;
}

int16_t lora_manager_get_last_rssi(void) {
    return s_lora.last_packet.rssi;
}

float lora_manager_get_last_snr(void) {
    return s_lora.last_packet.snr;
}

esp_err_t lora_manager_sleep(void) {
    if (!s_lora.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    lora_manager_stop_receive();
    return sx1262_write_command(SX1262_REG_SET_SLEEP, (uint8_t[]){0x00}, 1);
}

esp_err_t lora_manager_wake(void) {
    if (!s_lora.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    sx1262_write_command(SX1262_REG_SET_STANDBY, (uint8_t[]){SX1262_STANDBY_XOSC}, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
    return ESP_OK;
}

esp_err_t lora_manager_get_config(lora_config_t *config) {
    if (!config || !s_lora.initialized) {
        return ESP_ERR_INVALID_ARG;
    }
    
    memcpy(config, &s_lora.config, sizeof(lora_config_t));
    return ESP_OK;
}
