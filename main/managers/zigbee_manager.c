#include "managers/zigbee_manager.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_zigbee_core.h"
#include "zcl/esp_zigbee_zcl_common.h"

static const char *ZB_TAG = "ZIGBEE";
static bool zigbee_initialized = false;
static TaskHandle_t zigbee_task_handle = NULL;

// Zigbee event handler (called from Zigbee stack)
static void zigbee_event_handler(esp_zb_app_signal_t *signal)
{
    //ESP_LOGI(ZB_TAG, "Zigbee event: %d", signal->sig);
    // TODO: Handle Zigbee events (e.g., device join, leave, attribute report, etc.)
    return;
}

static void zigbee_main_task(void *pvParameters)
{
    ESP_LOGI(ZB_TAG, "Zigbee main task started");
    // Start Zigbee stack main loop
    esp_zb_main_loop_iteration();
    ESP_LOGI(ZB_TAG, "Zigbee main task exiting");
    vTaskDelete(NULL);
}

void zigbee_manager_init(ZigbeeManager *manager)
{
    if (zigbee_initialized) {
        ESP_LOGW(ZB_TAG, "Zigbee manager already initialized");
        return;
    }
    ESP_LOGI(ZB_TAG, "Initializing Zigbee manager (ESP Zigbee stack)...");

    esp_zb_platform_config_t platform_config = {0}; // Use defaults
    esp_zb_platform_config(&platform_config);

    esp_zb_cfg_t zb_cfg = {
        .esp_zb_role = ESP_ZB_DEVICE_TYPE_COORDINATOR,
        .install_code_policy = false,
        .nwk_cfg.zczr_cfg = {
            .max_children = 10,
        },
    };
    esp_zb_init(&zb_cfg);
    //esp_zb_app_signal_handler_register(zigbee_event_handler);

    zigbee_initialized = true;
    manager->is_initialized = true;

    xTaskCreate(zigbee_main_task, "zigbee_task", 4096, NULL, 5, &zigbee_task_handle);

    ESP_LOGI(ZB_TAG, "Zigbee manager initialized (ESP Zigbee stack)");
}

void zigbee_manager_deinit(ZigbeeManager *manager)
{
    if (!zigbee_initialized) return;

    ESP_LOGI(ZB_TAG, "Deinitializing Zigbee manager...");

    zigbee_initialized = false;
    manager->is_initialized = false;

    // Wait for task to exit
    if (zigbee_task_handle) {
        vTaskDelete(zigbee_task_handle);
        zigbee_task_handle = NULL;
    }

    ESP_LOGI(ZB_TAG, "Zigbee manager deinitialized");
}

bool zigbee_manager_send_command(const uint8_t *data, size_t len)
{
    if (!zigbee_initialized) {
        ESP_LOGW(ZB_TAG, "Zigbee not initialized");
        return false;
    }
    // TODO: Use esp_zb_zcl API or esp_zb_send_data for actual Zigbee commands
    ESP_LOGI(ZB_TAG, "Sending Zigbee command (stub): len=%d", (int)len);
    return true;
}