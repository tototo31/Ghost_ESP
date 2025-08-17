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
#include "zdo/esp_zigbee_zdo_command.h"
#include "zdo/esp_zigbee_zdo_common.h"
#include "esp_partition.h"
#include "esp_err.h"

#define PERMIT_JOIN_DURATION 180  // seconds

static const char *ZB_TAG = "ZIGBEE";
static bool zigbee_initialized = false;
static TaskHandle_t zigbee_task_handle = NULL;

static void zigbee_permit_join(uint8_t duration_sec)
{
    esp_zb_zdo_permit_joining_req_param_t req = {
        .dst_nwk_addr = 0x0000, // coordinator
        .permit_duration = duration_sec,
        .tc_significance = false
    };
    esp_zb_zdo_permit_joining_req(&req, NULL, NULL);
    ESP_LOGI(ZB_TAG, "Permit joining for %d seconds", duration_sec);
}

#ifdef CONFIG_ZB_ENABLED
// Zigbee event handler (called from Zigbee stack)
void esp_zb_app_signal_handler(esp_zb_app_signal_t *signal)
{
    uint32_t signal_type = *signal->p_app_signal;
    
    switch (signal_type) {
        case ESP_ZB_ZDO_SIGNAL_DEVICE_ANNCE: {
            esp_zb_zdo_signal_device_annce_params_t *annce = 
                (esp_zb_zdo_signal_device_annce_params_t *)esp_zb_app_signal_get_params(signal->p_app_signal);
            if (annce) {
                ESP_LOGI(ZB_TAG, "Device joined: short_addr=0x%04x ieee_addr=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                    annce->device_short_addr,
                    annce->ieee_addr[7], annce->ieee_addr[6], annce->ieee_addr[5], annce->ieee_addr[4],
                    annce->ieee_addr[3], annce->ieee_addr[2], annce->ieee_addr[1], annce->ieee_addr[0]);
            }
            break;
        }
        case ESP_ZB_ZDO_SIGNAL_LEAVE: {
            esp_zb_zdo_signal_leave_params_t *leave = 
                (esp_zb_zdo_signal_leave_params_t *)esp_zb_app_signal_get_params(signal->p_app_signal);
            if (leave) {
                ESP_LOGI(ZB_TAG, "Device left: leave_type=%d", leave->leave_type);
            }
            break;
        }
        case ESP_ZB_ZDO_SIGNAL_LEAVE_INDICATION: {
            esp_zb_zdo_signal_leave_indication_params_t *leave_ind = 
                (esp_zb_zdo_signal_leave_indication_params_t *)esp_zb_app_signal_get_params(signal->p_app_signal);
            if (leave_ind) {
                ESP_LOGI(ZB_TAG, "Device left indication: short_addr=0x%04x, rejoin=%d", 
                    leave_ind->short_addr, leave_ind->rejoin);
            }
            break;
        }
        case ESP_ZB_ZDO_SIGNAL_DEFAULT_START: {
            ESP_LOGI(ZB_TAG, "Zigbee network started successfully");
            break;
        }
        case ESP_ZB_ZDO_SIGNAL_SKIP_STARTUP: {
            ESP_LOGI(ZB_TAG, "Zigbee stack framework ready");
            break;
        }
        case ESP_ZB_ZDO_SIGNAL_ERROR: {
            ESP_LOGE(ZB_TAG, "Zigbee signal error: %s", esp_err_to_name(signal->esp_err_status));
            break;
        }
        default:
            ESP_LOGI(ZB_TAG, "Unhandled Zigbee signal: %d", signal_type);
            break;
    }
}
#endif

#ifdef CONFIG_ZB_ENABLED
static void zigbee_main_task(void *pvParameters)
{
    ESP_LOGI(ZB_TAG, "Zigbee main task started");
    // Permit joining for interrogation
    zigbee_permit_join(PERMIT_JOIN_DURATION);

    while (zigbee_initialized) {
        esp_zb_stack_main_loop_iteration();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ESP_LOGI(ZB_TAG, "Zigbee main task exiting");
    vTaskDelete(NULL);
}
#endif

void zigbee_manager_init(ZigbeeManager *manager)
{
    if (zigbee_initialized) {
        ESP_LOGW(ZB_TAG, "Zigbee manager already initialized");
        return;
    }
    ESP_LOGI(ZB_TAG, "Initializing Zigbee manager (ESP Zigbee stack)...");

    // Check if the required zb_storage partition exists
    if (!zigbee_manager_check_partition()) {
        ESP_LOGE(ZB_TAG, "Required partition not found. Zigbee manager initialization failed.");
        return;
    }

    // Use minimal platform configuration
    esp_zb_platform_config_t platform_config = {
        .radio_config = {
            .radio_mode = ZB_RADIO_MODE_NATIVE,
        },
        .host_config = {
            .host_connection_mode = ZB_HOST_CONNECTION_MODE_NONE,
        },
    };
    esp_zb_platform_config(&platform_config);

    // Use minimal Zigbee configuration
    esp_zb_cfg_t zb_cfg = {
        .esp_zb_role = ESP_ZB_DEVICE_TYPE_COORDINATOR,
        .install_code_policy = false,
        .nwk_cfg.zczr_cfg = {
            .max_children = 10,
        },
    };
    esp_zb_init(&zb_cfg);

    // Start the Zigbee stack with autostart enabled
    esp_err_t ret = esp_zb_start(true);
    if (ret != ESP_OK) {
        ESP_LOGE(ZB_TAG, "Failed to start Zigbee stack: %s", esp_err_to_name(ret));
        return;
    }

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

// Debug and test functions
void zigbee_manager_test_permit_join(uint8_t duration_sec)
{
    if (!zigbee_initialized) {
        ESP_LOGW(ZB_TAG, "Zigbee not initialized");
        return;
    }
    
    ESP_LOGI(ZB_TAG, "Testing permit join for %d seconds", duration_sec);
    zigbee_permit_join(duration_sec);
}

void zigbee_manager_print_status(void)
{
    ESP_LOGI(ZB_TAG, "=== Zigbee Manager Status ===");
    ESP_LOGI(ZB_TAG, "Initialized: %s", zigbee_initialized ? "Yes" : "No");
    ESP_LOGI(ZB_TAG, "Network Role: Coordinator");
    ESP_LOGI(ZB_TAG, "Task Handle: %p", zigbee_task_handle);
    ESP_LOGI(ZB_TAG, "=============================");
    printf("=== Zigbee Manager Status ===");
    printf("Initialized: %s", zigbee_initialized ? "Yes" : "No");
    printf("Network Role: Coordinator");
    printf("Task Handle: %p", zigbee_task_handle);
    printf("=============================");
}

bool zigbee_manager_check_partition(void)
{
    const esp_partition_t *zb_partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, "zb_storage");
    
    if (zb_partition == NULL) {
        ESP_LOGW(ZB_TAG, "zb_storage partition not found. Please check your partition table.");
        ESP_LOGW(ZB_TAG, "Add this line to your partitions.csv:");
        ESP_LOGW(ZB_TAG, "zb_storage, data, nvs, 0x400000, 0x10000,");
        return false;
    }
    
    ESP_LOGI(ZB_TAG, "zb_storage partition found: addr=0x%x, size=%d", 
              zb_partition->address, zb_partition->size);
    return true;
}