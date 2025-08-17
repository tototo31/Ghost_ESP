#ifndef ZIGBEE_MANAGER_H
#define ZIGBEE_MANAGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool is_initialized;
    // Add more fields as needed (e.g., device address, state)
} ZigbeeManager;

void zigbee_manager_init(ZigbeeManager *manager);
void zigbee_manager_deinit(ZigbeeManager *manager);
bool zigbee_manager_send_command(const uint8_t *data, size_t len);

#endif // ZIGBEE_MANAGER_H