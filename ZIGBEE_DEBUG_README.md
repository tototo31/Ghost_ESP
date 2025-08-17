# Zigbee Debug Commands

This document describes the Zigbee debug commands that have been added to help test and debug the Zigbee functionality in your Ghost ESP project.

## Overview

The Zigbee manager has been integrated into the main system and provides several debug commands through the command line interface. These commands allow you to:

- Check the status of the Zigbee manager
- Test device joining permissions
- Send test data (placeholder)
- Reset the network (placeholder)

## Available Commands

### 1. `zigbee` - Show Help
Displays all available Zigbee debug commands and their usage.

**Usage:**
```
zigbee
```

**Output:**
```
Zigbee Debug Commands:
  zigbee status     - Show Zigbee manager status
  zigbee permit <n> - Permit joining for n seconds
  zigbee send <hex> - Send test data (e.g., zigbee send 01020304)
  zigbee reset      - Reset Zigbee network
```

### 2. `zigbee status` - Show Manager Status
Displays the current status of the Zigbee manager, including initialization state, network role, and task information.

**Usage:**
```
zigbee status
```

**Output:**
```
Zigbee Manager Status:
=== Zigbee Manager Status ===
Initialized: Yes
Network Role: Coordinator
Task Handle: 0x3ffb1234
=============================
```

### 3. `zigbee permit <seconds>` - Permit Device Joining
Allows Zigbee devices to join the network for a specified duration. This is useful for testing device discovery and joining.

**Usage:**
```
zigbee permit 60
```

**Parameters:**
- `<seconds>`: Duration in seconds (1-255)

**Output:**
```
Permitting Zigbee device joining for 60 seconds
```

**Note:** This command calls the actual Zigbee permit join function and will be visible in the ESP-IDF logs.

### 4. `zigbee send <hex_data>` - Send Test Data
Parses and validates hex data for sending Zigbee commands. Currently a placeholder for future implementation.

**Usage:**
```
zigbee send 01020304
```

**Parameters:**
- `<hex_data>`: Hexadecimal data string (must be even number of characters)

**Output:**
```
Sending 2 bytes: 01 02 03 04
Note: Send functionality not yet implemented
```

### 5. `zigbee reset` - Reset Network
Placeholder command for future network reset functionality.

**Usage:**
```
zigbee reset
```

**Output:**
```
Resetting Zigbee network...
Note: Reset functionality not yet implemented
```

## Integration Details

### Zigbee Manager Initialization
The Zigbee manager is automatically initialized during system startup in `main.c`:

```c
ESP_LOGI(TAG, "Initializing Zigbee Manager");
ZigbeeManager zigbee_manager;
MEASURE_INIT_RAM("Zigbee Manager", zigbee_manager_init(&zigbee_manager));
```

### Signal Handler
The Zigbee manager includes a signal handler that processes various Zigbee events:

- **Device Announce**: When devices join/rejoin the network
- **Leave**: When devices leave the network
- **Leave Indication**: Detailed leave information
- **Default Start**: Network startup completion
- **Skip Startup**: Stack framework ready

### Logging
All Zigbee operations are logged with the tag `ZIGBEE`. You can monitor these logs to see:

- Device join/leave events
- Network status changes
- Error conditions
- Debug information

## Testing Workflow

1. **Start the system** - The Zigbee manager will initialize automatically
2. **Check status** - Use `zigbee status` to verify initialization
3. **Permit joining** - Use `zigbee permit 180` to allow devices to join for 3 minutes
4. **Monitor logs** - Watch for device join/leave events in the ESP-IDF logs
5. **Test commands** - Use the various debug commands to test functionality

## Future Enhancements

The following features are planned for future implementation:

- **Data sending**: Actual Zigbee data transmission
- **Network reset**: Complete network reset functionality
- **Device management**: List and manage connected devices
- **Security**: Implement Zigbee security features
- **Cluster operations**: ZCL cluster command support

## Troubleshooting

### Common Issues

1. **Manager not initialized**: Check if the Zigbee manager is included in the build
2. **No device events**: Ensure the permit join command is active
3. **Compilation errors**: Verify ESP-IDF version compatibility (v5.5+)

### Debug Tips

- Use `zigbee status` to verify manager state
- Monitor ESP-IDF logs for detailed Zigbee events
- Test with simple commands first before complex operations
- Check network permissions and device compatibility

## Technical Notes

- **ESP-IDF Version**: Requires ESP-IDF v5.5 or later
- **Zigbee Stack**: Uses the official Espressif ESP-Zigbee library
- **Network Role**: Configured as Coordinator by default
- **Task Priority**: Zigbee main task runs at priority 5
- **Memory Usage**: Approximately 4KB stack size for Zigbee operations

For more detailed technical information, refer to the ESP-IDF Zigbee documentation and the ESP-Zigbee library reference.
