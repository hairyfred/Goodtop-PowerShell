# Goodtop-PowerShell
A powershell script to allow you to control features/ports of a Goodtop switch

WARNING: My code should not be counted as relabile, this should not be anywhere near being considered to use in production

# Features
* Enable/Disable Ports
* Change Speed/Duplex and Flow
* Toggle Port PoE

# Usage
Required Global Paramters
| Parameter   | Description                                                       |
| ----------- | ------------------------------------------------------------------|
| `-username` | Login username (default: `admin`)                                 |
| `-password` | Login password (default: `admin`)                                 |
| `-url`      | The base domain or IP address of the switch (e.g., `192.168.1.1`) |

Optional Global Paramters
| Parameter   | Description                                                       |
| ----------- | ------------------------------------------------------------------|
| `-debug`    | Enables debug messages                                            |
| `-save`     | Saves current configuration (default: `0`)                        |

Port Settings
| Parameter    | Description                                                                            |
| ------------ | -------------------------------------------------------------------------------------- |
| `-port`      | **Required**: Selects port configuration mode                                          |
| `-speed`     | Port speed and duplex (e.g. `1000FD`, `100HD`, etc.)                                   |
| `-flow`      | Flow control state (`0` or `1`)                                                        |
| `-interface` | Port/interface number                                                                  |
| `-enabled`   | Port state: `0` (disabled), `1` (enabled)                                              |

PoE settings
| Parameter    | Description                                                               |
| ------------ | ------------------------------------------------------------------------- |
| `-poe`       | **Required**: Selects PoE configuration mode                              |
| `-interface` | Port/interface number                                                     |
| `-enabled`   | PoE state: `0` (off), `1` (on)                                            |

Misc
| Parameter    | Description                                                      |
| ------------ | -----------------------------------------------------------------|
| `-sysinfo`   | Outputs system information                                       |
| `-saveconfig`| Saves current configuration                                      |

# Tested Models
ZX-AFGW-SWTG218ANS-100
