# Living Off the Orchard: Apple Script (LOAS)

[![View in ATT&CK Navigator](https://img.shields.io/badge/ATT%26CK-Navigator-red?logo=mitre)](https://mitre-attack.github.io/attack-navigator/#layerURL=https://loas.dev/api/attack_navigator_layer.json)
[![Documentation](https://img.shields.io/badge/docs-loas.dev-blue)](https://loas.dev)

**L**iving **O**ff the **O**rchard: **A**pple **S**cript is a library of AppleScript and JXA tests mapped to the [MITRE ATT&CK®](https://attack.mitre.org/) framework. Security teams can use LOAS to quickly, portably, and reproducibly test their macOS environments using multiple execution methods, each generating different endpoint security logs. This makes it ideal for:

- Security testing and validation
- Endpoint detection rule development
- Red team operations
- Security research and education

## Quick Start

### Download Pre-built Tests

Download pre-compiled tests from the [latest release](https://github.com/cyberbuff/loas/releases/latest). Each test is available in multiple formats:

- `.scpt` - AppleScript file
- `.swift` - Swift executable
- `.app` - macOS application
- Binary executable

### Build from Source

```bash
# Clone the repository
git clone https://github.com/cyberbuff/loas.git
cd loas

# Install dependencies
uv sync

# Validate YAML files
uv run main.py validate

# Build all test files
uv run main.py build
```

## Execution Methods

LOAS provides multiple execution methods, each generating different endpoint security logs. These methods are documented in the [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/applescript/).

### 1. osascript CLI

Execute commands directly from the command line:

```bash
osascript -e "the clipboard"
```

### 2. Script File

Execute a script file with osascript:

```bash
osascript get_clipboard_content_using_applescript_defaults.scpt
```

### 3. Swift

Execute using Swift (requires XCode Developer Tools):

```bash
swift get_clipboard_content_using_applescript_defaults.swift
```

### 4. Applet

Execute as a macOS application:

```bash
open -n get_clipboard_content_using_applescript_defaults.app
```

### 5. Binary

Execute as a compiled binary:

```bash
./get_clipboard_content_using_applescript_defaults
```

## MITRE ATT&CK Coverage

LOAS implements various MITRE ATT&CK techniques using AppleScript and JXA. View the interactive coverage map:

- [Interactive ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://loas.dev/api/attack_navigator_layer.json)

## Contributing

We welcome contributions! To add new tests:

1. Create a YAML file in the appropriate technique directory under `yaml/`
2. Follow the YAML structure with required fields: name, language, description, command
3. Run validation: `uv run main.py validate`
4. Submit a pull request

## Documentation

For complete documentation, visit [loas.dev](https://loas.dev):

- [Execution Methods](https://loas.dev/docs) - Different ways to execute tests
- [Contributing Guide](https://loas.dev/docs/contributing) - How to write YAML test files
- [ATT&CK Coverage](https://loas.dev/docs/coverage) - Interactive technique coverage

## Requirements

- macOS
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (if you are building from source)
- XCode Developer Tools (for Swift execution method)

## Security Notice

This project is intended for authorized security testing, research, and educational purposes only. Users are responsible for ensuring they have proper authorization before running these tests on any system.

## License

See [LICENSE](LICENSE.md) file for details.
