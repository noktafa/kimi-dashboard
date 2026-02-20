# Kimi Ecosystem VS Code Extension

A VS Code extension for the Kimi ecosystem providing integration with `kimi-audit`, `kimi-admin`, and `kimi-converge` tools.

## Features

### 1. Command Palette Integration

Access all Kimi commands through the VS Code command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

- **Kimi: Run Audit** - Run a security audit on your project
- **Kimi: Audit Current File** - Audit the currently open file
- **Kimi: Open Admin** - Launch the Kimi admin interface
- **Kimi: Run Converge** - Execute the convergence loop
- **Kimi: Open Configuration** - Open or create `kimi.yaml`
- **Kimi: Show Logs** - View real-time logs

### 2. Tree View - Convergence Loop Status

The Kimi Convergence view in the Explorer sidebar shows:

- Real-time convergence loop status
- Discovery phase progress
- Analysis phase progress
- Execution phase progress
- Verification phase progress

Features:
- Auto-refresh during convergence runs
- Visual status indicators (running, success, error, warning)
- One-click refresh and stop actions

### 3. Output Channel - Real-time Logs

Dedicated output channel for Kimi ecosystem logs:

- Timestamped log entries
- Log level filtering (debug, info, warn, error)
- Configurable max lines
- Export functionality

### 4. Configuration UI for YAML Files

Smart configuration management:

- Auto-detection of `kimi.yaml` files
- One-click configuration creation
- Default configuration template with all options
- Settings integration

### 5. Problem Matchers for Security Findings

Integrated problem matchers:

- `kimi-audit` - Parse audit output for errors and warnings
- `kimi-security` - Parse security findings with severity levels

Security findings appear in:
- Problems panel
- Inline diagnostics
- Hover information

### 6. Code Lenses for Running Audits

Smart code lenses in supported languages:

- **Audit this file** - Top of every supported file
- **Audit** - On function/method definitions
- **Security Check** - On security-sensitive code patterns

Supported languages:
- TypeScript/JavaScript
- Python
- Go
- Rust
- Java
- YAML
- JSON

## Installation

### From VSIX

1. Build the extension: `npm run compile`
2. Package: `vsce package`
3. Install in VS Code: Extensions → ... → Install from VSIX

### Development

```bash
# Clone the repository
git clone <repo-url>
cd vscode-extension

# Install dependencies
npm install

# Compile
npm run compile

# Watch for changes
npm run watch

# Run tests
npm test

# Package extension
vsce package
```

## Configuration

Access settings via `File > Preferences > Settings` or edit `.vscode/settings.json`:

```json
{
  "kimi-ecosystem.enabled": true,
  "kimi-ecosystem.kimiPath": "kimi",
  "kimi-ecosystem.audit.autoRunOnSave": false,
  "kimi-ecosystem.convergence.autoRefresh": true,
  "kimi-ecosystem.convergence.refreshInterval": 5000,
  "kimi-ecosystem.logs.maxLines": 1000,
  "kimi-ecosystem.security.severityThreshold": "low"
}
```

## Kimi Configuration File

Create `kimi.yaml` in your project root:

```yaml
# Kimi Ecosystem Configuration
audit:
  include:
    - src/**
    - lib/**
  exclude:
    - node_modules/**
    - dist/**
  rules:
    - sql-injection
    - xss
    - hardcoded-secrets
  severityThreshold: low

convergence:
  autoRun: false
  loop:
    maxIterations: 10
    timeout: 300000

logging:
  level: info
  format: json
```

## Keyboard Shortcuts

| Command | Windows/Linux | macOS |
|---------|--------------|-------|
| Audit Current File | `Ctrl+Shift+K A` | `Cmd+Shift+K A` |
| Run Converge | `Ctrl+Shift+K C` | `Cmd+Shift+K C` |

## Requirements

- VS Code 1.85.0 or higher
- Kimi CLI installed and available in PATH

## Troubleshooting

### Kimi CLI not found

Set the correct path in settings:
```json
{
  "kimi-ecosystem.kimiPath": "/usr/local/bin/kimi"
}
```

### Extension not activating

Check that the extension is enabled:
```json
{
  "kimi-ecosystem.enabled": true
}
```

## License

MIT
