import * as vscode from 'vscode';

export class KimiLogger {
    private static instance: KimiLogger;
    private outputChannel: vscode.OutputChannel;
    private maxLines: number;
    private logBuffer: string[] = [];

    private constructor() {
        this.outputChannel = vscode.window.createOutputChannel('Kimi Ecosystem', 'kimi-log');
        this.maxLines = vscode.workspace.getConfiguration('kimi-ecosystem').get('logs.maxLines', 1000);
        
        // Listen for configuration changes
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration('kimi-ecosystem.logs.maxLines')) {
                this.maxLines = vscode.workspace.getConfiguration('kimi-ecosystem').get('logs.maxLines', 1000);
                this.trimBuffer();
            }
        });
    }

    static getInstance(): KimiLogger {
        if (!KimiLogger.instance) {
            KimiLogger.instance = new KimiLogger();
        }
        return KimiLogger.instance;
    }

    private trimBuffer(): void {
        if (this.logBuffer.length > this.maxLines) {
            this.logBuffer = this.logBuffer.slice(-this.maxLines);
        }
    }

    private formatMessage(level: string, message: string): string {
        const timestamp = new Date().toISOString();
        return `[${timestamp}] [${level}] ${message}`;
    }

    private addToBuffer(line: string): void {
        this.logBuffer.push(line);
        this.trimBuffer();
    }

    info(message: string): void {
        const formatted = this.formatMessage('INFO', message);
        this.addToBuffer(formatted);
        this.outputChannel.appendLine(formatted);
    }

    warn(message: string): void {
        const formatted = this.formatMessage('WARN', message);
        this.addToBuffer(formatted);
        this.outputChannel.appendLine(formatted);
    }

    error(message: string): void {
        const formatted = this.formatMessage('ERROR', message);
        this.addToBuffer(formatted);
        this.outputChannel.appendLine(formatted);
    }

    debug(message: string): void {
        const config = vscode.workspace.getConfiguration('kimi-ecosystem');
        const logLevel = config.get<string>('logging.level', 'info');
        
        if (logLevel === 'debug') {
            const formatted = this.formatMessage('DEBUG', message);
            this.addToBuffer(formatted);
            this.outputChannel.appendLine(formatted);
        }
    }

    append(data: string): void {
        const lines = data.split('\n');
        for (const line of lines) {
            if (line.trim()) {
                this.addToBuffer(line);
            }
        }
        this.outputChannel.append(data);
    }

    appendError(data: string): void {
        const lines = data.split('\n');
        for (const line of lines) {
            if (line.trim()) {
                const formatted = this.formatMessage('ERROR', line);
                this.addToBuffer(formatted);
            }
        }
        this.outputChannel.append(data);
    }

    show(): void {
        this.outputChannel.show(true);
    }

    hide(): void {
        this.outputChannel.hide();
    }

    clear(): void {
        this.logBuffer = [];
        this.outputChannel.clear();
    }

    getLogs(): string[] {
        return [...this.logBuffer];
    }

    exportLogs(): string {
        return this.logBuffer.join('\n');
    }

    dispose(): void {
        this.outputChannel.dispose();
    }
}
