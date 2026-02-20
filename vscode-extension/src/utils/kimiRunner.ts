import * as vscode from 'vscode';
import { spawn, ChildProcess } from 'child_process';
import { KimiLogger } from './logger';

interface RunOptions {
    onOutput?: (data: string) => void;
    onError?: (data: string) => void;
    onExit?: (code: number | null) => void;
    cwd?: string;
    env?: NodeJS.ProcessEnv;
}

export class KimiRunner {
    private currentProcess: ChildProcess | null = null;
    private logger: KimiLogger;

    constructor() {
        this.logger = KimiLogger.getInstance();
    }

    async runCommand(command: string, args: string[] = [], options: RunOptions = {}): Promise<void> {
        const config = vscode.workspace.getConfiguration('kimi-ecosystem');
        const kimiPath = config.get<string>('kimiPath', 'kimi');
        
        const fullArgs = [command, ...args];
        
        this.logger.info(`Running: ${kimiPath} ${fullArgs.join(' ')}`);

        return new Promise((resolve, reject) => {
            const cwd = options.cwd || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
            
            this.currentProcess = spawn(kimiPath, fullArgs, {
                cwd,
                env: { ...process.env, ...options.env },
                shell: true
            });

            if (this.currentProcess.stdout) {
                this.currentProcess.stdout.on('data', (data: Buffer) => {
                    const output = data.toString();
                    this.logger.append(output);
                    if (options.onOutput) {
                        options.onOutput(output);
                    }
                });
            }

            if (this.currentProcess.stderr) {
                this.currentProcess.stderr.on('data', (data: Buffer) => {
                    const output = data.toString();
                    this.logger.appendError(output);
                    if (options.onError) {
                        options.onError(output);
                    }
                });
            }

            this.currentProcess.on('error', (error) => {
                this.logger.error(`Process error: ${error.message}`);
                this.currentProcess = null;
                reject(error);
            });

            this.currentProcess.on('close', (code) => {
                this.logger.info(`Process exited with code ${code}`);
                this.currentProcess = null;
                
                if (options.onExit) {
                    options.onExit(code);
                }

                if (code === 0) {
                    resolve();
                } else {
                    reject(new Error(`Process exited with code ${code}`));
                }
            });
        });
    }

    stopCurrentProcess(): void {
        if (this.currentProcess) {
            this.logger.info('Stopping current process...');
            
            // Try graceful termination first
            this.currentProcess.kill('SIGTERM');
            
            // Force kill after 5 seconds if still running
            setTimeout(() => {
                if (this.currentProcess && !this.currentProcess.killed) {
                    this.logger.warn('Force killing process...');
                    this.currentProcess.kill('SIGKILL');
                }
            }, 5000);
            
            this.currentProcess = null;
        }
    }

    isRunning(): boolean {
        return this.currentProcess !== null && !this.currentProcess.killed;
    }

    async getVersion(): Promise<string | null> {
        return new Promise((resolve) => {
            const kimiPath = vscode.workspace.getConfiguration('kimi-ecosystem').get<string>('kimiPath', 'kimi');
            const process = spawn(kimiPath, ['--version'], { shell: true });
            
            let output = '';
            
            process.stdout?.on('data', (data: Buffer) => {
                output += data.toString();
            });

            process.on('close', (code) => {
                if (code === 0) {
                    resolve(output.trim());
                } else {
                    resolve(null);
                }
            });

            process.on('error', () => {
                resolve(null);
            });
        });
    }

    async checkInstallation(): Promise<{ installed: boolean; version?: string; error?: string }> {
        try {
            const version = await this.getVersion();
            if (version) {
                return { installed: true, version };
            } else {
                return { installed: false, error: 'Could not get kimi version' };
            }
        } catch (error) {
            return { 
                installed: false, 
                error: `Kimi CLI not found. Please install it or set the correct path in settings.` 
            };
        }
    }
}
