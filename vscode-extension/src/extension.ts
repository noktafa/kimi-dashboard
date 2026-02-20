import * as vscode from 'vscode';
import { KimiConvergenceProvider } from './providers/convergenceProvider';
import { KimiCodeLensProvider } from './providers/codeLensProvider';
import { KimiConfigurationProvider } from './providers/configurationProvider';
import { KimiLogger } from './utils/logger';
import { KimiRunner } from './utils/kimiRunner';
import { SecurityDiagnosticsProvider } from './providers/securityDiagnosticsProvider';

export function activate(context: vscode.ExtensionContext) {
    const logger = KimiLogger.getInstance();
    logger.info('Kimi Ecosystem extension is now active');

    // Initialize kimi runner
    const kimiRunner = new KimiRunner();

    // Initialize tree view provider
    const convergenceProvider = new KimiConvergenceProvider();
    const treeView = vscode.window.createTreeView('kimi-ecosystem.convergenceView', {
        treeDataProvider: convergenceProvider,
        showCollapseAll: true
    });

    // Initialize security diagnostics provider
    const securityDiagnosticsProvider = new SecurityDiagnosticsProvider();

    // Initialize configuration provider
    const configProvider = new KimiConfigurationProvider();

    // Register code lens provider
    const codeLensProvider = vscode.languages.registerCodeLensProvider(
        [
            { scheme: 'file', language: 'typescript' },
            { scheme: 'file', language: 'javascript' },
            { scheme: 'file', language: 'python' },
            { scheme: 'file', language: 'go' },
            { scheme: 'file', language: 'rust' },
            { scheme: 'file', language: 'java' },
            { scheme: 'file', language: 'yaml' },
            { scheme: 'file', language: 'json' }
        ],
        new KimiCodeLensProvider()
    );

    // Register commands
    const commands = [
        // Audit command
        vscode.commands.registerCommand('kimi-ecosystem.audit', async () => {
            try {
                logger.info('Running kimi audit...');
                await kimiRunner.runCommand('audit', [], {
                    onOutput: (data) => logger.append(data),
                    onError: (data) => logger.appendError(data)
                });
                vscode.window.showInformationMessage('Kimi audit completed');
            } catch (error) {
                logger.error(`Audit failed: ${error}`);
                vscode.window.showErrorMessage(`Audit failed: ${error}`);
            }
        }),

        // Audit current file command
        vscode.commands.registerCommand('kimi-ecosystem.auditFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('No active editor');
                return;
            }

            const filePath = editor.document.uri.fsPath;
            try {
                logger.info(`Running kimi audit on ${filePath}...`);
                await kimiRunner.runCommand('audit', [filePath], {
                    onOutput: (data) => {
                        logger.append(data);
                        securityDiagnosticsProvider.processOutput(data, filePath);
                    },
                    onError: (data) => logger.appendError(data)
                });
                vscode.window.showInformationMessage('File audit completed');
            } catch (error) {
                logger.error(`File audit failed: ${error}`);
                vscode.window.showErrorMessage(`File audit failed: ${error}`);
            }
        }),

        // Admin command
        vscode.commands.registerCommand('kimi-ecosystem.admin', async () => {
            try {
                logger.info('Opening kimi admin...');
                await kimiRunner.runCommand('admin', [], {
                    onOutput: (data) => logger.append(data),
                    onError: (data) => logger.appendError(data)
                });
            } catch (error) {
                logger.error(`Admin command failed: ${error}`);
                vscode.window.showErrorMessage(`Admin command failed: ${error}`);
            }
        }),

        // Converge command
        vscode.commands.registerCommand('kimi-ecosystem.converge', async () => {
            try {
                logger.info('Running kimi converge...');
                convergenceProvider.setRunning(true);
                await kimiRunner.runCommand('converge', [], {
                    onOutput: (data) => {
                        logger.append(data);
                        convergenceProvider.processOutput(data);
                    },
                    onError: (data) => logger.appendError(data),
                    onExit: () => convergenceProvider.setRunning(false)
                });
                vscode.window.showInformationMessage('Kimi converge completed');
            } catch (error) {
                convergenceProvider.setRunning(false);
                logger.error(`Converge failed: ${error}`);
                vscode.window.showErrorMessage(`Converge failed: ${error}`);
            }
        }),

        // Refresh convergence view
        vscode.commands.registerCommand('kimi-ecosystem.refreshConvergence', () => {
            convergenceProvider.refresh();
            logger.info('Convergence view refreshed');
        }),

        // Stop convergence
        vscode.commands.registerCommand('kimi-ecosystem.stopConvergence', () => {
            kimiRunner.stopCurrentProcess();
            convergenceProvider.setRunning(false);
            logger.info('Convergence stopped');
        }),

        // Open configuration
        vscode.commands.registerCommand('kimi-ecosystem.openConfig', async () => {
            await configProvider.openConfiguration();
        }),

        // Show logs
        vscode.commands.registerCommand('kimi-ecosystem.showLogs', () => {
            logger.show();
        })
    ];

    // Register all disposables
    context.subscriptions.push(
        treeView,
        codeLensProvider,
        convergenceProvider,
        securityDiagnosticsProvider,
        configProvider,
        ...commands
    );

    // Set context for conditional UI
    vscode.commands.executeCommand('setContext', 'kimi-ecosystem.enabled', true);

    // Auto-run audit on save if enabled
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (document) => {
            const config = vscode.workspace.getConfiguration('kimi-ecosystem');
            if (config.get<boolean>('audit.autoRunOnSave', false)) {
                const filePath = document.uri.fsPath;
                logger.info(`Auto-auditing ${filePath}...`);
                try {
                    await kimiRunner.runCommand('audit', [filePath], {
                        onOutput: (data) => {
                            logger.append(data);
                            securityDiagnosticsProvider.processOutput(data, filePath);
                        },
                        onError: (data) => logger.appendError(data)
                    });
                } catch (error) {
                    logger.error(`Auto-audit failed: ${error}`);
                }
            }
        })
    );

    logger.info('Kimi Ecosystem extension activation complete');
}

export function deactivate() {
    KimiLogger.getInstance().info('Kimi Ecosystem extension is now deactivated');
}
