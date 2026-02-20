import * as vscode from 'vscode';

export class KimiCodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChangeCodeLenses: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
    readonly onDidChangeCodeLenses: vscode.Event<void> = this._onDidChangeCodeLenses.event;

    constructor() {
        // Refresh code lenses when configuration changes
        vscode.workspace.onDidChangeConfiguration(() => {
            this._onDidChangeCodeLenses.fire();
        });
    }

    provideCodeLenses(document: vscode.TextDocument, token: vscode.CancellationToken): vscode.CodeLens[] | Thenable<vscode.CodeLens[]> {
        const codeLenses: vscode.CodeLens[] = [];
        const config = vscode.workspace.getConfiguration('kimi-ecosystem');
        
        // Only provide code lenses if extension is enabled
        if (!config.get<boolean>('enabled', true)) {
            return codeLenses;
        }

        // Add code lens at the top of the file
        const topRange = new vscode.Range(0, 0, 0, 0);
        
        // Audit this file code lens
        const auditLens = new vscode.CodeLens(topRange, {
            title: '$(search) Kimi Audit',
            tooltip: 'Run Kimi audit on this file',
            command: 'kimi-ecosystem.auditFile'
        });
        codeLenses.push(auditLens);

        // Look for function/class definitions to add specific code lenses
        const text = document.getText();
        const lines = text.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            
            // Detect function/method definitions based on language
            if (this.isFunctionDefinition(line, document.languageId)) {
                const range = new vscode.Range(i, 0, i, line.length);
                
                const functionLens = new vscode.CodeLens(range, {
                    title: '$(search) Audit',
                    tooltip: 'Audit this function with Kimi',
                    command: 'kimi-ecosystem.auditFile',
                    arguments: [document.uri, i + 1]
                });
                
                codeLenses.push(functionLens);
            }

            // Detect security-sensitive patterns
            if (this.isSecuritySensitive(line)) {
                const range = new vscode.Range(i, 0, i, line.length);
                
                const securityLens = new vscode.CodeLens(range, {
                    title: '$(warning) Security Check',
                    tooltip: 'This code may have security implications - run audit',
                    command: 'kimi-ecosystem.auditFile'
                });
                
                codeLenses.push(securityLens);
            }
        }

        return codeLenses;
    }

    private isFunctionDefinition(line: string, languageId: string): boolean {
        const patterns: { [key: string]: RegExp[] } = {
            typescript: [/^(export\s+)?(async\s+)?function\s+\w+/, /^(export\s+)?(async\s+)?\w+\s*\([^)]*\)\s*[:{]/, /^\s*(private|public|protected|static)?\s*(async\s+)?\w+\s*\([^)]*\)\s*[:{]/],
            javascript: [/^(export\s+)?(async\s+)?function\s+\w+/, /^\s*\w+\s*[:=]\s*(async\s+)?\([^)]*\)\s*=>?/],
            python: [/^\s*(async\s+)?def\s+\w+\s*\(/, /^\s*class\s+\w+/],
            go: [/^func\s+/, /^func\s*\([^)]*\)\s*\w+\s*\(/],
            rust: [/^\s*(pub\s+)?(async\s+)?fn\s+\w+/, /^\s*(pub\s+)?impl/],
            java: [/^\s*(public|private|protected)?\s*(static\s+)?\w+\s+\w+\s*\(/]
        };

        const languagePatterns = patterns[languageId] || [];
        return languagePatterns.some(pattern => pattern.test(line));
    }

    private isSecuritySensitive(line: string): boolean {
        const securityPatterns = [
            // Authentication/Authorization
            /password/i,
            /secret/i,
            /token/i,
            /auth/i,
            /login/i,
            /credential/i,
            // SQL
            /sql/i,
            /query/i,
            /SELECT\s+.*FROM/i,
            /INSERT\s+INTO/i,
            // Network
            /http/i,
            /fetch/i,
            /axios/i,
            /request/i,
            /curl/i,
            // Crypto
            /encrypt/i,
            /decrypt/i,
            /hash/i,
            /md5/i,
            /sha/i,
            // File operations
            /readFile/i,
            /writeFile/i,
            /fs\./i,
            /exec/i,
            /spawn/i,
            // Input validation
            /eval\s*\(/i,
            /innerHTML/i,
            /dangerouslySetInnerHTML/i
        ];

        return securityPatterns.some(pattern => pattern.test(line));
    }

    resolveCodeLens?(codeLens: vscode.CodeLens, token: vscode.CancellationToken): vscode.ProviderResult<vscode.CodeLens> {
        return codeLens;
    }
}
