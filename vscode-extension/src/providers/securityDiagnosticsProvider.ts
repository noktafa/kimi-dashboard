import * as vscode from 'vscode';

interface SecurityFinding {
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    message: string;
    file: string;
    line: number;
    column?: number;
    rule?: string;
    code?: string;
}

export class SecurityDiagnosticsProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private findings: Map<string, SecurityFinding[]> = new Map();

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('kimi-security');
    }

    processOutput(output: string, filePath: string): void {
        const lines = output.split('\n');
        
        for (const line of lines) {
            this.parseSecurityLine(line, filePath);
        }

        this.updateDiagnostics();
    }

    private parseSecurityLine(line: string, defaultFilePath: string): void {
        // Parse security findings from kimi audit output
        // Expected formats:
        // [SECURITY] HIGH SQL Injection vulnerability
        // [SECURITY] CRITICAL Hardcoded secret found
        // File: /path/to/file.ts:42
        
        const securityMatch = line.match(/\[SECURITY\]\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+(.+)/i);
        if (securityMatch) {
            const severity = securityMatch[1].toLowerCase() as SecurityFinding['severity'];
            const message = securityMatch[2];
            
            const finding: SecurityFinding = {
                severity,
                message,
                file: defaultFilePath,
                line: 1,
                column: 0
            };

            // Try to extract file and line info from subsequent context
            const fileMatch = line.match(/(?:File:|at)\s+(.+?):(\d+)(?::(\d+))?/);
            if (fileMatch) {
                finding.file = fileMatch[1];
                finding.line = parseInt(fileMatch[2], 10);
                if (fileMatch[3]) {
                    finding.column = parseInt(fileMatch[3], 10);
                }
            }

            // Try to extract rule name
            const ruleMatch = line.match(/\[([^\]]+)\]$/);
            if (ruleMatch) {
                finding.rule = ruleMatch[1];
            }

            this.addFinding(finding);
        }

        // Alternative format: [KIMI_AUDIT] ERROR ...
        const auditMatch = line.match(/\[KIMI_AUDIT\]\s+(ERROR|WARN)\s+(.+)/i);
        if (auditMatch) {
            const severity = auditMatch[1].toLowerCase() === 'error' ? 'high' : 'medium';
            const message = auditMatch[2];
            
            const finding: SecurityFinding = {
                severity,
                message,
                file: defaultFilePath,
                line: 1,
                column: 0
            };

            const fileMatch = line.match(/(?:File:)\s+(.+?):(\d+)/i);
            if (fileMatch) {
                finding.file = fileMatch[1];
                finding.line = parseInt(fileMatch[2], 10);
            }

            this.addFinding(finding);
        }
    }

    private addFinding(finding: SecurityFinding): void {
        const existing = this.findings.get(finding.file) || [];
        existing.push(finding);
        this.findings.set(finding.file, existing);
    }

    private updateDiagnostics(): void {
        this.diagnosticCollection.clear();

        for (const [filePath, findings] of this.findings) {
            const uri = vscode.Uri.file(filePath);
            const diagnostics: vscode.Diagnostic[] = [];

            for (const finding of findings) {
                const range = new vscode.Range(
                    finding.line - 1,
                    finding.column || 0,
                    finding.line - 1,
                    finding.column || 100
                );

                const diagnostic = new vscode.Diagnostic(
                    range,
                    `[Kimi] ${finding.message}${finding.rule ? ` (${finding.rule})` : ''}`,
                    this.mapSeverity(finding.severity)
                );

                diagnostic.source = 'kimi-security';
                diagnostic.code = finding.rule;

                diagnostics.push(diagnostic);
            }

            this.diagnosticCollection.set(uri, diagnostics);
        }
    }

    private mapSeverity(severity: SecurityFinding['severity']): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            case 'info':
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    clearFindings(): void {
        this.findings.clear();
        this.diagnosticCollection.clear();
    }

    getFindingsCount(): { total: number; critical: number; high: number; medium: number; low: number } {
        let total = 0;
        let critical = 0;
        let high = 0;
        let medium = 0;
        let low = 0;

        for (const findings of this.findings.values()) {
            total += findings.length;
            for (const finding of findings) {
                switch (finding.severity) {
                    case 'critical':
                        critical++;
                        break;
                    case 'high':
                        high++;
                        break;
                    case 'medium':
                        medium++;
                        break;
                    case 'low':
                        low++;
                        break;
                }
            }
        }

        return { total, critical, high, medium, low };
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}
