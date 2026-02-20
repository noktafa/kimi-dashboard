import * as vscode from 'vscode';

export interface ConvergenceItem {
    id: string;
    label: string;
    description?: string;
    status: 'pending' | 'running' | 'success' | 'error' | 'warning';
    timestamp?: Date;
    details?: string;
    children?: ConvergenceItem[];
}

export class ConvergenceTreeItem extends vscode.TreeItem {
    constructor(
        public readonly data: ConvergenceItem,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState
    ) {
        super(data.label, collapsibleState);
        
        this.description = data.description;
        this.tooltip = this.buildTooltip();
        this.iconPath = this.getIconForStatus(data.status);
        this.contextValue = `convergence-${data.status}`;
        
        if (data.details) {
            this.command = {
                command: 'kimi-ecosystem.showLogs',
                title: 'Show Details'
            };
        }
    }

    private buildTooltip(): string {
        const parts = [this.data.label];
        if (this.data.description) {
            parts.push(`Status: ${this.data.status}`);
        }
        if (this.data.timestamp) {
            parts.push(`Time: ${this.data.timestamp.toLocaleTimeString()}`);
        }
        if (this.data.details) {
            parts.push(`Details: ${this.data.details.substring(0, 200)}...`);
        }
        return parts.join('\n');
    }

    private getIconForStatus(status: string): vscode.ThemeIcon {
        switch (status) {
            case 'running':
                return new vscode.ThemeIcon('sync~spin');
            case 'success':
                return new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'));
            case 'error':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('testing.iconFailed'));
            case 'warning':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('testing.iconQueued'));
            case 'pending':
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }
}

export class KimiConvergenceProvider implements vscode.TreeDataProvider<ConvergenceTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<ConvergenceTreeItem | undefined | null | void> = new vscode.EventEmitter<ConvergenceTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<ConvergenceTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private items: ConvergenceItem[] = [];
    private isRunning = false;
    private autoRefreshInterval: NodeJS.Timeout | undefined;

    constructor() {
        // Initialize with default structure
        this.items = [
            {
                id: 'root',
                label: 'Convergence Loop',
                status: 'pending',
                description: 'Not started',
                children: [
                    {
                        id: 'discovery',
                        label: 'Discovery',
                        status: 'pending',
                        description: 'Waiting...'
                    },
                    {
                        id: 'analysis',
                        label: 'Analysis',
                        status: 'pending',
                        description: 'Waiting...'
                    },
                    {
                        id: 'execution',
                        label: 'Execution',
                        status: 'pending',
                        description: 'Waiting...'
                    },
                    {
                        id: 'verification',
                        label: 'Verification',
                        status: 'pending',
                        description: 'Waiting...'
                    }
                ]
            }
        ];

        // Start auto-refresh if enabled
        this.startAutoRefresh();
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: ConvergenceTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: ConvergenceTreeItem): Thenable<ConvergenceTreeItem[]> {
        if (!element) {
            // Return root items
            return Promise.resolve(
                this.items.map(item => new ConvergenceTreeItem(
                    item,
                    item.children ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.None
                ))
            );
        } else {
            // Return children
            const children = element.data.children || [];
            return Promise.resolve(
                children.map(child => new ConvergenceTreeItem(
                    child,
                    child.children ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None
                ))
            );
        }
    }

    setRunning(running: boolean): void {
        this.isRunning = running;
        vscode.commands.executeCommand('setContext', 'kimi-ecosystem.convergenceRunning', running);
        
        if (this.items[0]) {
            this.items[0].status = running ? 'running' : 'success';
            this.items[0].description = running ? 'Running...' : 'Completed';
        }
        
        this.refresh();
    }

    processOutput(output: string): void {
        // Parse convergence output and update items
        const lines = output.split('\n');
        
        for (const line of lines) {
            this.parseLine(line);
        }

        this.refresh();
    }

    private parseLine(line: string): void {
        // Parse different types of convergence output
        if (line.includes('DISCOVERY') || line.includes('discovering')) {
            this.updateItemStatus('discovery', 'running', 'In progress...');
        } else if (line.includes('ANALYSIS') || line.includes('analyzing')) {
            this.updateItemStatus('discovery', 'success', 'Complete');
            this.updateItemStatus('analysis', 'running', 'In progress...');
        } else if (line.includes('EXECUTION') || line.includes('executing')) {
            this.updateItemStatus('analysis', 'success', 'Complete');
            this.updateItemStatus('execution', 'running', 'In progress...');
        } else if (line.includes('VERIFICATION') || line.includes('verifying')) {
            this.updateItemStatus('execution', 'success', 'Complete');
            this.updateItemStatus('verification', 'running', 'In progress...');
        } else if (line.includes('ERROR') || line.includes('FAILED')) {
            this.updateCurrentItemStatus('error', 'Failed');
        } else if (line.includes('SUCCESS') || line.includes('COMPLETED')) {
            this.updateCurrentItemStatus('success', 'Complete');
        }

        // Update root item with latest info
        if (this.items[0]) {
            this.items[0].details = line;
        }
    }

    private updateItemStatus(id: string, status: ConvergenceItem['status'], description: string): void {
        const rootItem = this.items[0];
        if (rootItem?.children) {
            const item = rootItem.children.find(child => child.id === id);
            if (item) {
                item.status = status;
                item.description = description;
                item.timestamp = new Date();
            }
        }
    }

    private updateCurrentItemStatus(status: ConvergenceItem['status'], description: string): void {
        const rootItem = this.items[0];
        if (rootItem?.children) {
            const runningItem = rootItem.children.find(child => child.status === 'running');
            if (runningItem) {
                runningItem.status = status;
                runningItem.description = description;
                runningItem.timestamp = new Date();
            }
        }
    }

    private startAutoRefresh(): void {
        const config = vscode.workspace.getConfiguration('kimi-ecosystem');
        if (config.get<boolean>('convergence.autoRefresh', true)) {
            const interval = config.get<number>('convergence.refreshInterval', 5000);
            this.autoRefreshInterval = setInterval(() => {
                if (this.isRunning) {
                    this.refresh();
                }
            }, interval);
        }
    }

    dispose(): void {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
        }
    }
}
