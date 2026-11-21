const vscode = require('vscode');
const { exec } = require('child_process');

function activate(context) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('secretguard');
    context.subscriptions.push(diagnosticCollection);

    // Command: Scan Workspace
    let scanCmd = vscode.commands.registerCommand('secretguard.scanWorkspace', function () {
        vscode.window.showInformationMessage('🛡️ SecretGuard: Scanning workspace for exposed credentials...');
        exec('secretguard scan .', (error, stdout, stderr) => {
            if (error) {
                vscode.window.showWarningMessage('🚨 SecretGuard detected exposed secrets in workspace! Check terminal output.');
            } else {
                vscode.window.showInformationMessage('✅ SecretGuard: Workspace is 100% clean!');
            }
        });
    });

    // Command: Replace with Mock
    let mockCmd = vscode.commands.registerCommand('secretguard.generateMock', function () {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;

        const selection = editor.selection;
        const text = editor.document.getText(selection);
        if (!text) return;

        exec(`secretguard mock "${text}"`, (error, stdout) => {
            if (!error && stdout) {
                editor.edit(editBuilder => {
                    editBuilder.replace(selection, stdout.trim());
                });
                vscode.window.showInformationMessage('🔄 Replaced secret with format-preserving synthetic mock!');
            }
        });
    });

    // Command: Compliance Report
    let reportCmd = vscode.commands.registerCommand('secretguard.complianceReport', function () {
        exec('secretguard report .', (error, stdout) => {
            const channel = vscode.window.createOutputChannel('SecretGuard Compliance');
            channel.append(stdout);
            channel.show();
        });
    });

    context.subscriptions.push(scanCmd, mockCmd, reportCmd);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
