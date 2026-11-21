pub struct CompletionsGenerator;

impl CompletionsGenerator {
    pub fn print_completions(shell: &str) {
        match shell.to_lowercase().as_str() {
            "zsh" => print!("{}", Self::generate_zsh()),
            "bash" => print!("{}", Self::generate_bash()),
            "fish" => print!("{}", Self::generate_fish()),
            "powershell" | "pwsh" => print!("{}", Self::generate_powershell()),
            _ => {
                eprintln!("Unsupported shell: {}. Supported shells: zsh, bash, fish, powershell", shell);
                std::process::exit(1);
            }
        }
    }

    pub fn generate_zsh() -> &'static str {
        r#"#compdef secretguard

_secretguard() {
    local -a pillars
    pillars=(
        'shield:Pillar 1 - Ambient Shield & Runtime Defense'
        'vault:Pillar 2 - Zero-Knowledge Keystore & Team Mesh'
        'audit:Pillar 3 - Repository Auditing & Remediation'
        'init:One-command 10-second workstation & AI agent setup wizard'
        'scan:High-speed codebase and directory scanner'
        'hook:Attach sub-millisecond line interceptor to active shell'
        'doctor:Diagnostics, latency verification & health check'
        'completions:Generate shell tab completion script'
        'ghost:Zero-Knowledge LLM Context Virtualization (Ghost Tokens)'
        'immune:Autonomous self-healing key revocation circuit-breaker'
    )

    local -a shield_cmds
    shield_cmds=(
        'hook:Install shell line interceptor'
        'tun:In-flight TLS secret swapper'
        'wrap:Cloak stdout/stderr during screen share'
        'screen:Detect Zoom/Teams/Meet and blur terminal'
        'clipboard:OS clipboard guardian with auto-destruct'
        'radar:Trojan Source & prompt injection detector'
        'agent:AI agent workspace shield'
        'firewall:Agent terminal & egress firewall'
    )

    local -a vault_cmds
    vault_cmds=(
        'init:Initialize local encrypted vault'
        'set:Store encrypted secret in hardware vault'
        'get:Retrieve secret on demand'
        'run:Inject secrets into child process in-memory'
        'list:List secret identifiers'
        'mesh:Serverless P2P team secret sync'
        'canary:Plant decoy honeytoken tripwires'
    )

    local -a audit_cmds
    audit_cmds=(
        'scan:Multi-threaded codebase scanner'
        'git:Cryptographic Git Time-Machine history scrubber'
        'history:Audit shell history file'
        'clean-history:Atomically sanitize shell history'
        'docker:Dockerfile & container layer X-Ray'
        'verify:Zero-privilege token scope & privilege verifier'
        'blast:Compromised key blast-radius graph'
        'report:Generate SOC 2, HIPAA, GDPR compliance audit'
        'panic:Emergency developer lockdown kill-switch'
        'immune:Autonomous API key revocation & rotation'
    )

    if (( CURRENT == 2 )); then
        _describe -t commands 'secretguard commands' pillars
    elif (( CURRENT == 3 )); then
        case "$words[2]" in
            shield) _describe -t subcommands 'shield commands' shield_cmds ;;
            vault)  _describe -t subcommands 'vault commands' vault_cmds ;;
            audit)  _describe -t subcommands 'audit commands' audit_cmds ;;
            *)      _files ;;
        esac
    else
        _files
    fi
}

_secretguard "$@"
"#
    }

    pub fn generate_bash() -> &'static str {
        r#"# Bash completion for secretguard
_secretguard_completions() {
    local cur prev words cword
    _init_completion || return

    local pillars="shield vault audit init scan hook doctor completions ghost immune panic"
    local shield_cmds="hook tun wrap screen auto status run clipboard radar agent firewall"
    local vault_cmds="init set get run list mesh canary"
    local audit_cmds="scan git history clean-history docker verify blast report panic immune"

    if [ "$cword" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$pillars" -- "$cur") )
        return 0
    elif [ "$cword" -eq 2 ]; then
        case "$prev" in
            shield) COMPREPLY=( $(compgen -W "$shield_cmds" -- "$cur") ) ;;
            vault)  COMPREPLY=( $(compgen -W "$vault_cmds" -- "$cur") ) ;;
            audit)  COMPREPLY=( $(compgen -W "$audit_cmds" -- "$cur") ) ;;
            completions) COMPREPLY=( $(compgen -W "zsh bash fish powershell" -- "$cur") ) ;;
            hook) COMPREPLY=( $(compgen -W "zsh bash fish powershell" -- "$cur") ) ;;
            *) _filedir ;;
        esac
        return 0
    fi
}
complete -F _secretguard_completions secretguard
"#
    }

    pub fn generate_fish() -> &'static str {
        r#"# Fish completion for secretguard
complete -c secretguard -f

complete -c secretguard -n "__fish_use_subcommand" -a "shield" -d "Pillar 1: Ambient Shield & Runtime Defense"
complete -c secretguard -n "__fish_use_subcommand" -a "vault"  -d "Pillar 2: Zero-Knowledge Keystore & Team Mesh"
complete -c secretguard -n "__fish_use_subcommand" -a "audit"  -d "Pillar 3: Repository Auditing & Remediation"
complete -c secretguard -n "__fish_use_subcommand" -a "init"   -d "10-Second 3-Pillar Setup Wizard"
complete -c secretguard -n "__fish_use_subcommand" -a "scan"   -d "High-speed codebase scanner"
complete -c secretguard -n "__fish_use_subcommand" -a "doctor" -d "Health check & latency verification"

complete -c secretguard -n "__fish_seen_subcommand_from shield" -a "hook tun wrap screen clipboard radar agent"
complete -c secretguard -n "__fish_seen_subcommand_from vault"  -a "init set get run list mesh canary"
complete -c secretguard -n "__fish_seen_subcommand_from audit"  -a "scan git history clean-history docker verify blast report panic"
"#
    }

    pub fn generate_powershell() -> &'static str {
        r#"# PowerShell tab completion for secretguard
Register-ArgumentCompleter -Native -CommandName secretguard -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $elements = $commandAst.Elements
    $pillars = @('shield', 'vault', 'audit', 'init', 'scan', 'hook', 'doctor', 'completions', 'ghost', 'immune', 'panic')
    $shield_cmds = @('hook', 'tun', 'wrap', 'screen', 'auto', 'status', 'run', 'clipboard', 'radar', 'agent', 'firewall')
    $vault_cmds = @('init', 'set', 'get', 'run', 'list', 'mesh', 'canary')
    $audit_cmds = @('scan', 'git', 'history', 'clean-history', 'docker', 'verify', 'blast', 'report', 'panic', 'immune')

    if ($elements.Count -le 2) {
        $pillars | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    } elseif ($elements.Count -eq 3) {
        $prev = $elements[1].Extent.Text
        $targets = switch ($prev) {
            'shield' { $shield_cmds }
            'vault'  { $vault_cmds }
            'audit'  { $audit_cmds }
            'completions' { @('zsh', 'bash', 'fish', 'powershell') }
            'hook'   { @('powershell', 'zsh', 'bash', 'fish') }
            Default  { @() }
        }
        $targets | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}
"#
    }
}
