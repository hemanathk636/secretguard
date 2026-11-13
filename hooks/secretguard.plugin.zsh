# SecretGuard Zsh Plugin

zshaddhistory() {
    emulate -L zsh
    local raw_cmd="${1%%$'\n'}"

    # Fast skip empty lines or very short commands (< 15 chars)
    if [[ ${#raw_cmd} -lt 15 ]]; then
        return 0
    fi

    # Pass command to secretguard
    local sanitized
    sanitized=$(secretguard sanitize "$raw_cmd" 2>/dev/null)
    local status=$?

    if [[ $status -eq 1 ]]; then
        # Secret was detected and sanitized!
        # Inject the redacted version into history instead of the raw key
        print -s -- "$sanitized"
        echo "\033[1;33m[secretguard]\033[0m 🚨 Secret stripped from history: \033[2m$sanitized\033[0m" >&2
        
        # Drop raw dirty command from persistent history
        return 1
    fi

    return 0
}
