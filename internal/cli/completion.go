package cli

import (
	"flag"
	"fmt"
	"os"
)

// cmdCompletion prints shell-completion script for the named shell to
// stdout. Pipe into the shell's completion-loader location:
//
//	tarpit-honeypot completion bash > /etc/bash_completion.d/tarpit-honeypot
//	tarpit-honeypot completion zsh  > "${fpath[1]}/_tarpit-honeypot"
//	tarpit-honeypot completion fish > ~/.config/fish/completions/tarpit-honeypot.fish
func cmdCompletion(args []string) error {
	fs := flag.NewFlagSet("completion", flag.ContinueOnError)
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: tarpit-honeypot completion bash|zsh|fish")
		return fmt.Errorf("completion: expected 1 argument")
	}
	switch fs.Arg(0) {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	case "fish":
		fmt.Print(fishCompletion)
	default:
		return fmt.Errorf("completion: unknown shell %q (want bash|zsh|fish)", fs.Arg(0))
	}
	return nil
}

const bashCompletion = `# bash completion for tarpit-honeypot
_tarpit_honeypot() {
    local cur prev cmds opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmds="run validate-config show-config test-alert list-events gen-token export-pcap list-honeynets list-devices list-archetypes list-handlers list-archeservices list-cves list-techniques export-navigator identify jarm reset-db init completion version"
    opts="-c --set --log-level --log-format --log-file --quiet --verbose --version -V -h --help"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
        return 0
    fi

    case "${prev}" in
        -c|--diff)
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0 ;;
        --log-level)
            COMPREPLY=( $(compgen -W "debug info warn error" -- "${cur}") )
            return 0 ;;
        --log-format)
            COMPREPLY=( $(compgen -W "text json" -- "${cur}") )
            return 0 ;;
        --type)
            COMPREPLY=( $(compgen -W "dns url hex ssrf doc" -- "${cur}") )
            return 0 ;;
        --proto)
            COMPREPLY=( $(compgen -W "tcp udp" -- "${cur}") )
            return 0 ;;
        --kind)
            COMPREPLY=( $(compgen -W "rule handler anomaly" -- "${cur}") )
            return 0 ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
            return 0 ;;
    esac
    COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
}
complete -F _tarpit_honeypot tarpit-honeypot
`

const zshCompletion = `#compdef tarpit-honeypot
_tarpit_honeypot() {
    local -a cmds
    cmds=(
        'run:start the sensor'
        'validate-config:validate a YAML config'
        'show-config:print the effective config'
        'test-alert:emit a synthetic event'
        'list-events:tail the local event store'
        'gen-token:generate a canary token'
        'export-pcap:copy one event pcap out'
        'list-honeynets:print honeynet topology'
        'list-devices:print the learned-device inventory'
        'list-archetypes:print the archetype catalog'
        'list-handlers:print valid listener handlers'
        'list-archeservices:print service roles'
        'list-cves:print the CVE catalog'
        'list-techniques:print ATT&CK / D3FEND coverage'
        'export-navigator:write a MITRE ATT&CK Navigator layer'
        'identify:fingerprint a UA / ssh-id / payload'
        'jarm:probe a TLS server for its JARM fingerprint'
        'reset-db:empty the local databases'
        'init:write default config skeleton'
        'completion:print shell completion'
        'version:print version info'
    )
    if (( CURRENT == 2 )); then
        _describe 'subcommand' cmds
        return
    fi
    _arguments \
        '-c[config file]:file:_files' \
        '--set[override key=value]:override' \
        '--log-level[log level]:level:(debug info warn error)' \
        '--log-format[log format]:format:(text json)' \
        '--log-file[log destination]:file:_files' \
        '--quiet[shortcut for --log-level=error]' \
        '--verbose[shortcut for --log-level=debug]' \
        '--version[print version and exit]' \
        '-V[print version and exit]' \
        '-h[show help]' \
        '--help[show help]'
}
_tarpit_honeypot "$@"
`

const fishCompletion = `# fish completion for tarpit-honeypot
complete -c tarpit-honeypot -f
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'run' -d 'start the sensor'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'validate-config' -d 'validate a YAML config'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'show-config' -d 'print the effective config'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'test-alert' -d 'emit a synthetic event'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'list-events' -d 'tail the local event store'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'gen-token' -d 'generate a canary token'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'export-pcap' -d 'copy one event pcap out'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'list-honeynets' -d 'print honeynet topology'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'list-devices' -d 'print the learned-device inventory'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'list-archetypes' -d 'print the archetype catalog'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'list-handlers' -d 'print valid listener handlers'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'list-archeservices' -d 'print service roles'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'list-cves' -d 'print the CVE catalog'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'list-techniques' -d 'print ATT&CK / D3FEND coverage'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'export-navigator' -d 'write a MITRE ATT&CK Navigator layer'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'identify' -d 'fingerprint a UA / ssh-id / payload'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'jarm' -d 'probe a TLS server for its JARM fingerprint'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'reset-db' -d 'empty the local databases'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'init' -d 'write default config skeleton'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'completion' -d 'print shell completion'
complete -c tarpit-honeypot -n '__fish_use_subcommand' -a 'version' -d 'print version info'
complete -c tarpit-honeypot -s c -r -F -d 'config file'
complete -c tarpit-honeypot -l set -r -d 'override key=value'
complete -c tarpit-honeypot -l log-level -x -a 'debug info warn error' -d 'log level'
complete -c tarpit-honeypot -l log-format -x -a 'text json' -d 'log format'
complete -c tarpit-honeypot -l log-file -r -F -d 'log destination'
complete -c tarpit-honeypot -l quiet -d 'shortcut for --log-level=error'
complete -c tarpit-honeypot -l verbose -d 'shortcut for --log-level=debug'
complete -c tarpit-honeypot -l version -d 'print version and exit'
complete -c tarpit-honeypot -s V -d 'print version and exit'
complete -c tarpit-honeypot -s h -l help -d 'show help'
complete -c tarpit-honeypot -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c tarpit-honeypot -n '__fish_seen_subcommand_from gen-token' -l type -x -a 'dns url hex ssrf doc'
complete -c tarpit-honeypot -n '__fish_seen_subcommand_from list-handlers' -l proto -x -a 'tcp udp'
complete -c tarpit-honeypot -n '__fish_seen_subcommand_from list-techniques' -l kind -x -a 'rule handler anomaly'
`
