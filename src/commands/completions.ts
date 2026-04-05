/**
 * `mcpm completions <shell>` command handler.
 *
 * Generates shell completion scripts for bash, zsh, and fish.
 * Users pipe the output into their shell config to enable tab-completion.
 *
 * Usage:
 *   mcpm completions bash >> ~/.bashrc
 *   mcpm completions zsh >> ~/.zshrc
 *   mcpm completions fish > ~/.config/fish/completions/mcpm.fish
 */

import { Command } from "commander";
import chalk from "chalk";
import { stdoutOutput } from "../utils/output.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ShellType = "bash" | "zsh" | "fish";

export interface CompletionsDeps {
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// Shell scripts
// ---------------------------------------------------------------------------

const SUBCOMMANDS = [
  "search", "install", "info", "list", "remove", "audit", "update",
  "doctor", "init", "import", "serve", "disable", "enable", "completions",
];

const CLIENT_IDS = ["claude-desktop", "cursor", "vscode", "windsurf"];

function bashScript(): string {
  return `# mcpm bash completions
# Add to ~/.bashrc: eval "$(mcpm completions bash)"
_mcpm_completions() {
  local cur prev commands
  COMPREPLY=()
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  commands="${SUBCOMMANDS.join(" ")}"

  case "\${prev}" in
    mcpm)
      COMPREPLY=( $(compgen -W "\${commands}" -- "\${cur}") )
      return 0
      ;;
    --client|-c)
      COMPREPLY=( $(compgen -W "${CLIENT_IDS.join(" ")}" -- "\${cur}") )
      return 0
      ;;
    init)
      COMPREPLY=( $(compgen -W "developer data web" -- "\${cur}") )
      return 0
      ;;
    completions)
      COMPREPLY=( $(compgen -W "bash zsh fish" -- "\${cur}") )
      return 0
      ;;
  esac

  if [[ "\${cur}" == -* ]]; then
    COMPREPLY=( $(compgen -W "--help --json --yes --client --limit --force" -- "\${cur}") )
    return 0
  fi
}
complete -F _mcpm_completions mcpm`;
}

function zshScript(): string {
  return `# mcpm zsh completions
# Add to ~/.zshrc: eval "$(mcpm completions zsh)"
_mcpm() {
  local -a commands
  commands=(
    'search:Search the MCP registry for servers'
    'install:Install an MCP server with trust assessment'
    'info:Show full details for an MCP server'
    'list:List all installed MCP servers'
    'remove:Remove an MCP server from client configs'
    'audit:Scan all installed servers for trust assessment'
    'update:Check for newer versions of installed servers'
    'doctor:Check MCP setup health'
    'init:Install a curated starter pack'
    'import:Import existing MCP configs'
    'serve:Start mcpm as an MCP server'
    'disable:Disable an MCP server without removing it'
    'enable:Re-enable a previously disabled server'
    'completions:Generate shell completion scripts'
  )

  _arguments -C \\
    '1:command:->command' \\
    '*::arg:->args'

  case "$state" in
    command)
      _describe 'mcpm command' commands
      ;;
    args)
      case "\${words[1]}" in
        init)
          _values 'pack' developer data web
          ;;
        completions)
          _values 'shell' bash zsh fish
          ;;
        remove|disable|enable|install|info|search)
          _arguments '--client[Target client]:client:(${CLIENT_IDS.join(" ")})'
          ;;
      esac
      ;;
  esac
}
compdef _mcpm mcpm`;
}

function fishScript(): string {
  return `# mcpm fish completions
# Save to: ~/.config/fish/completions/mcpm.fish
complete -c mcpm -e
complete -c mcpm -n '__fish_use_subcommand' -a search -d 'Search the MCP registry'
complete -c mcpm -n '__fish_use_subcommand' -a install -d 'Install an MCP server'
complete -c mcpm -n '__fish_use_subcommand' -a info -d 'Show server details'
complete -c mcpm -n '__fish_use_subcommand' -a list -d 'List installed servers'
complete -c mcpm -n '__fish_use_subcommand' -a remove -d 'Remove an MCP server'
complete -c mcpm -n '__fish_use_subcommand' -a audit -d 'Scan installed servers'
complete -c mcpm -n '__fish_use_subcommand' -a update -d 'Check for updates'
complete -c mcpm -n '__fish_use_subcommand' -a doctor -d 'Check MCP setup health'
complete -c mcpm -n '__fish_use_subcommand' -a init -d 'Install a starter pack'
complete -c mcpm -n '__fish_use_subcommand' -a import -d 'Import existing configs'
complete -c mcpm -n '__fish_use_subcommand' -a serve -d 'Start as MCP server'
complete -c mcpm -n '__fish_use_subcommand' -a disable -d 'Disable an MCP server'
complete -c mcpm -n '__fish_use_subcommand' -a enable -d 'Re-enable an MCP server'
complete -c mcpm -n '__fish_use_subcommand' -a completions -d 'Generate completions'
complete -c mcpm -n '__fish_seen_subcommand_from init' -a 'developer data web'
complete -c mcpm -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
complete -c mcpm -n '__fish_seen_subcommand_from remove disable enable install info' -l client -s c -a '${CLIENT_IDS.join(" ")}' -d 'Target client'
complete -c mcpm -l json -d 'Output as JSON'
complete -c mcpm -l yes -s y -d 'Skip confirmation'
complete -c mcpm -l help -s h -d 'Show help'`;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export function handleCompletions(shell: ShellType, deps: CompletionsDeps): void {
  const { output } = deps;

  switch (shell) {
    case "bash":
      output(bashScript());
      break;
    case "zsh":
      output(zshScript());
      break;
    case "fish":
      output(fishScript());
      break;
  }
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

const VALID_SHELLS: ShellType[] = ["bash", "zsh", "fish"];

export function registerCompletionsCommand(program: Command): void {
  program
    .command("completions <shell>")
    .description("Generate shell completion scripts (bash, zsh, fish)")
    .action((shell: string) => {
      if (!VALID_SHELLS.includes(shell as ShellType)) {
        console.error(chalk.red(`Invalid shell: "${shell}". Choose from: ${VALID_SHELLS.join(", ")}`));
        process.exit(1);
      }
      handleCompletions(shell as ShellType, { output: stdoutOutput });
    });
}
