#!/usr/bin/env bash

_qlock_complete()
{
  local cur prev cmd
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmd="${COMP_WORDS[1]}"

  if [[ "$cmd" == "ls" || "$cmd" == "rm" ]]; then
    if [[ -d .qlock_metadata ]]; then
      local files=(".qlock_metadata/"*.json)
      local names=()

      for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
          if command -v jq >/dev/null 2>&1; then
            while IFS= read -r name; do
              [[ -n "$name" ]] && names+=("$name")
            done < <(jq -r '.. | objects | .name? // empty' "$file")
          else
            while IFS= read -r name; do
              [[ -n "$name" ]] && names+=("$name")
            done < <(grep -o '"name":[ ]*"[^"]*"' "$file" | sed 's/"name":[ ]*"\([^"]*\)"/\1/')
          fi
        fi
      done

      local unique_names=()
      while IFS= read -r line; do
        unique_names+=("$line")
      done < <(printf "%s\n" "${names[@]}" | sort -u)

      COMPREPLY=($(compgen -W "${unique_names[*]}" -- "$cur"))
    fi
  fi
  return 0
}

complete -F _qlock_complete qlock
