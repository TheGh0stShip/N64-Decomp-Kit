#!/bin/sh
# Example refiner for `n64dk decompile-run --refine-command` / `[run.refine] command`.
#
# Contract: the prompt arrives on stdin, one fenced C block leaves on stdout.
# The model is given no tools and no project context, so it can only answer with text; what it
# answers is untrusted and is built, compared and strictly verified by the kit.
#
# The prompt contains disassembly of the image under analysis and candidate sources, and this
# script sends it to the model provider configured for the `claude` command.  Use it only where
# that is acceptable.
#
#   N64DK_REFINE_MODEL   model alias or id (default: sonnet)
#
# It runs from an empty directory so that no project instructions or memory are loaded.
empty="${TMPDIR:-/tmp}/n64dk-refiner-empty"
mkdir -p "$empty" && cd "$empty" || exit 1
exec claude -p --model "${N64DK_REFINE_MODEL:-sonnet}" --tools "" --strict-mcp-config \
  --no-session-persistence --setting-sources "" \
  --system-prompt "You write C source that a specific old compiler turns into exactly the given MIPS machine code. Follow the rules in the message. Reply with one fenced C code block and nothing else."
