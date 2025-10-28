# Detection

The detection module classifies bytecode regions and extracts Solidity dispatcher metadata so later passes know which bytes belong to deployment scaffolding versus runtime logic. `locate_sections` walks the disassembled instructions, identifies auxdata, padding, init/runtime boundaries, and optional constructor arguments, and emits an ordered list of `Section { kind, offset, len }`. The logic combines strict deployment-pattern matching with heuristics (e.g. CODECOPY+RETURN, CALLDATASIZE prologues) to stay resilient against obfuscated inputs while still validating that sections are gap-free and inside bounds.

For dispatcher analysis, `detect_function_dispatcher` tracks the stack across the function selector prologue and pairs PUSHed selectors with their jump destinations. The result is a `DispatcherInfo` structure that records extraction style (standard, alternative, fallback-only, etc.) plus the selector-to-target mapping, which drives both transform heuristics and verification.

Utility helpers such as `extract_runtime_instructions` and `validate_sections` allow other modules (`strip`, `cfg_ir`) to operate exclusively on the runtime slice or assert structural soundness before mutating the program.
