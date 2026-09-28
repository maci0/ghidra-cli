# Agentic Reverse Engineering Features Proposal

This document proposes higher-level analysis features for `ghidra-cli` designed to enhance AI agent-driven reverse engineering workflows. These features build on existing primitives to provide semantic understanding, guided exploration, and automated hypothesis testing.

## Current Primitives (Foundation)

| Category | Capabilities |
|----------|-------------|
| **Function Analysis** | list, decompile, disasm, xrefs, calls, rename |
| **Search** | strings, bytes, function patterns, crypto constants |
| **Heuristics** | "interesting" functions (size, xref count, suspicious names) |
| **Graphs** | call graph, callers/callees with depth traversal |
| **Memory** | map, read, write, search |
| **Annotations** | comments, symbols, types |
| **Patching** | bytes, nop, export |

---

## Proposed Higher-Level Features

### 1. Semantic Function Classification (`ghidra analyze classify`)

**Purpose**: Automatically categorize functions by behavioral patterns to give agents an instant understanding of binary structure.

```bash
ghidra analyze classify [--categories all|crypto,network,file,string,memory,auth]
```

**Output**:
```json
{
  "categories": {
    "crypto": [
      {"name": "sub_401200", "confidence": 0.92, "indicators": ["calls MD5_Init", "xors in loop", "S-box access"]}
    ],
    "network": [
      {"name": "sub_402300", "confidence": 0.87, "indicators": ["calls socket", "calls connect", "IP string refs"]}
    ],
    "file_io": [...],
    "string_manipulation": [...],
    "memory_management": [...],
    "authentication": [...],
    "encoding": [...],
    "compression": [...]
  }
}
```

**Implementation Approach**:
- Import-based: Functions calling `socket`, `recv`, `send` → network
- String-based: Functions referencing "password", "token" → auth
- Pattern-based: XOR loops, S-box patterns → crypto
- Structural: Many small allocations → memory management
- Control flow: Large switch statements → dispatchers/parsers

---

### 2. Data Flow Analysis (`ghidra trace`)

**Purpose**: Track data flow from sources (user input, file reads, network recv) to sinks (system calls, file writes, memory operations).

```bash
# Track where data from a source goes
ghidra trace from <address|function> --depth 5

# Track what data reaches a sink
ghidra trace to <address|function> --depth 5

# Find paths between source and sink
ghidra trace path --from recv --to system
```

**Output**:
```json
{
  "source": "recv@0x401000",
  "paths": [
    {
      "hops": ["recv", "parse_cmd", "execute_cmd", "system"],
      "addresses": ["0x401000", "0x401500", "0x401800", "0x402000"],
      "transforms": ["none", "string_copy", "sprintf"],
      "risk": "high",
      "reason": "unvalidated user input reaches system()"
    }
  ]
}
```

**Use Cases**:
- Find command injection paths
- Track encryption key derivation
- Understand data transformations
- Identify trust boundaries

---

### 3. Vulnerability Pattern Detection (`ghidra vuln`)

**Purpose**: Detect common vulnerability patterns using heuristics and code analysis.

```bash
ghidra vuln scan [--types all|buffer,format,injection,uaf,integer]
ghidra vuln check <address> --type buffer
```

**Patterns to Detect**:

| Type | Detection Method |
|------|-----------------|
| **Buffer Overflow** | `strcpy`, `sprintf`, `gets` without bounds; stack buffer + unbounded copy |
| **Format String** | User-controlled arg to printf-family |
| **Command Injection** | User input reaching `system`, `popen`, `exec*` |
| **Integer Overflow** | Unchecked arithmetic before allocation size |
| **Use-After-Free** | Free followed by use (requires data flow) |
| **Double Free** | Multiple free paths to same allocation |
| **Null Deref** | Unchecked return values from allocation |

**Output**:
```json
{
  "vulnerabilities": [
    {
      "type": "buffer_overflow",
      "location": "0x401234",
      "function": "parse_input",
      "severity": "high",
      "description": "strcpy from user input to 64-byte stack buffer",
      "evidence": {
        "sink": "strcpy@0x401234",
        "source": "recv buffer via arg1",
        "buffer_size": 64
      },
      "suggested_patch": "Replace strcpy with strncpy"
    }
  ]
}
```

---

### 4. Function Similarity & Library Identification (`ghidra match`)

**Purpose**: Identify known library functions and code reuse patterns.

```bash
# Match against known signatures
ghidra match library [--db libc,openssl,zlib,crypto]

# Find similar functions within binary
ghidra match internal --threshold 0.8

# Compare function against external binary
ghidra match function <name> --against <other_binary>
```

**Detection Methods**:
- FLIRT-style byte signatures
- Control flow graph fingerprinting
- String/constant fingerprinting
- N-gram similarity
- Mnemonic sequences

**Output**:
```json
{
  "matches": [
    {
      "function": "sub_401000",
      "matched_to": "AES_encrypt",
      "library": "OpenSSL 1.1.1",
      "confidence": 0.95,
      "method": "constant_match",
      "evidence": ["AES S-box at 0x401100", "10 rounds detected"]
    },
    {
      "function": "sub_402000",
      "matched_to": "memcpy",
      "library": "glibc",
      "confidence": 0.88,
      "method": "cfg_signature"
    }
  ]
}
```

---

### 5. Structure & Protocol Inference (`ghidra struct`)

**Purpose**: Identify data structures and protocol formats from parsing code.

```bash
# Infer structure at address
ghidra struct infer <address> --context <function>

# Find all structure parsing locations
ghidra struct find-parsers

# Generate C struct definition
ghidra struct define <name> --from <address>
```

**Analysis Approach**:
- Track offsets accessed from a base pointer
- Identify field types from operations (cmp = enum/flag, add = integer, etc.)
- Detect arrays from loop patterns
- Infer sizes from memcpy/allocation

**Output**:
```json
{
  "structures": [
    {
      "name": "packet_header",
      "base_address": "0x404000",
      "inferred_from": "parse_packet@0x401500",
      "size": 16,
      "fields": [
        {"offset": 0, "size": 2, "type": "uint16", "name": "magic", "value": "0x1234"},
        {"offset": 2, "size": 2, "type": "uint16", "name": "length"},
        {"offset": 4, "size": 4, "type": "uint32", "name": "command"},
        {"offset": 8, "size": 8, "type": "pointer", "name": "payload"}
      ],
      "c_definition": "struct packet_header {\n  uint16_t magic;\n  uint16_t length;\n  uint32_t command;\n  void* payload;\n};"
    }
  ]
}
```

---

### 6. Control Flow Summarization (`ghidra summarize`)

**Purpose**: Generate human/agent-readable summaries of complex functions.

```bash
ghidra summarize <function> [--detail low|medium|high]
ghidra summarize --all --filter "size>500"
```

**Output**:
```json
{
  "function": "process_command",
  "address": "0x401800",
  "summary": "Command dispatcher that reads 4-byte command code, validates against whitelist, then dispatches to handler functions via switch statement",
  "key_points": [
    "Reads command from first argument (socket buffer)",
    "Validates command is 0x01-0x0F",
    "Returns -1 on invalid command",
    "Calls 15 different handler functions",
    "No bounds checking on payload"
  ],
  "decision_points": [
    {"address": "0x401820", "condition": "cmd <= 0x0F", "true_path": "dispatch", "false_path": "error"}
  ],
  "loops": [
    {"address": "0x401900", "type": "bounded", "iterations": "payload_length"}
  ],
  "error_handling": "Returns -1, does not log"
}
```

---

### 7. Hypothesis Testing Framework (`ghidra hypothesis`)

**Purpose**: Let agents form hypotheses about code behavior and systematically test them.

```bash
# Propose a hypothesis
ghidra hypothesis create "sub_401000 is an XOR cipher with key at 0x404000"

# Test hypothesis with evidence gathering
ghidra hypothesis test <id>

# List hypotheses with confidence scores
ghidra hypothesis list

# Mark hypothesis as confirmed/rejected
ghidra hypothesis confirm <id> --evidence "..."
ghidra hypothesis reject <id> --reason "..."
```

**Built-in Tests**:
- "is_cipher" - Looks for reversible transforms, key usage
- "is_hash" - Looks for irreversible mixing, constants
- "is_compression" - Looks for dictionary, output size < input
- "is_parser" - Looks for field offset patterns, length checks
- "is_serializer" - Reverse of parser pattern
- "is_validator" - Multiple comparison branches, boolean return

**Output**:
```json
{
  "hypothesis_id": "hyp_001",
  "statement": "sub_401000 is an XOR cipher with key at 0x404000",
  "status": "testing",
  "evidence": {
    "supporting": [
      "Function contains XOR operations in loop",
      "References address 0x404000",
      "Input and output same size"
    ],
    "contradicting": [
      "No key schedule detected"
    ]
  },
  "confidence": 0.75,
  "suggested_tests": [
    "Check if 0x404000 data matches any known key format",
    "Verify XOR is applied byte-by-byte"
  ]
}
```

---

### 8. Session Context & Exploration Tracking (`ghidra session`)

**Purpose**: Track exploration progress across multiple queries, suggest next steps.

```bash
# Start a new analysis session
ghidra session start --name "malware_analysis" --goal "understand C2 protocol"

# Log exploration (auto-logged on queries)
ghidra session log "Identified main dispatch loop at 0x401500"

# Get session status and suggestions
ghidra session status

# Get AI-friendly context dump
ghidra session context

# Export session notes
ghidra session export --format markdown
```

**Session State Tracking**:
- Functions explored vs. unexplored
- Hypotheses formed
- Comments/annotations added
- Confidence in understanding per region
- Time spent per function
- Coverage percentage

**Suggestions Engine**:
```json
{
  "session": "malware_analysis",
  "coverage": 0.23,
  "explored": 45,
  "remaining": 150,
  "suggestions": [
    {
      "priority": 1,
      "action": "Investigate sub_402000",
      "reason": "Called by 3 already-explored functions, likely important",
      "estimated_complexity": "medium"
    },
    {
      "priority": 2,
      "action": "Trace data flow from recv@0x401100",
      "reason": "Network input source, understand data path"
    }
  ],
  "current_understanding": {
    "initialization": "well understood",
    "main_loop": "partially understood",
    "network_handling": "not yet explored",
    "crypto": "identified, not analyzed"
  }
}
```

---

### 9. Capability Extraction (`ghidra capabilities`)

**Purpose**: Summarize what a binary can DO - its capabilities at a high level.

```bash
ghidra capabilities [--detail low|high]
```

**Output**:
```json
{
  "capabilities": {
    "file_system": {
      "can_read": true,
      "can_write": true,
      "can_delete": true,
      "paths_referenced": ["/etc/passwd", "/tmp/*"]
    },
    "network": {
      "can_connect": true,
      "can_listen": true,
      "protocols": ["TCP", "UDP"],
      "ports": [443, 8080],
      "domains": ["example.com"]
    },
    "process": {
      "can_spawn": true,
      "can_inject": false,
      "commands": ["cmd.exe", "/bin/sh"]
    },
    "crypto": {
      "algorithms": ["AES-128", "SHA-256"],
      "key_sources": ["hardcoded", "derived"]
    },
    "persistence": {
      "registry": false,
      "startup_folder": false,
      "service": true
    },
    "anti_analysis": {
      "debugger_detection": true,
      "vm_detection": false,
      "timing_checks": true
    }
  },
  "threat_level": "high",
  "classification_hints": ["backdoor", "C2_client"]
}
```

---

### 10. Entry Point Analysis (`ghidra entrypoints`)

**Purpose**: Map the initialization flow and identify key entry points.

```bash
ghidra entrypoints [--depth 3]
ghidra entrypoints handlers  # Find callback/handler registrations
```

**Output**:
```json
{
  "main_entry": "main@0x401000",
  "init_sequence": [
    {"order": 1, "function": "_start", "purpose": "CRT initialization"},
    {"order": 2, "function": "__libc_start_main", "purpose": "libc setup"},
    {"order": 3, "function": "main", "purpose": "program entry"}
  ],
  "registered_handlers": [
    {"type": "signal", "signal": "SIGTERM", "handler": "cleanup@0x402000"},
    {"type": "atexit", "handler": "save_state@0x402100"},
    {"type": "thread_start", "handler": "worker_thread@0x402200"}
  ],
  "exported_entry_points": [
    {"name": "PluginInit", "address": "0x403000", "likely_purpose": "DLL/plugin initialization"},
    {"name": "ProcessCommand", "address": "0x403100", "likely_purpose": "command handler export"}
  ]
}
```

---

### 11. Anti-Analysis Detection (`ghidra antianalysis`)

**Purpose**: Detect obfuscation, packing, and anti-debugging techniques.

```bash
ghidra antianalysis scan
ghidra antianalysis identify-packer
```

**Patterns Detected**:

| Category | Techniques |
|----------|-----------|
| **Anti-Debug** | IsDebuggerPresent, CheckRemoteDebugger, timing checks, int3 scanning |
| **Anti-VM** | CPUID checks, MAC address checks, registry queries, process names |
| **Anti-Disasm** | Opaque predicates, overlapping instructions, jump-in-middle |
| **Packing** | UPX, Themida, custom (entropy analysis) |
| **Obfuscation** | Control flow flattening, bogus code, string encryption |

**Output**:
```json
{
  "packed": true,
  "packer": {"name": "UPX", "version": "3.96", "confidence": 0.95},
  "techniques": [
    {
      "type": "anti_debug",
      "method": "IsDebuggerPresent",
      "location": "0x401100",
      "bypass": "Patch return value to 0"
    },
    {
      "type": "anti_vm",
      "method": "CPUID hypervisor bit check",
      "location": "0x401200"
    },
    {
      "type": "string_encryption",
      "method": "XOR with rotating key",
      "decrypt_function": "0x401300",
      "strings_found": 45
    }
  ],
  "entropy": {
    ".text": 7.2,
    ".data": 5.1,
    "overall": 6.8,
    "assessment": "likely packed/encrypted"
  }
}
```

---

### 12. Comparative Analysis (`ghidra compare`)

**Purpose**: Compare binaries for patch analysis, variant detection, version diffing.

```bash
ghidra compare <binary1> <binary2> [--focus functions|strings|behavior]
ghidra compare function <func1> <func2> --semantic
```

**Output**:
```json
{
  "summary": {
    "similarity": 0.87,
    "functions_added": 12,
    "functions_removed": 3,
    "functions_modified": 45
  },
  "significant_changes": [
    {
      "function": "validate_license",
      "change_type": "modified",
      "old_address": "0x401000",
      "new_address": "0x401100",
      "diff_summary": "Added new validation check at offset +0x50",
      "security_relevant": true
    }
  ],
  "behavioral_changes": [
    "New network connection to port 8443",
    "Additional file written to /tmp",
    "New crypto routine added"
  ]
}
```

---

### 13. Guided Exploration Mode (`ghidra explore`)

**Purpose**: AI-assisted exploration that suggests next steps based on analysis goals.

```bash
ghidra explore start --goal "find_vulnerability"
ghidra explore start --goal "understand_protocol"
ghidra explore start --goal "extract_algorithm"
ghidra explore next  # Get next suggested action
ghidra explore focus <function>  # Deep-dive a specific area
```

**Exploration Strategies**:
- **find_vulnerability**: Prioritize user input handlers, system call sites
- **understand_protocol**: Focus on parsing functions, dispatch tables
- **extract_algorithm**: Look for math-heavy functions, constants
- **map_c2**: Follow network functions, command handling

**Output**:
```json
{
  "goal": "find_vulnerability",
  "current_focus": "input_handling",
  "next_action": {
    "command": "ghidra trace path --from 0x401000 --to system",
    "reasoning": "recv() at 0x401000 is unvalidated input source, checking if it reaches dangerous sinks"
  },
  "findings_so_far": [
    {"type": "potential_vuln", "location": "0x401500", "description": "sprintf with user data"}
  ],
  "confidence_map": {
    "0x401000-0x401500": "high_risk",
    "0x402000-0x403000": "low_risk",
    "0x403000-0x404000": "unexplored"
  }
}
```

---

### 14. Inline Annotation Generation (`ghidra annotate`)

**Purpose**: Auto-generate comments and rename functions based on analysis.

```bash
ghidra annotate auto [--confidence-threshold 0.7]
ghidra annotate function <name> --aggressive
ghidra annotate strings  # Decode and annotate encrypted strings
```

**Actions**:
- Rename `sub_XXXX` to meaningful names based on behavior
- Add comments explaining complex code sections
- Decode encrypted strings inline
- Mark dangerous functions with warnings
- Add TODO comments for uncertain areas

**Output**:
```json
{
  "annotations_added": 145,
  "functions_renamed": 23,
  "comments_added": 122,
  "examples": [
    {"type": "rename", "old": "sub_401000", "new": "xor_decrypt_string", "confidence": 0.85},
    {"type": "comment", "address": "0x401500", "text": "WARN: User input reaches sprintf without bounds check"},
    {"type": "string_decode", "address": "0x404000", "encrypted": "\\x12\\x45...", "decoded": "cmd.exe /c"}
  ]
}
```

---

### 15. Batch Analysis Recipes (`ghidra recipe`)

**Purpose**: Pre-defined analysis workflows for common RE tasks.

```bash
ghidra recipe run malware-triage
ghidra recipe run vuln-audit
ghidra recipe run protocol-extract
ghidra recipe list
ghidra recipe create <name> --steps "..."
```

**Built-in Recipes**:

| Recipe | Steps |
|--------|-------|
| `malware-triage` | capabilities, antianalysis, strings, crypto, network-indicators |
| `vuln-audit` | classify, vuln scan, trace all-inputs, report |
| `protocol-extract` | find-parsers, struct-infer, summarize-handlers |
| `crypto-audit` | find-crypto, match-library, key-extraction |
| `license-crack` | find "license\|serial\|valid", trace checks, identify patch points |

---

## Implementation Priority

### Phase 1: High-Value, Lower Complexity
1. **Semantic Function Classification** - Builds on existing imports/strings
2. **Capability Extraction** - Aggregates existing queries
3. **Anti-Analysis Detection** - Pattern matching on known techniques
4. **Session Context** - State management layer

### Phase 2: Core Analysis Enhancements
5. **Vulnerability Pattern Detection** - Requires data flow basics
6. **Control Flow Summarization** - Decompiler + heuristics
7. **Guided Exploration** - Strategy engine on top of primitives

### Phase 3: Advanced Analysis
8. **Data Flow Analysis** - Full taint tracking
9. **Structure Inference** - Access pattern analysis
10. **Function Similarity** - Signature database
11. **Hypothesis Testing** - Evidence framework

### Phase 4: Polish & Integration
12. **Comparative Analysis** - Multi-binary support
13. **Inline Annotation** - Confidence-based auto-labeling
14. **Batch Recipes** - Workflow orchestration

---

## Design Principles for Agentic RE

1. **Token Efficiency**: All commands support `--fields`, `--limit`, `--count` to minimize output
2. **Confidence Scores**: Every inference includes confidence (0.0-1.0) for agent decision-making
3. **Evidence Trail**: Results include reasoning/evidence for interpretability
4. **Incremental Results**: Support streaming for long-running analysis
5. **Composability**: Higher-level commands build on primitives, can be decomposed
6. **Session Awareness**: Track exploration state to avoid redundant work
7. **Goal-Oriented**: Support explicit analysis goals to guide suggestions
8. **Fail Gracefully**: Partial results better than errors; uncertainty is valuable info

---

## Example Agentic Workflow: Crackme Analysis

```bash
# 1. Quick triage
ghidra capabilities
ghidra antianalysis scan

# 2. Find validation logic
ghidra analyze classify --categories auth
ghidra find string "*valid*|*correct*|*wrong*"

# 3. Trace the check
ghidra trace to "exit_success" --depth 5

# 4. Understand the algorithm
ghidra summarize check_serial
ghidra hypothesis create "check_serial uses XOR with hardcoded key"
ghidra hypothesis test hyp_001

# 5. Find patch point
ghidra vuln check 0x401234 --type logic

# 6. Patch and export
ghidra patch nop 0x401234 --count 2
ghidra patch export --output cracked.exe
```

This workflow demonstrates how higher-level commands accelerate analysis while maintaining the granular control needed for complex RE tasks.
