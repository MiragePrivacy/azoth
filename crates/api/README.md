# azoth-api

HTTP API server for bytecode obfuscation using Azoth's transformation pipeline. Exposes a REST endpoint at `/obfuscate` that accepts EVM bytecode and returns obfuscated versions with configurable transforms. The API provides detailed metrics including gas cost analysis, size impact, and obfuscation metadata for integration into development workflows and automated deployment pipelines.