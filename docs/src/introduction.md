Azoth is a deterministic EVM bytecode obfuscator designed to make Mirage execution contracts indistinguishable from ordinary, unverified deployments on Ethereum. The project takes its name from the alchemical "universal solvent", reflecting its goal of transforming bytecode while preserving the intent of the original program.

The toolchain dissects contract bytecode, reconstructs control-flow, and applies deterministic rewrites that reshape structure without inflating gas usage or breaking deployability.

Within this documentation you will find guidance on the command-line interface, core architecture, transforms, analysis, and verification systems, and the source for the book lives alongside Azoth on GitHub at https://github.com/MiragePrivacy/azoth/tree/master/docs
