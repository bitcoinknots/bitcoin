# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bitcoin Knots is a Bitcoin client that connects to the Bitcoin peer-to-peer network to download and fully validate blocks and transactions. It includes a wallet and optional graphical user interface. This is a fork/variant of Bitcoin Core with additional features and patches.

## Build Commands

### Building the Project
```bash
# Configure with CMake (from project root)
cmake -B build

# Build with parallel jobs
cmake --build build -j $(nproc)

# Install (optional)
cmake --install build
```

### Common Build Options
- `-DBUILD_GUI=ON` - Build bitcoin-qt GUI executable (default: OFF)
- `-DBUILD_DAEMON=ON` - Build bitcoind executable (default: ON)
- `-DWITH_MINIUPNPC=ON` - Enable UPnP support
- `-DWITH_ZMQ=ON` - Enable ZMQ support
- `-DWITH_QRENCODE=ON` - Enable QR code support in GUI

## Testing Commands

### Unit Tests
```bash
# Run all unit tests via ctest
ctest --test-dir build

# Run unit tests directly
build/bin/test_bitcoin

# Run specific test suite
build/bin/test_bitcoin --run_test=getarg_tests

# Run with verbose logging
build/bin/test_bitcoin --log_level=all --run_test=getarg_tests
```

### Functional Tests
```bash
# Run all functional tests
build/test/functional/test_runner.py

# Run specific functional test
build/test/functional/test_runner.py feature_rbf.py

# Run extended test suite
build/test/functional/test_runner.py --extended

# Run wallet tests
build/test/functional/test_runner.py test/functional/wallet*
```

## Code Architecture

### Core Components

- **src/init/** - Initialization and startup code for bitcoind and bitcoin-qt
- **src/consensus/** - Consensus-critical validation logic
- **src/wallet/** - Wallet functionality (keys, transactions, coin selection)
- **src/script/** - Bitcoin script interpreter and validation
- **src/primitives/** - Basic Bitcoin data structures (blocks, transactions)
- **src/net.cpp, net_processing.cpp** - P2P networking layer
- **src/validation.cpp** - Block and transaction validation, chain state management
- **src/rpc/** - RPC server and command implementations
- **src/qt/** - Qt-based GUI components

### Key Architectural Patterns

1. **Chain State Management**: The validation logic maintains the current chain state through `CChainState` and manages block validation, UTXO set, and mempool.

2. **P2P Networking**: Asynchronous message handling through `CConnman` for peer connections, with `net_processing` handling protocol logic.

3. **Wallet Architecture**: Modular wallet system supporting both legacy BDB wallets and descriptor-based SQLite wallets.

4. **RPC Interface**: JSON-RPC server providing programmatic access to node functionality, with commands organized by category (blockchain, wallet, network, etc.).

5. **Consensus Rules**: Critical validation rules are isolated in `src/consensus/` to ensure consistency and prevent accidental changes.

## Development Practices

### Code Style
- Use clang-format with the provided `.clang-format` configuration
- Follow naming conventions:
  - Classes/Functions: `UpperCamelCase`
  - Variables: `snake_case`
  - Member variables: `m_` prefix
  - Global variables: `g_` prefix
  - Constants: `ALL_CAPS`

### Testing Requirements
- Write unit tests for new functionality in `src/test/`
- Add functional tests for RPC changes and P2P behavior in `test/functional/`
- Run tests before submitting changes

### Important Files
- **CMakeLists.txt** - Main build configuration
- **src/chainparams.cpp** - Network parameters (mainnet, testnet, regtest)
- **src/version.h** - Version and protocol constants
- **doc/developer-notes.md** - Detailed development guidelines