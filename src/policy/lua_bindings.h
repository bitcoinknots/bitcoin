// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_LUA_BINDINGS_H
#define BITCOIN_POLICY_LUA_BINDINGS_H

#include <sol/sol.hpp>
#include <primitives/transaction.h>
#include <script/script.h>
#include <logging.h>

namespace LuaBindings {

/**
 * Wrapper for CTxOut to provide Lua-friendly interface
 */
class TxOutputWrapper {
private:
    const CTxOut& txout;

public:
    explicit TxOutputWrapper(const CTxOut& out) : txout(out) {}

    bool is_op_return() const {
        return txout.scriptPubKey.IsUnspendable();
    }

    std::string get_script_pubkey() const {
        return std::string(txout.scriptPubKey.begin(), txout.scriptPubKey.end());
    }

    int64_t get_value() const {
        return txout.nValue;
    }
};

/**
 * Wrapper for CTxIn to provide Lua-friendly interface
 */
class TxInputWrapper {
private:
    const CTxIn& txin;

public:
    explicit TxInputWrapper(const CTxIn& in) : txin(in) {}

    sol::as_table_t<std::vector<std::string>> get_witness() const {
        std::vector<std::string> witness_stack;

        for (const auto& witness_item : txin.scriptWitness.stack) {
            witness_stack.push_back(std::string(witness_item.begin(), witness_item.end()));
        }

        return sol::as_table(witness_stack);
    }
};

/**
 * Wrapper for CTransaction to provide Lua-friendly interface
 */
class TransactionWrapper {
private:
    const CTransaction& tx;
    mutable std::vector<TxInputWrapper> input_wrappers;
    mutable std::vector<TxOutputWrapper> output_wrappers;

public:
    explicit TransactionWrapper(const CTransaction& transaction) : tx(transaction) {
        // Pre-create wrappers for all inputs and outputs
        for (const auto& input : tx.vin) {
            input_wrappers.emplace_back(input);
        }
        for (const auto& output : tx.vout) {
            output_wrappers.emplace_back(output);
        }
    }

    sol::as_table_t<std::vector<TxInputWrapper>> get_inputs() const {
        return sol::as_table(input_wrappers);
    }

    sol::as_table_t<std::vector<TxOutputWrapper>> get_outputs() const {
        return sol::as_table(output_wrappers);
    }
};

/**
 * Context wrapper for logging and other utilities
 */
class ContextWrapper {
public:
    void log_info(const std::string& message) const {
        LogPrintf("Lua filter [INFO]: %s\n", message);
    }

    void log_warn(const std::string& message) const {
        LogPrintf("Lua filter [WARN]: %s\n", message);
    }

    void log_error(const std::string& message) const {
        LogPrintf("Lua filter [ERROR]: %s\n", message);
    }
};

/**
 * Register all Lua bindings with the Sol2 state
 */
inline void RegisterBindings(sol::state& lua) {
    // Register TxOutputWrapper
    lua.new_usertype<TxOutputWrapper>("TxOutput",
        "is_op_return", &TxOutputWrapper::is_op_return,
        "get_script_pubkey", &TxOutputWrapper::get_script_pubkey,
        "get_value", &TxOutputWrapper::get_value
    );

    // Register TxInputWrapper
    lua.new_usertype<TxInputWrapper>("TxInput",
        "get_witness", &TxInputWrapper::get_witness
    );

    // Register TransactionWrapper
    lua.new_usertype<TransactionWrapper>("Transaction",
        "get_inputs", &TransactionWrapper::get_inputs,
        "get_outputs", &TransactionWrapper::get_outputs
    );

    // Register ContextWrapper
    lua.new_usertype<ContextWrapper>("Context",
        "log_info", &ContextWrapper::log_info,
        "log_warn", &ContextWrapper::log_warn,
        "log_error", &ContextWrapper::log_error
    );
}

} // namespace LuaBindings

#endif // BITCOIN_POLICY_LUA_BINDINGS_H
