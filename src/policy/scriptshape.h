// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_SCRIPTSHAPE_H
#define BITCOIN_POLICY_SCRIPTSHAPE_H

#include <script/script.h>

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

class CTxIn;

/**
 * Policy for the scripts a transaction input reveals: P2SH redeem scripts, P2WSH witness
 * scripts and tapscript leaves.
 *
 * A revealed script is a known shape when it is sane miniscript, sane miniscript behind
 * timelock or hash checks, or one of the contract templates in use on the network
 * (Lightning, swaps, Ark, Liquid, a few custodians). Everything else is an unknown shape
 * and is not relayed or mined when -rejectunknownscripts is set.
 *
 * Known shapes still carry fields: public keys and hashes. Fields beyond what the witness's
 * signatures prove are free slots, and past an allowance per input (plus one per signature
 * beyond the first) those bytes are counted as datacarrier bytes, as are witness bytes other
 * than signatures past room for two keys or preimages, so a script that is merely shaped like a
 * contract pays for its padding like an OP_RETURN would.
 */
namespace scriptshape {

enum class Kind { P2SH, P2WSH, TAPSCRIPT };

//! Unproven fields an input may carry before the rest counts as datacarrier bytes.
static constexpr unsigned int DEFAULT_UNPROVEN_FIELD_ALLOWANCE{5};
//! Largest trailing data push a template may carry (the tagged two-key leaf).
static constexpr size_t MAX_TEMPLATE_DATA_PUSH{80};
//! Witness bytes other than signatures an input may carry before they count as data: two keys or two preimages.
static constexpr size_t MAX_FREE_WITNESS_BYTES{66};

struct Analysis {
    bool known{false};          //!< the script is a sane miniscript, a generic rule or a template
    std::string shape;          //!< which rule or template matched, for logs and tests
    bool items_typed{true};     //!< every witness item is a signature, key, preimage, number or empty
    size_t fields{0};           //!< keys and hashes in the script
    size_t proven{0};           //!< fields the witness proves: one per signature, one per key or preimage within the free bytes
    size_t data_bytes{0};       //!< bytes of fields past the allowance plus template data pushes
};

/** Classify one revealed script with the witness items it consumes (script, control block and annex left out). */
Analysis Analyze(const CScript& script, Kind kind, const std::vector<std::vector<unsigned char>>& items, unsigned int allowance);

struct Revealed {
    CScript script;
    Kind kind;
    std::vector<std::vector<unsigned char>> items;
};

/** The script an input reveals and the items it consumes; nullopt for key spends and bare output scripts. */
std::optional<Revealed> RevealedScript(const CScript& prev_spk, const CTxIn& txin);

/** Datacarrier bytes the field budget charges for one input; 0 for key spends and unknown shapes. */
size_t FieldBudgetBytes(const CScript& prev_spk, const CTxIn& txin);

/** Reason suffixes used by the policy checks. */
inline constexpr const char* REJECT_UNKNOWN{"script-unknown"};
inline constexpr const char* REJECT_ITEM_TYPE{"witness-item-type"};

} // namespace scriptshape

#endif // BITCOIN_POLICY_SCRIPTSHAPE_H
