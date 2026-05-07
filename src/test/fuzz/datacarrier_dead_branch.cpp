// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <cassert>
#include <optional>
#include <vector>

namespace {
/**
 * The non-standard count of CScript::DatacarrierBytes before the dead-branch
 * rule. The first member is set where that function returned early with both
 * counts; the unproven pubkey count is otherwise left to the real function,
 * since the rule does not touch it.
 */
std::pair<std::optional<size_t>, size_t> ReferenceDatacarrierBytes(const CScript& self, const size_t remaining_outputs, const CScriptWitness* witness)
{
    if (size_t olga_bytes = self.IsOLGA(remaining_outputs); olga_bytes) {
        return {size_t{0}, olga_bytes};
    }

    if (witness) {
        if (uint32_t opnet_bytes = self.OPNetWitnessSize(*witness); opnet_bytes) {
            return {size_t{0}, opnet_bytes};
        }
    }

    size_t counted{0};
    opcodetype opcode, last_opcode{OP_INVALIDOPCODE};
    std::vector<unsigned char> push_data;
    unsigned int inside_noop{0}, inside_conditional{0};
    auto is_push = [](opcodetype op) { return op <= OP_16 && op != OP_RESERVED; };
    CScript::const_iterator opcode_it = self.begin(), data_began = self.begin();
    for (CScript::const_iterator it = self.begin(); it < self.end(); last_opcode = opcode) {
        opcode_it = it;
        if (!self.GetOp(it, opcode, push_data)) {
            return {size_t{0}, self.size()};
        }

        if (opcode == OP_IF || opcode == OP_NOTIF) {
            ++inside_conditional;
        } else if (opcode == OP_ENDIF) {
            if (!inside_conditional) return {size_t{0}, self.size()};
            --inside_conditional;
        } else if (opcode == OP_RETURN && !inside_conditional) {
            return {self.size(), size_t{0}};
        }

        if (inside_noop) {
            switch (opcode) {
            case OP_IF: case OP_NOTIF:
                ++inside_noop;
                break;
            case OP_ENDIF:
                if (0 == --inside_noop) {
                    counted += it - data_began + 1;
                }
                break;
            default: /* do nothing */;
            }
        } else if (opcode == OP_IF && last_opcode == OP_FALSE) {
            inside_noop = 1;
            data_began = opcode_it;
        } else if (is_push(opcode)) {
            if (!is_push(last_opcode)) data_began = opcode_it;
        } else if ((opcode == OP_DROP || opcode == OP_2DROP) && is_push(last_opcode)) {
            counted += it - data_began;
        }
    }
    return {std::nullopt, counted};
}

bool Runs(const CScript& script, const std::vector<std::vector<unsigned char>>& initial)
{
    std::vector<std::vector<unsigned char>> stack{initial};
    return EvalScript(stack, script, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_MINIMALDATA | SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_NULLFAIL,
                      BaseSignatureChecker(), SigVersion::WITNESS_V0);
}
} // namespace

FUZZ_TARGET(datacarrier_dead_branch)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    const CScript script{ConsumeScript(fdp)};
    const size_t remaining{fdp.ConsumeIntegralInRange<size_t>(0, 8)};
    std::optional<CScriptWitness> witness;
    if (fdp.ConsumeBool()) {
        witness.emplace();
        const size_t n{fdp.ConsumeIntegralInRange<size_t>(0, 6)};
        for (size_t i{0}; i < n; ++i) witness->stack.push_back(ConsumeRandomLengthByteVector(fdp, 80));
    }
    const CScriptWitness* w{witness ? &*witness : nullptr};

    // With the rule off the count is the old one, and the rule never changes the unproven pubkey count
    const auto off{script.DatacarrierBytes(remaining, w, false)};
    const auto on{script.DatacarrierBytes(remaining, w, true)};
    const auto [early, ref_counted] = ReferenceDatacarrierBytes(script, remaining, w);
    assert(off.second == ref_counted);
    if (early) assert(off.first == *early);
    assert(on.first == off.first);
    assert(on.second <= std::max<size_t>(script.size(), ref_counted));

    // A part marked dead never runs: an OP_RETURN put at its start leaves the interpreter's verdict
    // unchanged, whatever the initial stack. An OP_NOP at the same spot is the control, so the two
    // verdicts differ only if that part runs.
    const DeadParts dead{FindDeadParts(script)};
    std::vector<std::vector<unsigned char>> initial;
    const size_t items{fdp.ConsumeIntegralInRange<size_t>(0, 4)};
    for (size_t i{0}; i < items; ++i) initial.push_back(ConsumeRandomLengthByteVector(fdp, 8));
    if (script.size() < MAX_SCRIPT_SIZE) {
        opcodetype opcode;
        for (CScript::const_iterator it{script.begin()}; it < script.end();) {
            const size_t offset{size_t(it - script.begin())};
            if (!script.GetOp(it, opcode)) break;
            if (!dead.at_if[offset] && !dead.at_else[offset]) continue;
            CScript control{script.begin(), it}, probe{script.begin(), it};
            control << OP_NOP;
            probe << OP_RETURN;
            control.insert(control.end(), it, script.end());
            probe.insert(probe.end(), it, script.end());
            assert(Runs(probe, initial) == Runs(control, initial));
        }
    }

    // Balanced and without OP_ELSE, the rule finds at least what the envelope rule did
    bool has_else{false}, balanced{true};
    int depth{0};
    opcodetype op;
    for (CScript::const_iterator it{script.begin()}; it < script.end();) {
        if (!script.GetOp(it, op)) { balanced = false; break; }
        if (op == OP_ELSE) has_else = true;
        if (op == OP_IF || op == OP_NOTIF) ++depth;
        if (op == OP_ENDIF && --depth < 0) balanced = false;
    }
    if (depth != 0) balanced = false;
    if (balanced && !has_else && ref_counted > 0) assert(on.second > 0);
}
