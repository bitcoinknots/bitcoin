// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/script.h>

#include <crypto/common.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <uint256.h>
#include <util/hash_type.h>

#include <algorithm>
#include <string>

CScriptID::CScriptID(const CScript& in) : BaseHash(Hash160(in)) {}

std::string GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expansion
    case OP_NOP1                   : return "OP_NOP1";
    case OP_CHECKLOCKTIMEVERIFY    : return "OP_CHECKLOCKTIMEVERIFY";
    case OP_CHECKSEQUENCEVERIFY    : return "OP_CHECKSEQUENCEVERIFY";
    case OP_NOP4                   : return "OP_NOP4";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    // Opcode added by BIP 342 (Tapscript)
    case OP_CHECKSIGADD            : return "OP_CHECKSIGADD";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";

    default:
        return "OP_UNKNOWN";
    }
}

unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += MAX_PUBKEYS_PER_MULTISIG;
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    std::vector<unsigned char> vData;
    while (pc < scriptSig.end())
    {
        opcodetype opcode;
        if (!scriptSig.GetOp(pc, opcode, vData))
            return 0;
        if (opcode > OP_16)
            return 0;
    }

    /// ... and return its opcount:
    CScript subscript(vData.begin(), vData.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsPayToAnchor() const
{
    return (this->size() == 4 &&
        (*this)[0] == OP_1 &&
        (*this)[1] == 0x02 &&
        (*this)[2] == 0x4e &&
        (*this)[3] == 0x73);
}

bool CScript::IsPayToAnchor(int version, const std::vector<unsigned char>& program)
{
    return version == 1 &&
        program.size() == 2 &&
        program[0] == 0x4e &&
        program[1] == 0x73;
}

bool CScript::IsPayToScriptHash() const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (this->size() == 23 &&
            (*this)[0] == OP_HASH160 &&
            (*this)[1] == 0x14 &&
            (*this)[22] == OP_EQUAL);
}

bool CScript::IsPayToWitnessScriptHash() const
{
    // Extra-fast test for pay-to-witness-script-hash CScripts:
    return (this->size() == 34 &&
            (*this)[0] == OP_0 &&
            (*this)[1] == 0x20);
}

// A witness program is any valid CScript that consists of a 1-byte push opcode
// followed by a data push between 2 and 40 bytes.
bool CScript::IsWitnessProgram(int& version, std::vector<unsigned char>& program) const
{
    if (this->size() < 4 || this->size() > 42) {
        return false;
    }
    if ((*this)[0] != OP_0 && ((*this)[0] < OP_1 || (*this)[0] > OP_16)) {
        return false;
    }
    if ((size_t)((*this)[1] + 2) == this->size()) {
        version = DecodeOP_N((opcodetype)(*this)[0]);
        program = std::vector<unsigned char>(this->begin() + 2, this->end());
        return true;
    }
    return false;
}

bool CScript::IsPushOnly(const_iterator pc) const
{
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            return false;
        // Note that IsPushOnly() *does* consider OP_RESERVED to be a
        // push-type opcode, however execution of OP_RESERVED fails, so
        // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
        // the P2SH special validation code being executed.
        if (opcode > OP_16)
            return false;
    }
    return true;
}

bool CScript::IsPushOnly() const
{
    return this->IsPushOnly(begin());
}

std::string CScriptWitness::ToString() const
{
    std::string ret = "CScriptWitness(";
    for (unsigned int i = 0; i < stack.size(); i++) {
        if (i) {
            ret += ", ";
        }
        ret += HexStr(stack[i]);
    }
    return ret + ")";
}

bool CScript::HasValidOps() const
{
    CScript::const_iterator it = begin();
    while (it < end()) {
        opcodetype opcode;
        std::vector<unsigned char> item;
        if (!GetOp(it, opcode, item) || opcode > MAX_OPCODE || item.size() > MAX_SCRIPT_ELEMENT_SIZE) {
            return false;
        }
    }
    return true;
}

// Static truthiness of a byte vector, matching CastToBool in the interpreter:
// any nonzero byte is true, except a lone trailing sign bit (negative zero).
static bool DataCarrierCastToBool(const std::vector<unsigned char>& vch)
{
    for (size_t i = 0; i < vch.size(); ++i) {
        if (vch[i] != 0) {
            if (i == vch.size() - 1 && vch[i] == 0x80) return false;
            return true;
        }
    }
    return false;
}

namespace {
/** A value on the stack that follows from constants alone, as an index into KnownValues; 0 if it depends on the witness or a signature */
using KnownValue = size_t;
constexpr KnownValue UNKNOWN{0};

/** The values FindDeadParts has seen; the stacks hold indexes, so copying a value costs nothing */
class KnownValues
{
    std::vector<std::vector<unsigned char>> m_values{{}};

public:
    KnownValue Add(std::vector<unsigned char> v)
    {
        m_values.push_back(std::move(v));
        return m_values.size() - 1;
    }
    KnownValue AddNum(int64_t n) { return Add(CScriptNum{n}.getvch()); }
    const std::vector<unsigned char>& Get(KnownValue v) const { return m_values[v]; }
    /** The value as a script number, if it is known and a valid one */
    bool Num(KnownValue v, int64_t& out) const
    {
        if (v == UNKNOWN) return false;
        try {
            out = CScriptNum{m_values[v], /*fRequireMinimal=*/true}.GetInt64();
            return true;
        } catch (const scriptnum_error&) {
            return false;
        }
    }
};

/** The top of the stack as far as constants determine it; below it nothing is known */
class KnownStack
{
    std::vector<KnownValue> m_items;

public:
    size_t size() const { return m_items.size(); }
    void Push(KnownValue v)
    {
        m_items.push_back(std::move(v));
        if (m_items.size() > MAX_STACK_SIZE) Forget(); // the script fails here anyway
    }
    KnownValue Pop()
    {
        if (m_items.empty()) return UNKNOWN;
        KnownValue v{std::move(m_items.back())};
        m_items.pop_back();
        return v;
    }
    KnownValue Peek(size_t depth) const { return depth < m_items.size() ? m_items[m_items.size() - 1 - depth] : UNKNOWN; }
    KnownValue& At(size_t depth) { return m_items[m_items.size() - 1 - depth]; }
    void Forget() { m_items.clear(); }
};

} // namespace

DeadParts FindDeadParts(const CScript& script)
{
    DeadParts dead{std::vector<bool>(script.size()), std::vector<bool>(script.size())};
    // Per open conditional: whether constants decide it, and whether its current part runs
    struct Frame { bool known; bool running; };
    std::vector<Frame> frames;
    size_t not_running{0}; // open frames whose current part does not run
    KnownValues values;
    KnownStack stack, alt;
    opcodetype opcode;
    std::vector<unsigned char> push;
    // Each opcode costs one step, and OP_ROLL also costs its depth, the one move
    // that is not constant time. Stop, marking nothing more, after a few steps per
    // byte: no spendable script rolls deep over and over, and one built to do so
    // gets the plain scan instead of costing the node more than its size.
    size_t steps_left{4 * size_t{script.size()}};

    for (CScript::const_iterator it{script.begin()}; it < script.end();) {
        const size_t offset{size_t(it - script.begin())};
        if (!script.GetOp(it, opcode, push)) break;
        if (steps_left == 0) break;
        --steps_left;

        if (opcode == OP_IF || opcode == OP_NOTIF) {
            if (not_running) {
                frames.push_back({true, false});
                ++not_running;
                continue;
            }
            const KnownValue cond{stack.Pop()};
            if (cond != UNKNOWN) {
                const bool runs{DataCarrierCastToBool(values.Get(cond)) == (opcode == OP_IF)};
                if (!runs) {
                    dead.at_if[offset] = true;
                    ++not_running;
                }
                frames.push_back({true, runs});
            } else {
                frames.push_back({false, true});
            }
            continue;
        }
        if (opcode == OP_ELSE || opcode == OP_ENDIF) {
            if (frames.empty()) break; // unbalanced: the script cannot run
            Frame& frame{frames.back()};
            const bool outer_running{not_running == (frame.running ? 0 : 1)};
            if (opcode == OP_ELSE) {
                if (frame.known && outer_running) {
                    frame.running = !frame.running;
                    if (frame.running) {
                        --not_running;
                    } else {
                        ++not_running;
                        dead.at_else[offset] = true;
                    }
                } else if (!frame.known) {
                    // The else part starts from the state before the OP_IF, which is not kept
                    stack.Forget();
                    alt.Forget();
                }
            } else {
                if (!frame.running) --not_running;
                if (!frame.known && not_running == 0) {
                    stack.Forget();
                    alt.Forget();
                }
                frames.pop_back();
            }
            continue;
        }
        if (not_running) continue;

        if (opcode <= OP_PUSHDATA4) {
            stack.Push(values.Add(push));
            continue;
        }
        if (opcode == OP_1NEGATE || (opcode >= OP_1 && opcode <= OP_16)) {
            stack.Push(values.AddNum(opcode == OP_1NEGATE ? -1 : CScript::DecodeOP_N(opcode)));
            continue;
        }
        switch (opcode) {
        case OP_NOP: case OP_NOP1: case OP_CHECKLOCKTIMEVERIFY: case OP_CHECKSEQUENCEVERIFY:
        case OP_NOP4: case OP_NOP5: case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
        case OP_CODESEPARATOR:
            break;
        case OP_VERIFY: case OP_DROP:
            stack.Pop();
            break;
        case OP_2DROP:
            stack.Pop();
            stack.Pop();
            break;
        case OP_TOALTSTACK:
            alt.Push(stack.Pop());
            break;
        case OP_FROMALTSTACK:
            stack.Push(alt.Pop());
            break;
        case OP_DUP:
            stack.Push(stack.Peek(0));
            break;
        case OP_OVER:
            stack.Push(stack.Peek(1));
            break;
        case OP_2DUP: {
            const KnownValue a{stack.Peek(1)}, b{stack.Peek(0)};
            stack.Push(a);
            stack.Push(b);
            break;
        }
        case OP_3DUP: {
            const KnownValue a{stack.Peek(2)}, b{stack.Peek(1)}, c{stack.Peek(0)};
            stack.Push(a);
            stack.Push(b);
            stack.Push(c);
            break;
        }
        case OP_2OVER: {
            const KnownValue a{stack.Peek(3)}, b{stack.Peek(2)};
            stack.Push(a);
            stack.Push(b);
            break;
        }
        case OP_IFDUP: {
            const KnownValue top{stack.Peek(0)};
            if (top == UNKNOWN) {
                stack.Forget(); // whether it duplicates is not known, so neither is the depth
            } else if (DataCarrierCastToBool(values.Get(top))) {
                stack.Push(top);
            }
            break;
        }
        case OP_SIZE: {
            const KnownValue top{stack.Peek(0)};
            stack.Push(top == UNKNOWN ? UNKNOWN : values.AddNum(values.Get(top).size()));
            break;
        }
        case OP_DEPTH:
            stack.Push(UNKNOWN);
            break;
        case OP_NIP: case OP_SWAP: case OP_TUCK: case OP_ROT: case OP_2SWAP: case OP_2ROT: {
            const size_t need{opcode == OP_2ROT ? 6u : opcode == OP_2SWAP ? 4u : opcode == OP_ROT ? 3u : 2u};
            if (stack.size() < need) {
                stack.Forget();
                break;
            }
            if (opcode == OP_NIP) {
                const KnownValue top{stack.Pop()};
                stack.Pop();
                stack.Push(top);
            } else if (opcode == OP_SWAP) {
                std::swap(stack.At(0), stack.At(1));
            } else if (opcode == OP_TUCK) {
                const KnownValue top{stack.Pop()}, second{stack.Pop()};
                stack.Push(top);
                stack.Push(second);
                stack.Push(top);
            } else if (opcode == OP_ROT) {
                std::swap(stack.At(2), stack.At(1));
                std::swap(stack.At(1), stack.At(0));
            } else if (opcode == OP_2SWAP) {
                std::swap(stack.At(3), stack.At(1));
                std::swap(stack.At(2), stack.At(0));
            } else {
                std::vector<KnownValue> six;
                for (int i{0}; i < 6; ++i) six.push_back(stack.Pop());
                // six[5] and six[4] were deepest; they move to the top
                for (int i{3}; i >= 0; --i) stack.Push(six[i]);
                stack.Push(six[5]);
                stack.Push(six[4]);
            }
            break;
        }
        case OP_PICK: case OP_ROLL: {
            int64_t n{0};
            const bool known{values.Num(stack.Pop(), n)};
            if (!known || n < 0 || size_t(n) >= stack.size()) {
                // Reaches below what is known, or the depth itself is unknown
                if (opcode == OP_ROLL || !known) stack.Forget();
                stack.Push(UNKNOWN);
                break;
            }
            const KnownValue v{stack.At(n)};
            if (opcode == OP_ROLL) {
                if (size_t(n) > steps_left) return dead;
                steps_left -= n;
                std::vector<KnownValue> above;
                for (int64_t i{0}; i < n; ++i) above.push_back(stack.Pop());
                stack.Pop();
                for (auto i{above.rbegin()}; i != above.rend(); ++i) stack.Push(*i);
            }
            stack.Push(v);
            break;
        }
        case OP_EQUAL: case OP_EQUALVERIFY: {
            const KnownValue b{stack.Pop()}, a{stack.Pop()};
            if (opcode == OP_EQUAL) {
                stack.Push(a == UNKNOWN || b == UNKNOWN ? UNKNOWN : values.Add(values.Get(a) == values.Get(b) ? std::vector<unsigned char>{1} : std::vector<unsigned char>{}));
            }
            break;
        }
        case OP_1ADD: case OP_1SUB: case OP_NEGATE: case OP_ABS: case OP_NOT: case OP_0NOTEQUAL: {
            int64_t a{0};
            if (!values.Num(stack.Pop(), a)) {
                stack.Push(UNKNOWN);
                break;
            }
            int64_t r{};
            switch (opcode) {
            case OP_1ADD: r = a + 1; break;
            case OP_1SUB: r = a - 1; break;
            case OP_NEGATE: r = -a; break;
            case OP_ABS: r = a < 0 ? -a : a; break;
            case OP_NOT: r = a == 0; break;
            default: r = a != 0; break;
            }
            stack.Push(values.AddNum(r));
            break;
        }
        case OP_ADD: case OP_SUB: case OP_BOOLAND: case OP_BOOLOR: case OP_NUMEQUAL: case OP_NUMEQUALVERIFY:
        case OP_NUMNOTEQUAL: case OP_LESSTHAN: case OP_GREATERTHAN: case OP_LESSTHANOREQUAL:
        case OP_GREATERTHANOREQUAL: case OP_MIN: case OP_MAX: {
            int64_t a{0}, b{0};
            const bool known_b{values.Num(stack.Pop(), b)};
            const bool known_a{values.Num(stack.Pop(), a)};
            if (opcode == OP_NUMEQUALVERIFY) break;
            if (!known_a || !known_b) {
                stack.Push(UNKNOWN);
                break;
            }
            int64_t r{};
            switch (opcode) {
            case OP_ADD: r = a + b; break;
            case OP_SUB: r = a - b; break;
            case OP_BOOLAND: r = a != 0 && b != 0; break;
            case OP_BOOLOR: r = a != 0 || b != 0; break;
            case OP_NUMEQUAL: r = a == b; break;
            case OP_NUMNOTEQUAL: r = a != b; break;
            case OP_LESSTHAN: r = a < b; break;
            case OP_GREATERTHAN: r = a > b; break;
            case OP_LESSTHANOREQUAL: r = a <= b; break;
            case OP_GREATERTHANOREQUAL: r = a >= b; break;
            case OP_MIN: r = a < b ? a : b; break;
            default: r = a > b ? a : b; break;
            }
            stack.Push(values.AddNum(r));
            break;
        }
        case OP_WITHIN: {
            int64_t hi{0}, lo{0}, x{0};
            const bool known_hi{values.Num(stack.Pop(), hi)};
            const bool known_lo{values.Num(stack.Pop(), lo)};
            const bool known_x{values.Num(stack.Pop(), x)};
            stack.Push(known_hi && known_lo && known_x ? values.AddNum(lo <= x && x < hi) : UNKNOWN);
            break;
        }
        case OP_RIPEMD160: case OP_SHA1: case OP_SHA256: case OP_HASH160: case OP_HASH256:
            stack.Pop();
            stack.Push(UNKNOWN);
            break;
        case OP_CHECKSIG:
            stack.Pop();
            stack.Pop();
            stack.Push(UNKNOWN);
            break;
        case OP_CHECKSIGVERIFY:
            stack.Pop();
            stack.Pop();
            break;
        case OP_CHECKSIGADD:
            stack.Pop();
            stack.Pop();
            stack.Pop();
            stack.Push(UNKNOWN);
            break;
        case OP_CHECKMULTISIG: case OP_CHECKMULTISIGVERIFY: {
            int64_t keys{0}, sigs{0};
            if (!values.Num(stack.Pop(), keys) || keys < 0 || keys > MAX_PUBKEYS_PER_MULTISIG) {
                stack.Forget();
            } else {
                for (int64_t i{0}; i < keys; ++i) stack.Pop();
                if (!values.Num(stack.Pop(), sigs) || sigs < 0 || sigs > keys) {
                    stack.Forget();
                } else {
                    for (int64_t i{0}; i < sigs + 1; ++i) stack.Pop(); // the signatures and the dummy
                }
            }
            if (opcode == OP_CHECKMULTISIG) stack.Push(UNKNOWN);
            break;
        }
        case OP_RETURN:
            return dead; // the script fails here
        default:
            // Not modeled: forget what is known rather than guess
            stack.Forget();
            alt.Forget();
            break;
        }
    }
    return dead;
}

size_t CScript::IsOLGA(const size_t remaining_outputs) const
{
    if (!IsPayToWitnessScriptHash()) {
        return 0;
    }

    const size_t olga_payload_size{(size_t{(*this)[2]} << 8) | (*this)[3]};
    const size_t olga_outputs{(olga_payload_size + 1) / WITNESS_V0_SCRIPTHASH_SIZE + 1};
    if (remaining_outputs < olga_outputs) {
        return 0;
    }

    if (((*this)[4] | 0x20) != 's') return 0;
    if (((*this)[5] | 0x20) != 't') return 0;
    if (((*this)[6] | 0x20) != 'a') return 0;
    if (((*this)[7] | 0x20) != 'm') return 0;
    if (((*this)[8] | 0x20) != 'p') return 0;
    if ((*this)[9] != ':') return 0;

    return olga_outputs * (WITNESS_V0_SCRIPTHASH_SIZE + /* script length */ 1 + /* amount */ 8);
}

size_t CScript::OPNetWitnessSize(const CScriptWitness& witness) const
{
    const auto& stack = witness.stack;

    if (stack.size() != 5) return 0;
    if (stack[4].size() != 65) return 0;

    const CScript tapscript{stack[3].begin(), stack[3].end()};
    bool found_opnet{false};
    size_t deduct{0};

    CScript::const_iterator pc = tapscript.begin();
    opcodetype opcode{OP_INVALIDOPCODE}, last_opcode{OP_INVALIDOPCODE};
    std::vector<unsigned char> data;
    while (pc < tapscript.end()) {
        last_opcode = opcode;
        if (!tapscript.GetOp(pc, opcode, data)) break;

        if (data.size() == 2 && data[0] == 0x6f && data[1] == 0x70) {
            found_opnet = true;
        }
        if (opcode == OP_CHECKSIGVERIFY && last_opcode == 0x20) {
            deduct += 34;
        }
    }

    if (!found_opnet) return 0;
    return stack[0].size() + stack[3].size() - deduct;
}

/** Value of OP_1..OP_16, or -1 for any other opcode. CScript::DecodeOP_N asserts instead. */
static int SmallIntValue(const opcodetype opcode)
{
    if (opcode < OP_1 || opcode > OP_16) return -1;
    return int{opcode} - int{OP_1 - 1};
}

/** The m or n of an m-of-n, which above 16 is a minimal one byte push rather than an OP_N. */
static int MultisigCount(const opcodetype opcode, const std::vector<unsigned char>& push_data)
{
    if (const int small{SmallIntValue(opcode)}; small > 0) return small;
    if (opcode == 1 && push_data.size() == 1 && push_data[0] > 16 && push_data[0] <= MAX_PUBKEYS_PER_MULTISIG) {
        return push_data[0];
    }
    return -1;
}

/**
 * The k of a tapscript k-of-n, which allows far more keys than OP_CHECKMULTISIG does.
 *
 * A k from 1 to 16 is an OP_N as usual. Beyond the range OP_N reaches, k is instead a minimal
 * push of the number: one byte up to 127, two beyond that, since a third would only ever hold
 * the sign of a count that cannot be negative.
 */
static int MultiACount(const opcodetype opcode, const std::vector<unsigned char>& push_data)
{
    if (const int small{SmallIntValue(opcode)}; small > 0) return small;
    if (opcode != 1 && opcode != 2) return -1;
    if (push_data.size() != static_cast<size_t>(opcode)) return -1;
    // The sign bit is never set here, and a zero high byte is minimal only where it keeps the
    // byte below it from reading as the sign, as in 128 written 80 00.
    if (push_data.back() & 0x80) return -1;
    if (push_data.back() == 0 && (push_data.size() == 1 || !(push_data[0] & 0x80))) return -1;
    int value{push_data[0]};
    if (push_data.size() == 2) value |= int{push_data[1]} << 8;
    if (value <= 16 || value > int{MAX_PUBKEYS_PER_MULTI_A}) return -1;
    return value;
}

static bool IsPubkeyPush(const opcodetype opcode, const std::vector<unsigned char>& push_data)
{
    if (opcode > OP_PUSHDATA4) return false;
    return push_data.size() == CPubKey::COMPRESSED_SIZE || push_data.size() == CPubKey::SIZE;
}

/** A 32 byte push, which is an x-only key where a checksig-family opcode claims it as one. */
static bool IsXOnlyPush(const opcodetype opcode, const std::vector<unsigned char>& push_data)
{
    return opcode <= OP_PUSHDATA4 && push_data.size() == XOnlyPubKey::size();
}

/** Opcodes that leave the stack as they found it, so the key below them is still on top. */
static bool IsStackNeutralNop(const opcodetype opcode)
{
    return opcode == OP_NOP || (opcode >= OP_NOP1 && opcode <= OP_NOP10);
}

/** Opcodes that neither read the stack nor change it. A timelock check reads the number on top. */
static bool IsNoOp(const opcodetype opcode)
{
    return opcode == OP_CODESEPARATOR || (IsStackNeutralNop(opcode) && opcode != OP_CHECKLOCKTIMEVERIFY && opcode != OP_CHECKSEQUENCEVERIFY);
}

/** A push of 5 bytes or less, which is a number where the opcode after it reads one. */
static bool IsShortPush(const opcodetype opcode, const std::vector<unsigned char>& push_data)
{
    return opcode <= OP_PUSHDATA4 && push_data.size() <= 5;
}

/** Mirror of the push run the caller counts when it is balanced by a drop. */
static bool IsRunPush(const opcodetype opcode)
{
    return opcode <= OP_16 && opcode != OP_RESERVED;
}

/**
 * Signature-shaped witness items: a DER signature plus its sighash byte, or a BIP340 one.
 *
 * The last item is the script or the control block of the spend, never a signature.
 */
static size_t CountWitnessSignatures(const CScriptWitness& witness)
{
    size_t count{0};
    for (size_t i{0}; i + 1 < witness.stack.size(); ++i) {
        const size_t size{witness.stack[i].size()};
        if (size >= 64 && size <= 73) ++count;
    }
    return count;
}

/** The size of the digest an opcode hashes the top item into, or 0 for any other opcode. */
static size_t DigestSize(const opcodetype opcode)
{
    switch (opcode) {
    case OP_RIPEMD160: case OP_SHA1: case OP_HASH160: return 20;
    case OP_SHA256: case OP_HASH256: return 32;
    default: return 0;
    }
}

/**
 * A push of 6 or more bytes that is no key a spend can check: longer than any number a script reads,
 * and neither a compressed key nor, outside a witness script, an uncompressed one. Segwit policy refuses
 * an uncompressed key wherever it checks one, so in a witness script 65 bytes is never a key either.
 */
static bool IsOddPush(const opcodetype opcode, const std::vector<unsigned char>& push_data, const bool witness_script)
{
    if (opcode > OP_PUSHDATA4 || push_data.size() <= 5 || push_data.size() == CPubKey::COMPRESSED_SIZE) return false;
    return witness_script || push_data.size() != CPubKey::SIZE;
}

/**
 * Bytes of the odd pushes in a push run that ends at `next`, less those something else accounts for.
 * A hash lock compares a digest with OP_EQUAL or OP_EQUALVERIFY: the last push of the run, sized as
 * the hash opcode before it outputs. The caller counts a run that a drop balances.
 */
static size_t OddRunBytes(const size_t run_bytes, const size_t last_bytes, const bool last_is_digest, const opcodetype next)
{
    if ((next == OP_EQUAL || next == OP_EQUALVERIFY) && last_is_digest) return run_bytes - last_bytes;
    if (next == OP_DROP || next == OP_2DROP) return 0;
    return run_bytes;
}

/**
 * Bytes a script carries in pubkeys that no signature can prove.
 *
 * A key in an m-of-n that nothing signs for authorizes nothing, so what it holds is payload
 * rather than a spending condition. That is how a file is published as a chain of ground
 * secp256k1 points, each carrying 31 bytes and hiding behind a hash until it is spent. Ordinary
 * multisig carries a couple of such keys itself, hence the tolerance.
 *
 * A key slot the spend never examines takes a push of any size, not only a key, so in a script that
 * runs OP_CHECKMULTISIG every odd push counts as data in full, outside the tolerance. So does a short
 * push with another push after it, no-ops aside: a script reads a number with the opcode after it, and
 * only a key count sits under keys, so a key count is left alone. None of the multisig spends
 * from block 961640 to 977870 has either that a hash lock, a drop or an OP_FALSE OP_IF envelope does
 * not account for, and none in a witness script has a 65 byte push.
 */
static size_t UnprovenPubkeyBytes(const CScript& script, const CScriptWitness* witness)
{
    /** Unproven pubkeys a script may carry before the rest are counted as data. Set so that ordinary
     *  multisig, including wide federations, is charged nothing at all: the budget is per
     *  transaction, so any per-input charge accumulates across inputs and would reject real spends. */
    static constexpr size_t MAX_UNPROVEN_PUBKEYS{10};

    size_t pubkeys{0}, provable{0};
    // The current run of adjacent pubkey pushes, and the count that opened it. A well-formed
    // m-of-n closes as <m> <pubkey>*n <n> OP_CHECKMULTISIG, and only that shape credits m.
    size_t run_keys{0};
    // Keys in the current push run, which the caller counts whole if a drop balances it.
    size_t push_run_keys{0};
    // The current run of a tapscript k-of-n, which names its keys one at a time as
    // <pubkey> OP_CHECKSIG (<pubkey> OP_CHECKSIGADD)* <k> OP_NUMEQUAL. Only that shape credits k.
    size_t multi_a_keys{0};
    int run_opened_by{-1}, last_count{-1}, last_a_count{-1};
    unsigned int inside_noop{0};
    bool last_is_push{false};
    // Whether the item before this one was a key a checksig-family opcode can still claim, and
    // whether it was the 32 byte kind that is only a key because one does.
    bool last_is_key{false}, last_is_xonly{false};
    opcodetype opcode{OP_INVALIDOPCODE}, last_opcode{OP_INVALIDOPCODE};
    std::vector<unsigned char> push_data;
    // Odd pushes counted so far, and those of the current push run, which its end decides.
    size_t odd_bytes{0}, odd_run_bytes{0}, odd_last_bytes{0};
    bool odd_last_is_digest{false};
    // The last short push, which counts if a push comes next, and whether a no-op has come between,
    // which leaves it outside the push run that the next push is in.
    size_t short_bytes{0};
    bool short_carried{false};

    // Odd pushes are this rule's only where the script runs OP_CHECKMULTISIG. A redeem script comes
    // with an empty witness, so a script with witness items here is a witness script.
    bool has_multisig{false};
    {
        unsigned int envelope{0};
        opcodetype op, last{OP_INVALIDOPCODE};
        std::vector<unsigned char> data;
        for (CScript::const_iterator it{script.begin()}; it < script.end(); last = op) {
            if (!script.GetOp(it, op, data)) return 0;
            if (envelope) {
                if (op == OP_IF || op == OP_NOTIF) {
                    ++envelope;
                } else if (op == OP_ENDIF) {
                    --envelope;
                }
            } else if (op == OP_IF && last == OP_FALSE) {
                envelope = 1;
            } else if (op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY) {
                has_multisig = true;
            }
        }
    }
    const bool segwit_multisig{has_multisig && witness && !witness->stack.empty()};

    for (CScript::const_iterator it{script.begin()}; it < script.end();) {
        // The caller counts an unparsable script whole, and the iterator may not have advanced.
        if (!script.GetOp(it, opcode, push_data)) return 0;
        const bool enveloped{inside_noop != 0};
        const bool is_pubkey{IsPubkeyPush(opcode, push_data) && !(segwit_multisig && push_data.size() == CPubKey::SIZE)};
        const bool is_xonly{IsXOnlyPush(opcode, push_data)};
        const int count{MultisigCount(opcode, push_data)};
        const int a_count{MultiACount(opcode, push_data)};
        bool is_key{false};

        if (inside_noop) {
            // A closed OP_FALSE OP_IF envelope is counted whole by the caller, so skip over it.
            if (opcode == OP_IF || opcode == OP_NOTIF) {
                ++inside_noop;
            } else if (opcode == OP_ENDIF) {
                --inside_noop;
            }
        } else if (opcode == OP_IF && last_opcode == OP_FALSE) {
            inside_noop = 1;
        } else if (is_pubkey) {
            if (!run_keys) run_opened_by = last_count;
            ++run_keys;
            ++push_run_keys;
            ++pubkeys;
            is_key = true;
        } else if (is_xonly) {
            // Nothing tells an x-only key from a hash but the opcode that spends it, so this
            // one is counted where a checksig-family opcode claims it rather than here. It
            // stays out of the push run for the same reason: a drop never reaches it.
            run_keys = 0;
            is_key = true;
        } else if ((opcode == OP_DROP || opcode == OP_2DROP) && last_is_push) {
            // The caller counts the whole run as dropped data, so do not charge it again.
            pubkeys -= push_run_keys;
            run_keys = 0;
            multi_a_keys = 0;
        } else if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY) {
            if (last_is_xonly) ++pubkeys;
            ++provable;
            run_keys = 0;
            // <pubkey> OP_CHECKSIG opens a tapscript k-of-n; anything else there ends one.
            multi_a_keys = (last_is_key && opcode == OP_CHECKSIG) ? 1 : 0;
        } else if (opcode == OP_CHECKSIGADD) {
            if (last_is_xonly) ++pubkeys;
            // The run is credited the k it closes on, so a key earns nothing on its own here.
            multi_a_keys = (multi_a_keys && last_is_key) ? multi_a_keys + 1 : 0;
            run_keys = 0;
        } else if ((opcode == OP_NUMEQUAL || opcode == OP_NUMEQUALVERIFY) && multi_a_keys) {
            // Padding or reordering the keys forfeits the credit rather than earning one, and
            // so does naming a k the run cannot satisfy. The OP_CHECKSIG that opened the run
            // has credited one of the k already.
            if (last_a_count > 0 && size_t(last_a_count) <= multi_a_keys) {
                provable += size_t(last_a_count) - 1;
            }
            multi_a_keys = 0;
            run_keys = 0;
        } else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY) {
            // Padding or reordering the keys forfeits the credit rather than earning one.
            if (run_opened_by > 0 && last_count > 0 && size_t(last_count) == run_keys) {
                provable += size_t(run_opened_by);
            }
            run_keys = 0;
            multi_a_keys = 0;
        } else if (count < 0) {
            // A key count sits on both ends of a multisig, so it does not break the run.
            run_keys = 0;
            if (a_count < 0) multi_a_keys = 0;
        }

        const bool is_push{IsRunPush(opcode)};
        if (!is_push) push_run_keys = 0;
        // The caller counts an OP_FALSE OP_IF envelope whole, so what is inside it is left to the caller.
        if (has_multisig && !enveloped) {
            if (is_push) {
                // The short push before this one is no number, so it joins the run the caller may
                // count as dropped, unless a no-op ended that run first.
                if (short_carried) {
                    odd_bytes += short_bytes;
                } else {
                    odd_run_bytes += short_bytes;
                }
                short_bytes = IsShortPush(opcode, push_data) && count < 0 ? push_data.size() : 0;
                short_carried = false;
                odd_last_bytes = IsOddPush(opcode, push_data, segwit_multisig) ? push_data.size() : 0;
                odd_last_is_digest = odd_last_bytes && DigestSize(last_opcode) == push_data.size();
                odd_run_bytes += odd_last_bytes;
            } else {
                odd_bytes += OddRunBytes(odd_run_bytes, odd_last_bytes, odd_last_is_digest, opcode);
                odd_run_bytes = odd_last_bytes = 0;
                odd_last_is_digest = false;
                // A no-op reads nothing, so the short push before it waits on the opcode after it.
                if (IsNoOp(opcode)) {
                    short_carried = true;
                } else {
                    short_bytes = 0;
                }
            }
        }
        // An opcode that leaves the stack as it found it leaves the key below it on top, so it
        // cannot hide that key from the opcode which spends it. It still breaks the run above:
        // padding a k-of-n is what forfeits its credit.
        if (!IsStackNeutralNop(opcode)) {
            last_is_key = is_key;
            last_is_xonly = is_xonly && !inside_noop;
        }
        last_opcode = opcode;
        last_count = count;
        last_a_count = a_count;
        last_is_push = is_push;
    }

    // A script can name more signatures than the spender supplies, including in branches that
    // never run. Where the witness carries the spend it is the honest count; a P2SH spend leaves
    // its signatures in the scriptSig, which is not visible here.
    //
    // A taproot script-path spend trails the script with a control block and, only when one is
    // present, an annex, but CountWitnessSignatures excludes only the true last item. A control
    // block can fall in the 64-73 byte range at a shallow merkle depth, so when an annex pushes
    // it off the end, it may be miscounted as a signature. That can only inflate the count this
    // rule caps against, never shrink it, so it can only undercharge, never overcharge: a
    // documented imprecision, not a bug.
    if (witness && !witness->stack.empty()) {
        provable = std::min(provable, CountWitnessSignatures(*witness));
    }

    if (has_multisig) odd_bytes += OddRunBytes(odd_run_bytes, odd_last_bytes, odd_last_is_digest, OP_INVALIDOPCODE);

    if (pubkeys < provable + MAX_UNPROVEN_PUBKEYS) return odd_bytes;
    // An uncompressed key carries no more payload than a compressed one, since only the x
    // coordinate is free, so the compressed size is the unit.
    return (pubkeys - provable - MAX_UNPROVEN_PUBKEYS) * CPubKey::COMPRESSED_SIZE + odd_bytes;
}

std::pair<size_t, size_t> CScript::DatacarrierBytes(const size_t remaining_outputs, const CScriptWitness* witness, const bool dead_branches) const
{
    if (size_t olga_bytes = IsOLGA(remaining_outputs); olga_bytes) {
        return {0, olga_bytes};
    }

    if (witness) {
        if (uint32_t opnet_bytes = OPNetWitnessSize(*witness); opnet_bytes) {
            return {0, opnet_bytes};
        }
    }

    // Where a constant guard makes part of a conditional unreachable
    const DeadParts dead{dead_branches ? FindDeadParts(*this) : DeadParts{}};
    // A span that began at a conditional counts its guard push too; one that began at OP_ELSE does not
    size_t span_guard{1};
    size_t counted{0};
    opcodetype opcode, last_opcode{OP_INVALIDOPCODE};
    std::vector<unsigned char> push_data;
    unsigned int inside_noop{0}, inside_conditional{0};
    auto is_push = [](opcodetype op) { return op <= OP_16 && op != OP_RESERVED; };  // OP_0..OP_16 push data/numbers
    CScript::const_iterator opcode_it = begin(), data_began = begin();
    for (CScript::const_iterator it = begin(); it < end(); last_opcode = opcode) {
        opcode_it = it;
        if (!GetOp(it, opcode, push_data)) {
            // Invalid scripts are necessarily all data
            return {0, size()};
        }

        if (opcode == OP_IF || opcode == OP_NOTIF) {
            ++inside_conditional;
        } else if (opcode == OP_ENDIF) {
            if (!inside_conditional) return {0, size()};  // invalid
            --inside_conditional;
        } else if (opcode == OP_RETURN && !inside_conditional) {
            // unconditional OP_RETURN is unspendable
            return {size(), 0};
        }

        // Count a conditional part that constants make unreachable: the
        // OP_FALSE OP_IF inscription envelope, and with dead_branches any part
        // FindDeadParts marks, including an OP_ELSE part. Pushes there cannot
        // affect the spend, so they are data. With dead_branches an OP_ELSE
        // switches between the counted and the live part; without it only the
        // envelope counts, through its OP_ENDIF.
        const size_t offset{size_t(opcode_it - begin())};
        const bool dead_guard{(opcode == OP_IF && last_opcode == OP_FALSE) ||
                              (dead_branches && (opcode == OP_IF || opcode == OP_NOTIF) && dead.at_if[offset])};
        if (dead_branches && !inside_noop && opcode == OP_ELSE && dead.at_else[offset]) {
            inside_noop = 1;
            data_began = opcode_it;
            span_guard = 0;
            continue;
        }
        if (dead_guard && !inside_noop) span_guard = 1;

        if (inside_noop) {
            switch (opcode) {
            case OP_IF: case OP_NOTIF:
                ++inside_noop;
                break;
            case OP_ELSE:
                if (dead_branches && inside_noop == 1) {
                    counted += opcode_it - data_began + span_guard;
                    inside_noop = 0;
                }
                break;
            case OP_ENDIF:
                if (0 == --inside_noop) {
                    counted += it - data_began + span_guard;
                }
                break;
            default: /* do nothing */;
            }
        } else if (dead_guard) {
            inside_noop = 1;
            data_began = opcode_it;
        // Match <data> OP_DROP, or a run of <data>/pushnums ... OP_DROP/OP_2DROP (bare/BIP-110 envelope)
        } else if (is_push(opcode)) {
            if (!is_push(last_opcode)) data_began = opcode_it;  // only reset at the start of a push run
        } else if ((opcode == OP_DROP || opcode == OP_2DROP) && is_push(last_opcode)) {
            counted += it - data_began;
        }
    }
    return {UnprovenPubkeyBytes(*this, witness), counted};
}

bool GetScriptOp(CScriptBase::const_iterator& pc, CScriptBase::const_iterator end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet)
{
    opcodeRet = OP_INVALIDOPCODE;
    if (pvchRet)
        pvchRet->clear();
    if (pc >= end)
        return false;

    // Read instruction
    if (end - pc < 1)
        return false;
    unsigned int opcode = *pc++;

    // Immediate operand
    if (opcode <= OP_PUSHDATA4)
    {
        unsigned int nSize = 0;
        if (opcode < OP_PUSHDATA1)
        {
            nSize = opcode;
        }
        else if (opcode == OP_PUSHDATA1)
        {
            if (end - pc < 1)
                return false;
            nSize = *pc++;
        }
        else if (opcode == OP_PUSHDATA2)
        {
            if (end - pc < 2)
                return false;
            nSize = ReadLE16(&pc[0]);
            pc += 2;
        }
        else if (opcode == OP_PUSHDATA4)
        {
            if (end - pc < 4)
                return false;
            nSize = ReadLE32(&pc[0]);
            pc += 4;
        }
        if (end - pc < 0 || (unsigned int)(end - pc) < nSize)
            return false;
        if (pvchRet)
            pvchRet->assign(pc, pc + nSize);
        pc += nSize;
    }

    opcodeRet = static_cast<opcodetype>(opcode);
    return true;
}

bool IsOpSuccess(const opcodetype& opcode)
{
    return opcode == 80 || opcode == 98 || (opcode >= 126 && opcode <= 129) ||
           (opcode >= 131 && opcode <= 134) || (opcode >= 137 && opcode <= 138) ||
           (opcode >= 141 && opcode <= 142) || (opcode >= 149 && opcode <= 153) ||
           (opcode >= 187 && opcode <= 254);
}

bool CheckMinimalPush(const std::vector<unsigned char>& data, opcodetype opcode) {
    // Excludes OP_1NEGATE, OP_1-16 since they are by definition minimal
    assert(0 <= opcode && opcode <= OP_PUSHDATA4);
    if (data.size() == 0) {
        // Should have used OP_0.
        return opcode == OP_0;
    } else if (data.size() == 1 && data[0] >= 1 && data[0] <= 16) {
        // Should have used OP_1 .. OP_16.
        return false;
    } else if (data.size() == 1 && data[0] == 0x81) {
        // Should have used OP_1NEGATE.
        return false;
    } else if (data.size() <= 75) {
        // Must have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode == data.size();
    } else if (data.size() <= 255) {
        // Must have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1;
    } else if (data.size() <= 65535) {
        // Must have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2;
    }
    return true;
}
