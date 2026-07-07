// Copyright 2014 BitPay Inc.
// Copyright 2015 Bitcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNIVALUE_INCLUDE_UNIVALUE_H
#define BITCOIN_UNIVALUE_INCLUDE_UNIVALUE_H

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#ifdef WITH_YYJSON
#include <yyjson/yyjson.h>
#endif

// NOLINTNEXTLINE(misc-no-recursion)
class UniValue {
public:
    enum VType { VNULL, VOBJ, VARR, VSTR, VNUM, VBOOL, };

    class type_error : public std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

#ifndef WITH_YYJSON
    UniValue() { typ = VNULL; }
    UniValue(UniValue::VType type, std::string str = {}) : typ{type}, val{std::move(str)} {}
#else
    UniValue();
    UniValue(UniValue::VType type, std::string str = {});
#endif
    template <typename Ref, typename T = std::remove_cv_t<std::remove_reference_t<Ref>>,
              std::enable_if_t<std::is_floating_point_v<T> ||                      // setFloat
                                   std::is_same_v<bool, T> ||                      // setBool
                                   std::is_signed_v<T> || std::is_unsigned_v<T> || // setInt
                                   std::is_constructible_v<std::string, T>,        // setStr
                               bool> = true>
    UniValue(Ref&& val)
    {
        if constexpr (std::is_floating_point_v<T>) {
            setFloat(val);
        } else if constexpr (std::is_same_v<bool, T>) {
            setBool(val);
        } else if constexpr (std::is_signed_v<T>) {
            setInt(int64_t{val});
        } else if constexpr (std::is_unsigned_v<T>) {
            setInt(uint64_t{val});
        } else {
            setStr(std::string{std::forward<Ref>(val)});
        }
    }

    void clear();

    void setNull();
    void setBool(bool val);
    void setNumStr(std::string str);
    void setInt(uint64_t val);
    void setInt(int64_t val);
    void setInt(int val_) { return setInt(int64_t{val_}); }
    void setFloat(double val);
    void setStr(std::string str);
    void setArray();
    void setObject();

#ifndef WITH_YYJSON
    enum VType getType() const { return typ; }
    const std::string& getValStr() const { return val; }
    bool empty() const { return (values.size() == 0); }
    size_t size() const { return values.size(); }
#else
    enum VType getType() const { return typ; }
    const std::string& getValStr() const;
    bool empty() const;
    size_t size() const;
#endif

    void reserve(size_t new_cap);

    void getObjMap(std::map<std::string,UniValue>& kv) const;
    bool checkObject(const std::map<std::string,UniValue::VType>& memberTypes) const;
    const UniValue& operator[](const std::string& key) const;
    const UniValue& operator[](size_t index) const;
    bool exists(const std::string& key) const { size_t i; return findKey(key, i); }

#ifndef WITH_YYJSON
    bool isNull() const { return (typ == VNULL); }
    bool isTrue() const { return (typ == VBOOL) && (val == "1"); }
    bool isFalse() const { return (typ == VBOOL) && (val != "1"); }
    bool isBool() const { return (typ == VBOOL); }
    bool isStr() const { return (typ == VSTR); }
    bool isNum() const { return (typ == VNUM); }
    bool isArray() const { return (typ == VARR); }
    bool isObject() const { return (typ == VOBJ); }
#else
    bool isNull() const { return (typ == VNULL); }
    bool isTrue() const;
    bool isFalse() const;
    bool isBool() const { return (typ == VBOOL); }
    bool isStr() const { return (typ == VSTR); }
    bool isNum() const { return (typ == VNUM); }
    bool isArray() const { return (typ == VARR); }
    bool isObject() const { return (typ == VOBJ); }
#endif

    void push_back(UniValue val);
    void push_backV(const std::vector<UniValue>& vec);
    template <class It>
    void push_backV(It first, It last);

    void pushKVEnd(std::string key, UniValue val);
    void pushKV(std::string key, UniValue val);
    void pushKVs(const UniValue& obj);

    std::string write(unsigned int prettyIndent = 0,
                      unsigned int indentLevel = 0) const;

    bool read(std::string_view raw);

    // Copy/move constructors and assignment operators
#ifndef WITH_YYJSON
    UniValue(const UniValue& other) : typ(other.typ), val(other.val), keys(other.keys), values(other.values) {}
    UniValue(UniValue&& other) noexcept : typ(other.typ), val(std::move(other.val)), keys(std::move(other.keys)), values(std::move(other.values)) {}
    UniValue& operator=(const UniValue& other) { if (this != &other) { typ = other.typ; val = other.val; keys = other.keys; values = other.values; } return *this; }
    UniValue& operator=(UniValue&& other) noexcept { if (this != &other) { typ = other.typ; val = std::move(other.val); keys = std::move(other.keys); values = std::move(other.values); } return *this; }
    ~UniValue() = default;
#else
    UniValue(const UniValue& other);
    UniValue(UniValue&& other) noexcept;
    UniValue& operator=(const UniValue& other);
    UniValue& operator=(UniValue&& other) noexcept;
    ~UniValue();
#endif

private:
    // Common members - mutable only when WITH_YYJSON for lazy materialization
#ifdef WITH_YYJSON
    mutable
#endif
    UniValue::VType typ;
#ifdef WITH_YYJSON
    mutable
#endif
    std::string val;                       // numbers are stored as C++ strings
#ifdef WITH_YYJSON
    mutable
#endif
    std::vector<std::string> keys;
#ifdef WITH_YYJSON
    mutable
#endif
    std::vector<UniValue> values;

#ifdef WITH_YYJSON
    // yyjson primary storage
    mutable std::shared_ptr<yyjson_mut_doc> m_yyjson_doc; //!< Shared pointer to yyjson mutable document (primary storage)
    mutable yyjson_mut_val* m_yyjson_node{nullptr};    //!< Pointer to the root node in the yyjson tree
    mutable bool m_materialized{false};                //!< Whether lazy caches (val/keys/values) have been populated

    void materialize() const;              // Populate lazy caches from yyjson
    void materializeIfNeeded() const;      // Centralized guard to materialize on-demand if needed
    static void yyjson_doc_deleter(yyjson_mut_doc* doc); //!< Custom deleter for yyjson document shared_ptr
#endif

    void checkType(const VType& expected) const;
    bool findKey(const std::string& key, size_t& retIdx) const;

#ifdef WITH_YYJSON
    // yyjson-specific write method
    std::string writeYyjson(unsigned int prettyIndent, unsigned int indentLevel) const;
#else
    // Original write methods
    void writeArray(unsigned int prettyIndent, unsigned int indentLevel, std::string& s) const;
    void writeObject(unsigned int prettyIndent, unsigned int indentLevel, std::string& s) const;
#endif

public:
    // Strict type-specific getters, these throw std::runtime_error if the
    // value is of unexpected type
    const std::vector<std::string>& getKeys() const;
    const std::vector<UniValue>& getValues() const;
    template <typename Int>
    Int getInt() const;
    bool get_bool() const;
    const std::string& get_str() const;
    double get_real() const;
    const UniValue& get_obj() const;
    const UniValue& get_array() const;

    enum VType type() const { return getType(); }
    const UniValue& find_value(std::string_view key) const;
};

template <class It>
void UniValue::push_backV(It first, It last)
{
    checkType(VARR);
#ifdef WITH_YYJSON
    // Always snapshot the input range to avoid iterator invalidation from self-append
    // This handles cases like arr.push_backV(arr.getValues().begin(), arr.getValues().end())
    std::vector<UniValue> snapshot;
    for (auto it = first; it != last; ++it) {
        snapshot.push_back(*it);
    }
    for (const auto& v : snapshot) {
        push_back(v);
    }
#else
    values.insert(values.end(), first, last);
#endif
}

template <typename Int>
Int UniValue::getInt() const
{
    static_assert(std::is_integral<Int>::value);
    checkType(VNUM);
    Int result;
    const auto [first_nonmatching, error_condition] = std::from_chars(val.data(), val.data() + val.size(), result);
    if (first_nonmatching != val.data() + val.size() || error_condition != std::errc{}) {
        throw std::runtime_error("JSON integer out of range");
    }
    return result;
}

enum jtokentype {
    JTOK_ERR        = -1,
    JTOK_NONE       = 0,                           // eof
    JTOK_OBJ_OPEN,
    JTOK_OBJ_CLOSE,
    JTOK_ARR_OPEN,
    JTOK_ARR_CLOSE,
    JTOK_COLON,
    JTOK_COMMA,
    JTOK_KW_NULL,
    JTOK_KW_TRUE,
    JTOK_KW_FALSE,
    JTOK_NUMBER,
    JTOK_STRING,
};

extern enum jtokentype getJsonToken(std::string& tokenVal,
                                    unsigned int& consumed, const char *raw, const char *end);
extern const char *uvTypeName(UniValue::VType t);

static inline bool jsonTokenIsValue(enum jtokentype jtt)
{
    switch (jtt) {
    case JTOK_KW_NULL:
    case JTOK_KW_TRUE:
    case JTOK_KW_FALSE:
    case JTOK_NUMBER:
    case JTOK_STRING:
        return true;

    default:
        return false;
    }

    // not reached
}

static inline bool json_isspace(int ch)
{
    switch (ch) {
    case 0x20:
    case 0x09:
    case 0x0a:
    case 0x0d:
        return true;

    default:
        return false;
    }

    // not reached
}

extern const UniValue NullUniValue;

#endif // BITCOIN_UNIVALUE_INCLUDE_UNIVALUE_H
