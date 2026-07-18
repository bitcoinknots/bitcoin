// Copyright 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit-license.php.

#include <univalue.h>
#include <univalue_common.h>
#include <yyjson/yyjson.h>

#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>



const UniValue NullUniValue;

/**
 * @brief Check if this UniValue represents true ("1")
 *
 * With eager materialization, primitives are always materialized, so this is a direct check.
 * For containers parsed from JSON, ensures legacy representation is populated.
 *
 * @return true if this is a boolean value equal to "1", false otherwise
 * @note In UniValue's encoding: "1" = true, "" (empty) = false
 */
bool UniValue::isTrue() const {
    if (typ != VBOOL) return false;
    materializeIfNeeded();
    return val == "1";
}

/**
 * @brief Check if this UniValue represents false ("")
 *
 * With eager materialization, primitives are always materialized, so this is a direct check.
 * For containers parsed from JSON, ensures legacy representation is populated.
 *
 * @return true if this is a boolean value not equal to "1", false otherwise
 * @note In UniValue's encoding: "1" = true, "" (empty) = false
 */
bool UniValue::isFalse() const {
    if (typ != VBOOL) return false;
    materializeIfNeeded();
    return val != "1";
}

/**
 * @brief Get type name as string
 *
 * @param t The VType to convert
 * @return String representation of the type ("null", "bool", "object", "array", "string", "number", or "unknown")
 */
const char *uvTypeName(UniValue::VType t)
{
    switch (t) {
    case UniValue::VNULL: return "null";
    case UniValue::VBOOL: return "bool";
    case UniValue::VOBJ: return "object";
    case UniValue::VARR: return "array";
    case UniValue::VSTR: return "string";
    case UniValue::VNUM: return "number";
    }
    return "unknown";
}

/**
 * @brief Custom deleter for yyjson mutable document shared_ptr
 *
 * Ensures proper cleanup of yyjson mutable documents when the shared_ptr goes out of scope.
 *
 * @param doc The document to free
 */
void UniValue::yyjson_doc_deleter(yyjson_mut_doc* doc) {
    yyjson_mut_doc_free(doc);
}

/**
 * @brief Set the root node of a yyjson mutable document
 *
 * Establishes ownership relationship between document and root node.
 * Required when creating new documents and assigning root nodes.
 *
 * @param doc The yyjson mutable document
 * @param node The root node to set
 */
static void setYyjsonRoot(yyjson_mut_doc* doc, yyjson_mut_val* node) {
    if (doc && node) {
        yyjson_mut_doc_set_root(doc, node);
    }
}
/**
 * @brief Default constructor - creates a null UniValue
 *
 * Creates a primitive VNULL value without a yyjson document.
 * Primitives (VNULL, VBOOL, VSTR, VNUM) store values only in the `val` member
 * and do not create yyjson documents for efficiency.
 * Documents are only created when primitives are pushed into containers.
 */
UniValue::UniValue() : typ(VNULL) {
    m_yyjson_doc = nullptr;
    m_yyjson_node = nullptr;
    val.clear();
    m_materialized = true;  // Primitives are always materialized
}

/**
 * @brief Constructor with type and string value
 *
 * For containers (VOBJ, VARR): Creates a yyjson document and root node for tree building.
 * For primitives (VNULL, VSTR, VNUM, VBOOL): Stores value only in `val`, no document.
 *
 * This split approach optimizes memory usage:
 * - Containers need documents to build their yyjson tree structure
 * - Primitives don't need documents when they'll be pushed into containers
 *
 * @param type The value type (VOBJ, VARR, VNULL, VSTR, VNUM, or VBOOL)
 * @param str The string value (for VSTR, VNUM, VBOOL) or ignored for containers
 */
UniValue::UniValue(UniValue::VType type, std::string str)
     : typ(type), m_materialized(false) {
    // Containers need yyjson documents for tree building
    if (type == VOBJ || type == VARR) {
        m_yyjson_doc = std::shared_ptr<yyjson_mut_doc>(yyjson_mut_doc_new(nullptr), yyjson_doc_deleter);
        if (!m_yyjson_doc) throw std::bad_alloc();

        switch (type) {
            case VOBJ:
                m_yyjson_node = yyjson_mut_obj(m_yyjson_doc.get());
                break;
            case VARR:
                m_yyjson_node = yyjson_mut_arr(m_yyjson_doc.get());
                break;
            default:
                // Should not happen
                m_yyjson_node = nullptr;
                break;
        }
        if (!m_yyjson_node) throw std::bad_alloc();
        setYyjsonRoot(m_yyjson_doc.get(), m_yyjson_node);
        // Eager materialization: populate legacy representation immediately
        materialize();
    } else {
        // Primitive types: store in val only, no document needed
        m_yyjson_doc = nullptr;
        m_yyjson_node = nullptr;

        switch (type) {
            case VNULL:
                val.clear();
                break;
            case VSTR:
                val = str;  // Store string in val for fast access
                break;
            case VNUM:
                val = str;  // Store number string in val for fast access
                break;
            case VBOOL:
                val = str;  // Store "1" or "0" in val for fast access
                break;
            default:
                // Should not happen for primitives
                val.clear();
                break;
        }
        m_materialized = true;  // Primitives are always materialized
    }
}

/** @brief Destructor */
UniValue::~UniValue() {}

/**
 * @brief Copy constructor
 *
 * For primitives: Copies `val` directly (already populated, no document).
 * For containers: Deep copies the yyjson tree using yyjson_mut_val_mut_copy()
 * to preserve performance. Falls back to materializing and copying keys/values
 * if the source has no yyjson tree.
 * For values without documents: Copies val only, no yyjson state.
 *
 * @param other The UniValue to copy from
 */
UniValue::UniValue(const UniValue& other)
    : typ(other.typ), m_materialized(false)
{
    // Initialize yyjson state to null (will be set below if needed)
    m_yyjson_doc = nullptr;
    m_yyjson_node = nullptr;

    // For primitives, copy val directly (it's already populated)
    if (other.typ != VARR && other.typ != VOBJ) {
        val = other.val;
        m_materialized = true;
    } else {
        // For containers: preserve yyjson tree if available to maintain performance
        if (other.m_yyjson_doc && other.m_yyjson_node) {
            // Deep copy the yyjson tree
            m_yyjson_doc = std::shared_ptr<yyjson_mut_doc>(yyjson_mut_doc_new(nullptr), yyjson_doc_deleter);
            m_yyjson_node = yyjson_mut_val_mut_copy(m_yyjson_doc.get(), other.m_yyjson_node);
            if (!m_yyjson_node) {
                // Copy failed, fall back: must materialize other to get its data
                m_yyjson_doc.reset();
                const_cast<UniValue&>(other).materialize();
                keys = other.keys;
                values = other.values;
                m_materialized = true;
            } else {
                setYyjsonRoot(m_yyjson_doc.get(), m_yyjson_node);
                // Eager materialization: populate legacy representation immediately
                materialize();
            }
        } else if (other.m_materialized) {
            // Other is already materialized without yyjson tree, copy keys/values directly
            keys = other.keys;
            values = other.values;
            m_materialized = true;
        } else {
            // Other has no yyjson state and is not materialized
            // Materialize other first to ensure we get the correct data
            const_cast<UniValue&>(other).materialize();
            keys = other.keys;
            values = other.values;
            m_materialized = true;
        }
    }
}

/**
 * @brief Move constructor
 *
 * Transfers ownership of yyjson state from other to this.
 * Other is left in a valid but unspecified state.
 *
 * @param other The UniValue to move from
 */
UniValue::UniValue(UniValue&& other) noexcept
{
    // Clear existing state first
    clear();

    // Move all state from other
    typ = other.typ;
    val = std::move(other.val);
    keys = std::move(other.keys);
    values = std::move(other.values);
    m_yyjson_doc = std::move(other.m_yyjson_doc);
    m_yyjson_node = other.m_yyjson_node;
    m_materialized = other.m_materialized;

    // Reset other to safe state
    other.typ = VNULL;
    other.m_yyjson_node = nullptr;
    other.m_materialized = false;
}

/**
 * @brief Copy assignment operator
 *
 * Similar to copy constructor: deep copy yyjson tree for containers using
 * yyjson_mut_val_mut_copy() to preserve performance, copy val directly for primitives.
 * Handles self-assignment safely by taking a complete snapshot of the source before
 * clearing the destination, ensuring that self-referential assignments like obj = obj["child"]
 * do not invalidate the source data.
 *
 * @param other The UniValue to copy from
 * @return Reference to this
 */
UniValue& UniValue::operator=(const UniValue& other) {
    if (this != &other) {
        // Take a COMPLETE snapshot of the source state BEFORE clearing this
        // to handle self-referential assignments like obj = obj["child"].
        // This ensures that clearing this->keys/values doesn't invalidate 'other'
        // when other is a reference into this's data structures.
        const VType other_typ = other.typ;
        const std::string other_val = other.val;
        std::vector<std::string> other_keys;
        std::vector<UniValue> other_values;
        bool other_has_yyjson = other.m_yyjson_doc && other.m_yyjson_node;
        bool other_materialized = other.m_materialized;
        
        // Snapshot yyjson state to use after clear() - retain strong reference to doc
        std::shared_ptr<yyjson_mut_doc> other_doc;
        yyjson_mut_val* other_node = nullptr;
        if (other_has_yyjson) {
            other_doc = other.m_yyjson_doc;  // Retain strong reference before clear()
            other_node = other.m_yyjson_node;
        }

        // For containers, snapshot the data we'll need after clear()
        // Note: Even if other has a yyjson tree, we may need keys/values if tree copy fails
        if (other_typ == VARR || other_typ == VOBJ) {
            if (other_has_yyjson) {
                // Snapshot keys/values in case tree copy fails and we need fallback
                const_cast<UniValue&>(other).materialize();
                other_keys = other.keys;
                other_values = other.values;
                other_materialized = true;
            } else if (other_materialized) {
                // Already materialized without tree, snapshot keys/values
                other_keys = other.keys;
                other_values = other.values;
            } else {
                // Not materialized and no tree, need to materialize first then snapshot
                const_cast<UniValue&>(other).materialize();
                other_keys = other.keys;
                other_values = other.values;
                other_materialized = true;
            }
        }

        // Clear existing state first to release resources
        clear();

        // For primitives, copy val directly (it's already populated)
        if (other_typ != VARR && other_typ != VOBJ) {
            typ = other_typ;
            val = other_val;
            m_materialized = true;
        } else {
            // For containers: preserve yyjson tree if available to maintain performance
            if (other_has_yyjson) {
                // Deep copy the yyjson tree using snapshotted node
                m_yyjson_doc = std::shared_ptr<yyjson_mut_doc>(yyjson_mut_doc_new(nullptr), yyjson_doc_deleter);
                m_yyjson_node = yyjson_mut_val_mut_copy(m_yyjson_doc.get(), other_node);
                if (!m_yyjson_node) {
                    // Copy failed, fall back: use snapshotted keys/values
                    m_yyjson_doc.reset();
                    typ = other_typ;
                    keys = std::move(other_keys);
                    values = std::move(other_values);
                    m_materialized = other_materialized;
                } else {
                    typ = other_typ;
                    setYyjsonRoot(m_yyjson_doc.get(), m_yyjson_node);
                    // Eager materialization: populate legacy representation immediately
                    materialize();
                }
            } else {
                // Other has no yyjson tree, use snapshotted keys/values
                typ = other_typ;
                keys = std::move(other_keys);
                values = std::move(other_values);
                m_materialized = other_materialized;
            }
        }
    }
    return *this;
}

/**
 * @brief Move assignment operator
 *
 * Transfers ownership from other to this.
 * Other is left in a valid but unspecified state.
 *
 * @param other The UniValue to move from
 * @return Reference to this
 */
UniValue& UniValue::operator=(UniValue&& other) noexcept {
    if (this != &other) {
        // Clear existing state
        clear();

        // Move all state from other
        typ = other.typ;
        val = std::move(other.val);
        keys = std::move(other.keys);
        values = std::move(other.values);
        m_yyjson_doc = std::move(other.m_yyjson_doc);
        m_yyjson_node = other.m_yyjson_node;  // Move node pointer (other's doc is now null after move)
        m_materialized = other.m_materialized;

        // Reset other to safe state
        other.typ = VNULL;
        other.m_yyjson_node = nullptr;
        other.m_materialized = false;
    }
    return *this;
}

/**
 * @brief Clear the UniValue, setting it to null
 *
 * Resets all state: type, val, keys, values, yyjson document and node.
 * The UniValue becomes a null value.
 */
void UniValue::clear() {
    typ = VNULL;
    val.clear();
    keys.clear();
    values.clear();
    m_yyjson_doc.reset();
    m_yyjson_node = nullptr;
    m_materialized = false;
}

/**
 * @brief Set this UniValue to null
 *
 * Optimization: Primitives don't need their own yyjson documents.
 * They will create nodes directly when pushed into containers.
 */
void UniValue::setNull() {
    clear();
    m_yyjson_doc = nullptr;
    m_yyjson_node = nullptr;
    typ = VNULL;
    val.clear();
    m_materialized = true;  // Primitives are always materialized
}

/**
 * @brief Set this UniValue to a boolean value
 *
 * Optimization: Primitives don't need their own yyjson documents.
 * They will create nodes directly when pushed into containers.
 *
 * @param val_ Boolean value (true becomes "1", false becomes "")
 */
void UniValue::setBool(bool val_) {
    clear();
    m_yyjson_doc = nullptr;
    m_yyjson_node = nullptr;
    typ = VBOOL;
    if (val_) {
        val = "1";
    } else {
        val.clear();  // Empty string for false
    }
    m_materialized = true;  // Primitives are always materialized
}

/**
 * @brief Check if character is a digit (0-9)
 *
 * @param ch Character to check (as int for compatibility with character classification)
 * @return true if ch is between '0' and '9' inclusive, false otherwise
 */
static bool json_isdigit(int ch) {
    return ((ch >= '0') && (ch <= '9'));
}

/**
 * @brief Validate a JSON number string according to UniValue's strict rules
 *
 * Ensures the string conforms to JSON number format while rejecting:
 * - Empty strings
 * - Strings with leading/trailing whitespace
 * - Embedded NUL characters
 * - Hex numbers (0x...)
 * - Leading zeros (except "0" itself)
 * - Invalid characters
 *
 * Supports:
 * - Optional minus sign
 * - Integer part (required)
 * - Optional decimal point and fractional part
 * - Optional exponent (e or E) with optional sign
 *
 * @param s The string to validate
 * @return true if valid JSON number, false otherwise
 */
static bool validNumStr(const std::string& s) {
    if (s.empty()) return false;
    if (s.size() >= 1 && (json_isspace(s[0]) || json_isspace(s[s.size()-1]))) return false;
    if (s.size() != strlen(s.c_str())) return false; // No embedded NUL
    if (s.size() >= 2 && s[0] == '0' && s[1] == 'x') return false; // No hex

    const char *raw = s.data();
    const char *end = raw + s.size();

    // Must start with digit, minus, or dot
    if (!json_isdigit(static_cast<unsigned char>(*raw)) && *raw != '-' && *raw != '.')
        return false;

    const char *firstDigit = raw;
    if (*firstDigit == '-') {
        firstDigit++;
        raw++; // Also advance raw past the sign
    }

    if (firstDigit == end)
        return false;

    if (!json_isdigit(static_cast<unsigned char>(*firstDigit)))
        return false;

    // Check for leading zeros
    if (*firstDigit == '0' && firstDigit + 1 < end && json_isdigit(static_cast<unsigned char>(firstDigit[1])))
        return false;

    // Parse the integer part
    bool hasDigit = false;
    while (raw < end && json_isdigit(static_cast<unsigned char>(*raw))) {
        hasDigit = true;
        raw++;
    }

    // Fractional part
    if (raw < end && *raw == '.') {
        raw++;
        if (raw >= end || !json_isdigit(static_cast<unsigned char>(*raw)))
            return false;
        while (raw < end && json_isdigit(static_cast<unsigned char>(*raw))) {
            hasDigit = true;
            raw++;
        }
    }

    // Exponent
    if (raw < end && (*raw == 'e' || *raw == 'E')) {
        raw++;
        if (raw < end && (*raw == '+' || *raw == '-'))
            raw++;
        if (raw >= end || !json_isdigit(static_cast<unsigned char>(*raw)))
            return false;
        while (raw < end && json_isdigit(static_cast<unsigned char>(*raw))) {
            hasDigit = true;
            raw++;
        }
    }

    return hasDigit && raw == end;
}

/**
 * @brief Set this UniValue to a number string
 *
 * Validates the string using validNumStr() before setting.
 * Creates a yyjson document and stores the number as raw text.
 *
 * @param str The number string to set
 * @throws std::runtime_error if the string is not a valid JSON number
 */
void UniValue::setNumStr(std::string str) {
    if (!validNumStr(str)) {
        throw std::runtime_error("The string '" + str + "' is not a valid JSON number");
    }

    clear();
    m_yyjson_doc = nullptr;
    m_yyjson_node = nullptr;
    typ = VNUM;
    val = std::move(str);
    m_materialized = true;  // Primitives are always materialized
}

/**
 * @brief Set this UniValue to an unsigned 64-bit integer
 *
 * Converts the integer to a string and stores it.
 * Optimization: Primitives don't need their own yyjson documents.
 *
 * @param val_ The unsigned integer value
 */
void UniValue::setInt(uint64_t val_) {
    std::ostringstream oss;
    oss << val_;
    std::string str = oss.str();
    clear();
    m_yyjson_doc = nullptr;
    m_yyjson_node = nullptr;
    typ = VNUM;
    val = str;  // Store number string for fast access
    m_materialized = true;  // Primitives are always materialized
}

/**
 * @brief Set this UniValue to a signed 64-bit integer
 *
 * Converts the integer to a string and stores it.
 * Optimization: Primitives don't need their own yyjson documents.
 *
 * @param val_ The signed integer value
 */
void UniValue::setInt(int64_t val_) {
    std::ostringstream oss;
    oss << val_;
    std::string str = oss.str();
    clear();
    m_yyjson_doc = nullptr;
    m_yyjson_node = nullptr;
    typ = VNUM;
    val = str;  // Store number string for fast access
    m_materialized = true;  // Primitives are always materialized
}

/**
 * @brief Set this UniValue to a floating-point number
 *
 * Converts the double to a string with 16 digits of precision.
 * Optimization: Primitives don't need their own yyjson documents.
 *
 * @param val_ The floating-point value
 */
void UniValue::setFloat(double val_) {
    std::ostringstream ss;
    ss << std::setprecision(16) << val_;
    setNumStr(ss.str());
}

/**
 * @brief Set this UniValue to a string
 *
 * Optimization: Primitives don't need their own yyjson documents.
 * They will create nodes directly when pushed into containers.
 *
 * @param str The string value
 */
void UniValue::setStr(std::string str) {
    clear();
    m_yyjson_doc = nullptr;
    m_yyjson_node = nullptr;
    typ = VSTR;
    val = str;  // Store string for fast access
    m_materialized = true;  // Primitives are always materialized
}

/**
 * @brief Set this UniValue to an empty array
 *
 * Creates a yyjson document and an empty array node.
 */
void UniValue::setArray() {
    clear();
    m_yyjson_doc = std::shared_ptr<yyjson_mut_doc>(yyjson_mut_doc_new(nullptr), yyjson_doc_deleter);
    m_yyjson_node = yyjson_mut_arr(m_yyjson_doc.get());
    setYyjsonRoot(m_yyjson_doc.get(), m_yyjson_node);
    typ = VARR;
    // Eager materialization: populate legacy representation immediately
    materialize();
}

/**
 * @brief Set this UniValue to an empty object
 *
 * Creates a yyjson document and an empty object node.
 */
void UniValue::setObject() {
    clear();
    m_yyjson_doc = std::shared_ptr<yyjson_mut_doc>(yyjson_mut_doc_new(nullptr), yyjson_doc_deleter);
    if (!m_yyjson_doc) throw std::bad_alloc();

    m_yyjson_node = yyjson_mut_obj(m_yyjson_doc.get());
    setYyjsonRoot(m_yyjson_doc.get(), m_yyjson_node);
    typ = VOBJ;
    // Eager materialization: populate legacy representation immediately
    materialize();
}

/**
 * @brief Check if this UniValue is of the expected type
 *
 * @param expected The expected VType
 * @throws std::runtime_error if the type doesn't match
 */
void UniValue::checkType(const VType& expected) const {
    if (typ != expected) {
        throw type_error(std::string("UniValue type is not ") + uvTypeName(expected));
    }
}
/**
 * @brief Materialize the yyjson tree into the legacy UniValue representation
 *
 * Populates the `val`, `keys`, and `values` members from the yyjson tree.
 * This is the main materialization method - callers ensure thread safety through eager materialization.
 *
 * SPECIAL NOTE: Neither UniValue nor yyjson are thread safe.  Depsite
 * this returning a const, the contents can change.  The caller must provide
 * their own thread safety mechanism.
 * 
 * For primitives: Extracts the value from the yyjson node into `val`
 * For arrays: Builds the `values` vector from the yyjson array
 * For objects: Builds both `keys` and `values` vectors from the yyjson object
 */
void UniValue::materialize() const {
    if (m_materialized) return;
    if (!m_yyjson_doc || !m_yyjson_node) return;

    yyjson_type ytype = yyjson_mut_get_type(m_yyjson_node);
    switch (ytype) {
        case YYJSON_TYPE_NULL:
            typ = VNULL;
            m_yyjson_doc.reset();
            m_yyjson_node = nullptr;
            break;
        case YYJSON_TYPE_BOOL:
            typ = VBOOL;
            if (yyjson_mut_get_bool(m_yyjson_node)) {
                val = "1";
            } else {
                val.clear();
            }
            m_yyjson_doc.reset();
            m_yyjson_node = nullptr;
            break;
        case YYJSON_TYPE_RAW:
        case YYJSON_TYPE_NUM: {
            const char* raw = yyjson_mut_get_raw(m_yyjson_node);
            size_t len = yyjson_mut_get_len(m_yyjson_node);
            typ = VNUM;
            if (raw && len > 0) {
                val.assign(raw, len);
            } else {
                val = "0";
            }
            m_yyjson_doc.reset();
            m_yyjson_node = nullptr;
            break;
        }
        case YYJSON_TYPE_STR: {
            const char* str = yyjson_mut_get_str(m_yyjson_node);
            size_t len = yyjson_mut_get_len(m_yyjson_node);
            typ = VSTR;
            if (str && len > 0) {
                val.assign(str, len);
            } else {
                val = "";
            }
            m_yyjson_doc.reset();
            m_yyjson_node = nullptr;
            break;
        }
        case YYJSON_TYPE_ARR: {
            typ = VARR;
            values.clear();
            size_t arr_size = yyjson_mut_arr_size(m_yyjson_node);
            values.reserve(arr_size);
            {
                size_t idx, max;
                yyjson_mut_val *item;
                yyjson_mut_arr_foreach(m_yyjson_node, idx, max, item) {
                    UniValue new_val;
                    new_val.clear();
                    new_val.m_yyjson_doc = m_yyjson_doc;
                    new_val.m_yyjson_node = item;
                    new_val.materialize();
                    values.push_back(std::move(new_val));
                }
            }
            break;
        }
        case YYJSON_TYPE_OBJ: {
            typ = VOBJ;
            keys.clear();
            values.clear();
            size_t obj_size = yyjson_mut_obj_size(m_yyjson_node);
            keys.reserve(obj_size);
            values.reserve(obj_size);
            {
                yyjson_mut_val *key, *v;
                yyjson_mut_obj_iter iter;
                if (yyjson_mut_obj_iter_init(m_yyjson_node, &iter)) {
                    while ((key = yyjson_mut_obj_iter_next(&iter))) {
                        v = yyjson_mut_obj_iter_get_val(key);
                        const char* kstr = yyjson_mut_get_str(key);
                        size_t klen = yyjson_mut_get_len(key);
                        std::string k;
                        if (kstr && klen > 0) {
                            k.assign(kstr, klen);
                        }
                        UniValue new_val;
                        new_val.clear();
                        new_val.m_yyjson_doc = m_yyjson_doc;
                        new_val.m_yyjson_node = v;
                        new_val.materialize();
                        keys.push_back(std::move(k));
                        values.push_back(std::move(new_val));
                    }
                }
            }
            break;
        }
        default:
            break;
    }
    m_materialized = true;
}

/**
 * @brief Materialize the yyjson tree into the legacy UniValue representation
 *
 * Populates the `val`, `keys`, and `values` members from the yyjson tree.
 * This is called lazily when accessors need the legacy representation.
 *
 * For primitives: Extracts the value from the yyjson node into `val`
 * For arrays: Builds the `values` vector from the yyjson array
 * For objects: Builds both `keys` and `values` vectors from the yyjson object
 *
 * Supports rematerialization when m_materialized is set to false (e.g., after
 * push_back/pushKV add to the yyjson tree). Uses eager materialization for performance.
 *
 * @note With eager materialization, containers are materialized immediately on construction/modification.
 */
// With eager materialization, this is typically a no-op
// since containers are materialized immediately on construction/modification
// materialize() now directly implements the materialization logic

/**
 * @brief Ensure the UniValue is materialized (eager materialization)
 *
 * With eager materialization, containers are materialized immediately on construction
 * or modification, so this is typically a no-op. However, it ensures the legacy
 * representation is populated if needed.
 */
void UniValue::materializeIfNeeded() const {
    materialize();
}


/**
 * @brief Find a key in an object
 *
 * Searches for a key in the object's keys vector.
 * With eager materialization, containers are materialized immediately on construction,
 * so this typically accesses already-populated data.
 *
 * @param key The key to find
 * @param retIdx Output parameter for the index if found
 * @return true if key was found, false otherwise
 */
bool UniValue::findKey(const std::string& key, size_t& retIdx) const {
    if (typ != VOBJ) return false;

    if (m_yyjson_doc && m_yyjson_node) {
        if (!m_materialized) {
            materialize();
        }
        for (size_t i = 0; i < keys.size(); ++i) {
            if (keys[i] == key) {
                retIdx = i;
                return true;
            }
        }
        return false;
    }

    for (size_t i = 0; i < keys.size(); ++i) {
        if (keys[i] == key) {
            retIdx = i;
            return true;
        }
    }
    return false;
}

/**
 * @brief Get the string representation of this value
 *
 * With eager materialization, primitives are always materialized directly.
 * For containers parsed from JSON, extracts the value from the tree if needed.
 *
 * @return Reference to the val string
 */
const std::string& UniValue::getValStr() const {
    if (m_yyjson_doc && m_yyjson_node) {
        if (!m_materialized) {
            materialize();
        }
    }
    return val;
}

/**
 * @brief Check if this container is empty
 *
 * With eager materialization, containers are materialized immediately on construction,
 * so this typically accesses already-populated data.
 *
 * @return true if empty, false otherwise
 */
bool UniValue::empty() const {
    if ((typ == VOBJ || typ == VARR) && m_yyjson_doc && m_yyjson_node) {
        if (!m_materialized) {
            materialize();
        }
    }
    return values.empty();
}

/**
 * @brief Get the size of this container
 *
 * With eager materialization, containers are materialized immediately on construction,
 * so this typically returns the already-cached size.
 *
 * @return Number of elements in the container
 */
size_t UniValue::size() const {
    if ((typ == VOBJ || typ == VARR) && m_yyjson_doc && m_yyjson_node) {
        if (!m_materialized) {
            materialize();
        }
    }
    // For containers, return the materialized size
    // Note: After materialization, values.size() should match the yyjson container size
    return values.size();
}

/**
 * @brief Reserve capacity for an array or object
 *
 * With eager materialization, containers are materialized immediately on construction.
 * Reserves the requested capacity in the values vector.
 * For objects, also reserves capacity in the keys vector.
 * Note: yyjson's reservation is array-only; objects must be materialized first.
 *
 * @param new_cap The new capacity to reserve
 */
void UniValue::reserve(size_t new_cap) {
    if (typ != VARR && typ != VOBJ) {
        checkType(VARR);
    }
    if (m_yyjson_doc && m_yyjson_node && !m_materialized) {
        materialize();
    }
    values.reserve(new_cap);
    if (typ == VOBJ) {
        keys.reserve(new_cap);
    }
}

/**
 * @brief Append a value to an array
 *
 * Optimization: For primitives without their own documents, creates yyjson nodes
 * directly in the container's document, avoiding document-to-document copying.
 * For values with documents (containers, parsed primitives), copies the node.
 *
 * This is a key optimization that eliminates the overhead of creating temporary
 * documents for primitives when building arrays.
 *
 * @param val The value to append
 */
void UniValue::push_back(UniValue val) {
    checkType(VARR);

    bool use_legacy_path = false;

    // Add to yyjson array (primary storage) or to materialized representation
    if (m_yyjson_doc && m_yyjson_node && yyjson_mut_get_type(m_yyjson_node) == YYJSON_TYPE_ARR) {
        // Check if we need to use legacy path (val is a container without yyjson tree)
        if (val.typ == VOBJ || val.typ == VARR) {
            if (!val.m_yyjson_doc || !val.m_yyjson_node) {
                // Container without yyjson tree - use legacy path
                use_legacy_path = true;
            }
        }

        if (!use_legacy_path) {
            yyjson_mut_val* new_val = nullptr;
            if (val.m_yyjson_doc && val.m_yyjson_node) {
                // val has its own yyjson tree - use yyjson's optimized copy function for mutable values
                new_val = yyjson_mut_val_mut_copy(m_yyjson_doc.get(), val.m_yyjson_node);
                if (!new_val) {
                    // Copy failed, cannot add to array
                    throw std::bad_alloc();
                }
            } else {
                // Optimization: val is a primitive without its own document
                // Create yyjson node directly from val's value
                switch (val.typ) {
                    case VNULL:
                        new_val = yyjson_mut_null(m_yyjson_doc.get());
                        break;
                    case VBOOL:
                        new_val = yyjson_mut_bool(m_yyjson_doc.get(), val.val == "1");
                        break;
                    case VNUM:
                        new_val = (yyjson_mut_val*)yyjson_mut_rawncpy(m_yyjson_doc.get(), val.val.data(), val.val.size());
                        break;
                    case VSTR:
                        new_val = (yyjson_mut_val*)yyjson_mut_strncpy(m_yyjson_doc.get(), val.val.data(), val.val.size());
                        break;
                    default:
                        // Shouldn't happen for non-container types
                        throw std::runtime_error("Unexpected type in push_back");
                }
            }
            if (!new_val) {
                // Node creation failed, cannot add to array
                throw std::bad_alloc();
            }
            if (!yyjson_mut_arr_append((yyjson_mut_val*)m_yyjson_node, new_val)) {
                throw std::runtime_error("yyjson_mut_arr_append failed");
            }
            // Mark as not materialized so legacy representation will be rebuilt on demand
            m_materialized = false;
            return;
        } else {
            // use_legacy_path is true: container without yyjson tree
            // With incremental materialization, the tree and values should already be in sync
            // No need to materialize here
        }
    }
    // Fallback to legacy representation
    // This is used when:
    // 1. The target array doesn't have yyjson tree
    // 2. The value is a container without yyjson tree (after materializing if needed)
    if (m_yyjson_doc && m_yyjson_node && !m_materialized) {
        materialize();
    }
    values.push_back(std::move(val));
    // Clear yyjson state to ensure writeYyjson() uses legacy representation
    m_yyjson_doc.reset();
    m_yyjson_node = nullptr;
    m_materialized = true;  // Legacy representation is now up to date
}

/**
 * @brief Add a key-value pair to an object
 *
 * Optimization: For primitives without their own documents, creates yyjson nodes
 * directly in the container's document, avoiding document-to-document copying.
 * For values with documents (containers, parsed primitives), copies the node.
 *
 * If the key already exists, the old value is replaced.
 *
 * @param key The key to add/update
 * @param val The value to associate with the key
 */
void UniValue::pushKV(std::string key, UniValue val) {
    checkType(VOBJ);

    size_t idx;
    bool use_legacy_path = false;

    if (m_yyjson_doc && m_yyjson_node) {
        // Always update the yyjson tree (primary storage)
        // Create key first, then value - if either fails, we throw
        yyjson_mut_val* new_key = (yyjson_mut_val*)yyjson_mut_strncpy(m_yyjson_doc.get(), key.data(), key.size());
        if (!new_key) {
            // Key allocation failed, cannot add the pair
            throw std::bad_alloc();
        }

        // Check if we need to use legacy path (val is a container without yyjson tree)
        if (val.typ == VOBJ || val.typ == VARR) {
            if (!val.m_yyjson_doc || !val.m_yyjson_node) {
                // Container without yyjson tree - use legacy path
                use_legacy_path = true;
            }
        }

        if (use_legacy_path) {
            // Can't add container without yyjson tree to yyjson object
            // With incremental materialization, the tree and keys/values should already be in sync
            // Fall through to legacy representation
        } else {
            // Optimization: Handle values with yyjson tree (both materialized and non-materialized)
            yyjson_mut_val* new_val = nullptr;
            if (val.m_yyjson_doc && val.m_yyjson_node) {
                // val has its own yyjson tree - use yyjson's optimized copy function for mutable values
                // This works for both materialized and non-materialized containers
                new_val = yyjson_mut_val_mut_copy(m_yyjson_doc.get(), val.m_yyjson_node);
                if (!new_val) {
                    // Copy failed, cannot add the pair
                    throw std::bad_alloc();
                }
            } else {
                // val is a primitive without its own document
                // Create yyjson node directly from val's value
                switch (val.typ) {
                    case VNULL:
                        new_val = yyjson_mut_null(m_yyjson_doc.get());
                        break;
                    case VBOOL:
                        new_val = yyjson_mut_bool(m_yyjson_doc.get(), val.val == "1");
                        break;
                    case VNUM:
                        new_val = (yyjson_mut_val*)yyjson_mut_rawncpy(m_yyjson_doc.get(), val.val.data(), val.val.size());
                        break;
                    case VSTR:
                        new_val = (yyjson_mut_val*)yyjson_mut_strncpy(m_yyjson_doc.get(), val.val.data(), val.val.size());
                        break;
                    default:
                        // Shouldn't happen for non-container types
                        throw std::runtime_error("Unexpected type in pushKV");
                }
            }
            if (!new_val) {
                // Node creation failed, cannot add to object
                throw std::bad_alloc();
            }

            // Use yyjson_mut_obj_put which handles both new and existing keys
            // in a single operation: replaces the first matching key's value in place
            // (preserving key order), removes any further duplicates, or appends
            // at the end if the key is new.
            if (!yyjson_mut_obj_put((yyjson_mut_val*)m_yyjson_node, new_key, new_val)) {
                throw std::runtime_error("yyjson_mut_obj_put failed");
            }
            // Mark as not materialized so legacy representation will be rebuilt on demand
            m_materialized = false;
            return;
        }
    }
    // Fallback to legacy representation
    // This is used when:
    // 1. The target object doesn't have yyjson tree
    // 2. The value is a container without yyjson tree (after materializing if needed)
    if (m_yyjson_doc && m_yyjson_node && !m_materialized) {
        materialize();
    }
    if (m_materialized && findKey(key, idx)) {
        values[idx] = std::move(val);
    } else {
        keys.push_back(std::move(key));
        values.push_back(std::move(val));
    }
    // Clear yyjson state to ensure writeYyjson() uses legacy representation
    m_yyjson_doc.reset();
    m_yyjson_node = nullptr;
    m_materialized = true;  // Legacy representation is now up to date
}

/**
 * @brief Add a key-value pair to an object (end variant)
 *
 * Same as pushKV but takes ownership of the parameters.
 *
 * @param key The key to add/update
 * @param val The value to associate with the key
 */
void UniValue::pushKVEnd(std::string key, UniValue val) {
    checkType(VOBJ);

    bool use_legacy_path = false;

    if (m_yyjson_doc && m_yyjson_node) {
        // Check if we need to use legacy path (val is a container without yyjson tree)
        if (val.typ == VOBJ || val.typ == VARR) {
            if (!val.m_yyjson_doc || !val.m_yyjson_node) {
                // Container without yyjson tree - use legacy path
                use_legacy_path = true;
            }
        }

        if (!use_legacy_path) {
            // Optimized path: assume keys are unique, skip duplicate checking
            // Create key first, then value - if either fails, we throw
            yyjson_mut_val* new_key = (yyjson_mut_val*)yyjson_mut_strncpy(m_yyjson_doc.get(), key.data(), key.size());
            if (!new_key) {
                // Key allocation failed, cannot add the pair
                throw std::bad_alloc();
            }

            // Handle values with yyjson tree (both materialized and non-materialized containers)
            yyjson_mut_val* new_val = nullptr;

            if (val.m_yyjson_doc && val.m_yyjson_node) {
                // val has its own yyjson tree - use yyjson's optimized copy function for mutable values
                // This works for both materialized and non-materialized containers
                new_val = yyjson_mut_val_mut_copy(m_yyjson_doc.get(), val.m_yyjson_node);
                if (!new_val) {
                    // Copy failed, cannot add the pair
                    throw std::bad_alloc();
                }
            } else {
                // val is a primitive without its own document
                // Create yyjson node directly from val's value
                switch (val.typ) {
                    case VNULL:
                        new_val = yyjson_mut_null(m_yyjson_doc.get());
                        break;
                    case VBOOL:
                        new_val = yyjson_mut_bool(m_yyjson_doc.get(), val.val == "1");
                        break;
                    case VNUM:
                        new_val = (yyjson_mut_val*)yyjson_mut_rawncpy(m_yyjson_doc.get(), val.val.data(), val.val.size());
                        break;
                    case VSTR:
                        new_val = (yyjson_mut_val*)yyjson_mut_strncpy(m_yyjson_doc.get(), val.val.data(), val.val.size());
                        break;
                    default:
                        // Shouldn't happen for non-container types
                        throw std::runtime_error("Unexpected type in pushKVEnd");
                }
            }
            if (!new_val) {
                // Node creation failed, cannot add to object
                throw std::bad_alloc();
            }

            // Add to object - no duplicate key checking for better performance
            if (!yyjson_mut_obj_add((yyjson_mut_val*)m_yyjson_node, new_key, new_val)) {
                throw std::runtime_error("yyjson_mut_obj_add failed");
            }
            // Mark as not materialized so legacy representation will be rebuilt on demand
            m_materialized = false;
            return;
        } else {
            // use_legacy_path is true: container without yyjson tree
            // With incremental materialization, the tree and keys/values should already be in sync
            // No need to materialize here
        }
    }
    // Fallback to legacy representation
    // This is used when:
    // 1. The target object doesn't have yyjson tree
    // 2. The value is a container without yyjson tree (after materializing if needed)
    if (m_yyjson_doc && m_yyjson_node && !m_materialized) {
        materialize();
    }
    keys.push_back(std::move(key));
    values.push_back(std::move(val));
    // Clear yyjson state to ensure writeYyjson() uses legacy representation
    m_yyjson_doc.reset();
    m_yyjson_node = nullptr;
    m_materialized = true;  // Legacy representation is now up to date
}

/**
 * @brief Merge all key-value pairs from another object into this one
 *
 * Takes a snapshot of the source object's keys/values to handle any self-aliasing
 * or descendant aliasing cases safely, ensuring stable iteration even if pushKVEnd
 * mutates values.
 *
 * @param obj The object to merge from (must be an object)
 */
void UniValue::pushKVs(UniValue obj) {
    checkType(VOBJ);
    obj.checkType(VOBJ);

    // Materialize obj if needed
    if (!obj.m_materialized) {
        obj.materialize();
    }

    for (size_t i = 0; i < obj.keys.size(); ++i)
        pushKVEnd(std::move(obj.keys[i]), std::move(obj.values[i]));
}

/**
 * @brief Access an object value by key
 *
 * Searches for the key in the object and returns the corresponding value.
 * Returns NullUniValue if the key is not found or if this is not an object.
 * With eager materialization, containers are materialized immediately on construction.
 *
 * @param key The key to look up
 * @return Reference to the value, or NullUniValue if not found
 */
const UniValue& UniValue::operator[](const std::string& key) const {
    if (typ != VOBJ)
        return NullUniValue;

    // Check if we have yyjson tree that needs materialization
    if (m_yyjson_doc && m_yyjson_node) {
        if (!m_materialized) {
            materialize();
        }
        // Search for key in materialized cache
        for (size_t i = 0; i < keys.size(); ++i) {
            if (keys[i] == key) {
                return values[i];
            }
        }
        return NullUniValue;
    }

    // For already-materialized objects without yyjson tree
    size_t idx;
    if (findKey(key, idx)) {
        return values[idx];
    }
    return NullUniValue;
}

/**
 * @brief Access an array or object value by index
 *
 * Returns the value at the specified index.
 * For arrays: Returns the element at the index.
 * For objects: Returns the value at the index (indexing by insertion order).
 * Returns NullUniValue if the index is out of bounds or if this is not a container.
 * With eager materialization, containers are materialized immediately on construction.
 *
 * @param index The index to access
 * @return Reference to the value, or NullUniValue if index is invalid
 */
const UniValue& UniValue::operator[](size_t index) const {
    if (typ != VOBJ && typ != VARR)
        return NullUniValue;
    if (m_yyjson_doc && m_yyjson_node) {
        if (!m_materialized) {
            materialize();
        }
    }
    if (index < values.size()) {
        return values[index];
    }
    return NullUniValue;
}

/**
 * @brief Find a value in an object by key
 *
 * Searches for the key in the object and returns the corresponding value.
 * Returns NullUniValue if the key is not found.
 *
 * @param key The key to look up
 * @return Reference to the value, or NullUniValue if not found
 */
const UniValue& UniValue::find_value(std::string_view key) const {
    size_t idx;
    if (findKey(std::string(key), idx)) {
        return values[idx];
    }
    return NullUniValue;
}

/**
 * @brief Check if this object has the expected structure
 *
 * Verifies that the object contains all the keys specified in memberTypes
 * and that each key has the expected type.
 *
 * With eager materialization, containers are materialized immediately on construction.
 *
 * @param memberTypes Map of key names to expected types
 * @return true if the object matches the expected structure, false otherwise
 */
bool UniValue::checkObject(const std::map<std::string,UniValue::VType>& memberTypes) const {
    if (typ != VOBJ) return false;

    if (m_yyjson_doc && m_yyjson_node && !m_materialized) {
        materialize();
    }

    for (const auto& [key, expectedType] : memberTypes) {
        size_t idx;
        if (!findKey(key, idx)) {
            return false;
        }
        if (values[idx].typ != expectedType) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Append multiple values to an array
 *
 * Convenience method to append all values from a vector.
 */
void UniValue::push_backV(const std::vector<UniValue>& vec)
{
    checkType(VARR);
    // Always snapshot the input vector to avoid iterator invalidation from self-append
    // This handles cases like arr.push_backV(arr.values) and nested cases like arr.push_backV(arr[0].values)
    // The snapshot ensures stable iteration even if push_back causes reallocation of this->values
    std::vector<UniValue> snapshot = vec;
    for (auto& v : snapshot) {
        push_back(std::move(v));
    }
}
