// Copyright 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

#include <univalue.h>
#include <univalue_common.h>
#include <yyjson/yyjson.h>

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

/**
 * @brief Get the keys of this object
 *
 * Triggers materialization if the object hasn't been materialized yet.
 * Note: Materializes on-demand using mutable cache members when WITH_YYJSON=ON.
 * This is safe because materialization only populates the keys/values cache
 * and doesn't change the logical state of the object.
 *
 * @return Reference to the vector of object keys
 * @throws std::runtime_error if this is not an object
 */
const std::vector<std::string>& UniValue::getKeys() const {
    checkType(VOBJ);
    materializeIfNeeded();

    return keys;
}

/**
 * @brief Get the values of this object or array
 *
 * Triggers materialization if the container hasn't been materialized yet.
 * Note: Materializes on-demand using mutable cache members when WITH_YYJSON=ON.
 * This is safe because materialization only populates the keys/values cache
 * and doesn't change the logical state of the object.
 *
 * @return Reference to the vector of values
 * @throws std::runtime_error if this is not an object or array
 */
const std::vector<UniValue>& UniValue::getValues() const {
    if (typ != VOBJ && typ != VARR)
        throw std::runtime_error("JSON value is not an object or array as expected");
    materializeIfNeeded();
    return values;
}

/**
 * @brief Get the boolean value
 *
 * Triggers materialization if the value hasn't been materialized yet.
 *
 * @return true if the value is "1", false if "" (empty string)
 * @throws std::runtime_error if this is not a boolean
 */
bool UniValue::get_bool() const {
    checkType(VBOOL);
    materializeIfNeeded();
    return val == "1";
}

/**
 * @brief Get the string value
 *
 * Triggers materialization if the value hasn't been materialized yet.
 *
 * @return Reference to the string value
 * @throws std::runtime_error if this is not a string
 */
const std::string& UniValue::get_str() const {
    checkType(VSTR);
    materializeIfNeeded();
    return val;
}

/**
 * @brief Get the floating-point value
 *
 * Triggers materialization if the value hasn't been materialized yet.
 * Parses the string representation using ParseDouble for strict, locale-independent parsing.
 *
 * @return The double-precision floating-point value
 * @throws std::runtime_error if this is not a number or out of range
 */
double UniValue::get_real() const {
    checkType(VNUM);
    materializeIfNeeded();
    double result;
    if (!ParseDouble(val, &result)) {
        throw std::runtime_error("JSON number out of range for double");
    }
    return result;
}

/**
 * @brief Get a reference to this UniValue as an object
 *
 * Triggers materialization if the object hasn't been materialized yet.
 *
 * @return Reference to this UniValue
 * @throws std::runtime_error if this is not an object
 */
const UniValue& UniValue::get_obj() const {
    checkType(VOBJ);
    materializeIfNeeded();
    return *this;
}

/**
 * @brief Get a reference to this UniValue as an array
 *
 * Triggers materialization if the array hasn't been materialized yet.
 *
 * @return Reference to this UniValue
 * @throws std::runtime_error if this is not an array
 */
const UniValue& UniValue::get_array() const {
    checkType(VARR);
    materializeIfNeeded();
    return *this;
}

/**
 * @brief Populate a map with all key-value pairs from this object
 *
 * Triggers materialization if the object hasn't been materialized yet.
 *
 * @param kv Output map to populate
 */
void UniValue::getObjMap(std::map<std::string,UniValue>& kv) const {
    if (typ != VOBJ) return;

    materializeIfNeeded();

    for (size_t i = 0; i < keys.size(); ++i) {
        kv[keys[i]] = values[i];
    }
}
