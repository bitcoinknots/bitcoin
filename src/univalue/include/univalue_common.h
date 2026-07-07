// Copyright 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_UNIVALUE_INCLUDE_UNIVALUE_COMMON_H
#define BITCOIN_UNIVALUE_INCLUDE_UNIVALUE_COMMON_H

#include <string>

/**
 * @brief Checks if a string is a valid precheck for number parsing.
 *
 * Ensures the string is not empty, has no padding whitespace,
 * and has no embedded NUL characters.
 *
 * @param str The string to check
 * @return true if valid for number parsing, false otherwise
 */
bool ParsePrechecks(const std::string& str);

/**
 * @brief Parses a string as a double with validation.
 *
 * @param str The string to parse
 * @param out Output parameter for the parsed double
 * @return true if parsing succeeded, false otherwise
 */
bool ParseDouble(const std::string& str, double *out);

/**
 * @brief Escapes special characters in a string for JSON output.
 *
 * @param inS The string to escape
 * @return The escaped string
 */
std::string json_escape(const std::string& inS);

/**
 * @brief Adds indentation to a string for pretty-printing JSON.
 *
 * @param prettyIndent The number of spaces per indentation level
 * @param indentLevel The current indentation level
 * @param s The string to append indentation to
 */
void indentStr(unsigned int prettyIndent, unsigned int indentLevel, std::string& s);

#endif // BITCOIN_UNIVALUE_INCLUDE_UNIVALUE_COMMON_H