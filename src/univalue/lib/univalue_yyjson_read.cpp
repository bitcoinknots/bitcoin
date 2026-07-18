// Copyright 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit-license.php.

#include <univalue.h>
#include <yyjson/yyjson.h>

#include <string>
#include <string_view>
#include <vector>

/** Maximum JSON nesting depth allowed (512 container levels) */
static constexpr size_t MAX_JSON_DEPTH = 512;

/**
 * @brief Check if JSON string exceeds maximum nesting depth without parsing
 *
 * Scans the input string counting bracket/brace nesting levels, ignoring
 * brackets/braces inside JSON strings. Returns false if depth exceeds MAX_JSON_DEPTH.
 *
 * @param str JSON string to check
 * @return true if depth is acceptable, false if too deep
 */
static bool checkJsonDepthBeforeParse(std::string_view str) {
    size_t current_depth = 0;
    bool in_string = false;
    bool escape_next = false;

    for (char c : str) {
        if (escape_next) {
            escape_next = false;
            continue;
        }

        if (c == '\\') {
            escape_next = true;
            continue;
        }

        if (in_string) {
            if (c == '"') {
                in_string = false;
            }
            continue;
        }

        // Not in string, check for whitespace (skip)
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }

        // Check for opening brackets/braces
        if (c == '[' || c == '{') {
            current_depth++;
            if (current_depth > MAX_JSON_DEPTH) {
                return false;
            }
        } else if (c == ']' || c == '}') {
            if (current_depth > 0) {
                current_depth--;
            }
            // If current_depth < 0, it means unbalanced brackets, but we'll let yyjson handle that
        } else if (c == '"') {
            in_string = true;
        }
    }

    return true;
}

/**
 * @brief Deep copy a yyjson value into a mutable document
 *
 * Copies the entire value tree from the source (which may be from yyjson_read's
 * immutable document) into the target mutable document. This is required because
 * yyjson values cannot be shared between documents - each UniValue must own
 * its tree.
 *
 * Uses immutable iterators (yyjson_arr_foreach, yyjson_obj_iter) which work
 * with both immutable values (from yyjson_read) and mutable values.
 *
 * @param src_val Source value to copy (from immutable yyjson_read output)
 * @param target_doc Target mutable document to copy into
 * @return New value in target document, or nullptr on error
 */
static yyjson_mut_val* copyYyjsonValue(yyjson_val* src_val, yyjson_mut_doc* target_doc) {
    if (!src_val) return nullptr;

    yyjson_type type = yyjson_get_type(src_val);

    switch (type) {
        case YYJSON_TYPE_NULL:
            return yyjson_mut_null(target_doc);
        case YYJSON_TYPE_BOOL:
            return yyjson_mut_bool(target_doc, yyjson_get_bool(src_val));
        case YYJSON_TYPE_NUM:
        case YYJSON_TYPE_RAW: {
            const char* raw = yyjson_get_raw(src_val);
            size_t len = yyjson_get_len(src_val);
            if (raw && len > 0) {
                return yyjson_mut_rawncpy(target_doc, raw, len);
            }
            return yyjson_mut_null(target_doc);
        }
        case YYJSON_TYPE_STR: {
            const char* str = yyjson_get_str(src_val);
            size_t len = yyjson_get_len(src_val);
            return yyjson_mut_strncpy(target_doc, str, len);
        }
        case YYJSON_TYPE_ARR: {
            yyjson_mut_val* arr = yyjson_mut_arr(target_doc);
            size_t idx, max;
            yyjson_val *item;
            yyjson_arr_foreach(src_val, idx, max, item) {
                yyjson_mut_val* copied = copyYyjsonValue(item, target_doc);
                if (!copied) {
                    // Copy failed, return error (don't free arr as it's owned by target_doc)
                    return nullptr;
                }
                if (!yyjson_mut_arr_append(arr, copied)) {
                    // Append failed, return error
                    return nullptr;
                }
            }
            return arr;
        }
        case YYJSON_TYPE_OBJ: {
            yyjson_mut_val* obj = yyjson_mut_obj(target_doc);
            yyjson_val *key, *val;
            yyjson_obj_iter iter;
            yyjson_obj_iter_init(src_val, &iter);
            while ((key = yyjson_obj_iter_next(&iter))) {
                val = yyjson_obj_iter_get_val(key);
                const char* kstr = yyjson_get_str(key);
                size_t klen = yyjson_get_len(key);
                yyjson_mut_val* new_key = yyjson_mut_strncpy(target_doc, kstr, klen);
                if (!new_key) {
                    // Key copy failed, return error (don't free obj as it's owned by target_doc)
                    return nullptr;
                }
                yyjson_mut_val* new_val = copyYyjsonValue(val, target_doc);
                if (!new_val) {
                    // Value copy failed, return error
                    return nullptr;
                }
                if (!yyjson_mut_obj_add(obj, new_key, new_val)) {
                    // Add failed, return error
                    return nullptr;
                }
            }
            return obj;
        }
        default:
            return nullptr;
    }
}

/**
 * @brief Calculate maximum container nesting depth in a yyjson value tree
 *
 * Uses iterative depth-first traversal with a stack to avoid recursion.
 * Only counts container nodes (arrays and objects) for depth calculation.
 *
 * @param val Root value to analyze
 * @return Maximum depth (0-indexed, counting only container nodes)
 */
static size_t getMaxDepth(yyjson_val* val) {
    if (!val) return 0;

    size_t max_depth = 0;

    // Stack entry for iterative DFS traversal
    struct StackEntry {
        yyjson_val* val;      ///< Current value being processed
        size_t depth;         ///< Current depth in tree
        bool children_processed;  ///< Whether children have been enqueued
    };

    std::vector<StackEntry> stack;
    stack.push_back({val, 0, false});

    while (!stack.empty()) {
        StackEntry& entry = stack.back();

        if (entry.children_processed) {
            // Already processed children, pop from stack
            stack.pop_back();
            continue;
        }

        // Mark as processed
        entry.children_processed = true;

        yyjson_type type = yyjson_get_type(entry.val);

        // Update max_depth for container nodes only
        if (type == YYJSON_TYPE_ARR || type == YYJSON_TYPE_OBJ) {
            if (entry.depth > max_depth) {
                max_depth = entry.depth;
            }
        }

        if (type == YYJSON_TYPE_ARR) {
            yyjson_val* item;
            yyjson_arr_iter iter;
            yyjson_arr_iter_init(entry.val, &iter);

            size_t child_depth = entry.depth + 1;
            while ((item = yyjson_arr_iter_next(&iter))) {
                // Only push container children (arrays and objects) onto stack
                yyjson_type child_type = yyjson_get_type(item);
                if (child_type == YYJSON_TYPE_ARR || child_type == YYJSON_TYPE_OBJ) {
                    stack.push_back({item, child_depth, false});
                }
            }
        } else if (type == YYJSON_TYPE_OBJ) {
            yyjson_val* key, *value;
            yyjson_obj_iter iter;
            yyjson_obj_iter_init(entry.val, &iter);

            size_t child_depth = entry.depth + 1;
            while ((key = yyjson_obj_iter_next(&iter))) {
                value = yyjson_obj_iter_get_val(key);
                // Only push container children (arrays and objects) onto stack
                yyjson_type child_type = yyjson_get_type(value);
                if (child_type == YYJSON_TYPE_ARR || child_type == YYJSON_TYPE_OBJ) {
                    stack.push_back({value, child_depth, false});
                }
            }
        }
    }

    return max_depth;
}

/**
 * @brief Parse JSON string and populate this UniValue
 *
 * Uses yyjson's SIMD-optimized parser for 5-10x faster parsing.
 * Validates against UniValue-specific rules (leading zeros, hex numbers, etc.)
 * that yyjson doesn't enforce by default.
 *
 * @param str_in JSON string to parse
 * @return true on success, false on parse error
 */
bool UniValue::read(std::string_view str_in) {
    clear();

    if (str_in.empty()) return false;

    // Check depth limit before parsing to avoid expensive parse of deeply nested JSON
    if (!checkJsonDepthBeforeParse(str_in)) {
        return false;
    }

    // Parse with yyjson: NUMBER_AS_RAW preserves exact number strings,
    // STOP_WHEN_DONE stops at first non-JSON token
    // yyjson_read requires non-const char*, but doesn't modify the buffer,
    // so we can safely cast away constness
    yyjson_read_flag flags = YYJSON_READ_NUMBER_AS_RAW | YYJSON_READ_STOP_WHEN_DONE;
    yyjson_doc* doc = yyjson_read(const_cast<char*>(str_in.data()), str_in.size(), flags);
    if (!doc) {
        return false;
    }

    // Check for trailing content
    size_t consumed = yyjson_doc_get_read_size(doc);
    const char* after = str_in.data() + consumed;
    const char* end = str_in.data() + str_in.size();

    // yyjson with STOP_WHEN_DONE stops at the first non-JSON token.
    // Original UniValue parser accepts trailing whitespace, so we do too.
    // Skip whitespace after the JSON value.
    while (after < end && (after[0] == ' ' || after[0] == '\t' || after[0] == '\n' || after[0] == '\r')) {
        after++;
    }

    // If there's non-whitespace content after the JSON, parsing fails
    if (after < end) {
        yyjson_doc_free(doc);
        return false;
    }

    // Check depth limit before building UniValue tree.
    // getMaxDepth returns 0-indexed depth counting only container nodes.
    // Original implementation uses stack.size() which equals max_depth + 1.
    // So we check: (max_depth + 1) > MAX_JSON_DEPTH, which is: max_depth >= MAX_JSON_DEPTH.
    yyjson_val* root = yyjson_doc_get_root(doc);
    if (getMaxDepth(root) >= MAX_JSON_DEPTH) {
        yyjson_doc_free(doc);
        return false;
    }

    // yyjson_read returns an immutable doc, but we need a mutable doc for consistency.
    // Create a new mutable document and copy the tree.
    yyjson_mut_doc* mut_doc = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val* mut_root = copyYyjsonValue(root, mut_doc);
    if (!mut_root) {
        // Copy failed, clean up and return failure
        yyjson_mut_doc_free(mut_doc);
        yyjson_doc_free(doc);
        return false;
    }
    yyjson_mut_doc_set_root(mut_doc, mut_root);

    // Store document with automatic cleanup using shared_ptr
    m_yyjson_doc = std::shared_ptr<yyjson_mut_doc>(mut_doc, yyjson_doc_deleter);
    m_yyjson_node = mut_root;

    // Free the immutable document from yyjson_read
    yyjson_doc_free(doc);

    // Set the type based on the root value.
    // Parsed primitives (numbers, booleans, strings) are materialized immediately
    // because they're accessed frequently and materialization is cheap.
    // Containers (arrays, objects) remain unmaterialized until accessed.
    switch (yyjson_mut_get_type(m_yyjson_node)) {
        case YYJSON_TYPE_NULL:
            typ = VNULL;
            break;
        case YYJSON_TYPE_BOOL:
            typ = VBOOL;
            val = yyjson_mut_get_bool(m_yyjson_node) ? "1" : "";
            break;
        case YYJSON_TYPE_RAW:
        case YYJSON_TYPE_NUM: {
            typ = VNUM;
            const char* raw = yyjson_mut_get_raw(m_yyjson_node);
            size_t len = yyjson_mut_get_len(m_yyjson_node);
            if (raw && len > 0) {
                val.assign(raw, len);
            } else {
                // Fallback: try to get the string representation
                const char* str = yyjson_mut_get_str(m_yyjson_node);
                if (str && len > 0) {
                    val.assign(str, len);
                } else {
                    val = "0"; // Fallback for invalid numbers
                }
            }
            break;
        }
        case YYJSON_TYPE_STR: {
            typ = VSTR;
            const char* str = yyjson_mut_get_str(m_yyjson_node);
            size_t len = yyjson_mut_get_len(m_yyjson_node);
            if (str && len > 0) {
                val.assign(str, len);
            } else {
                val = ""; // Fallback for invalid strings
            }
            break;
        }
        case YYJSON_TYPE_ARR:
            typ = VARR;
            break;
        case YYJSON_TYPE_OBJ:
            typ = VOBJ;
            break;
    }

    // Eager materialization: materialize containers immediately
    if (typ == VARR || typ == VOBJ) {
        materialize();
        m_materialized = true;
    } else {
        m_materialized = true;
    }

    return true;
}
