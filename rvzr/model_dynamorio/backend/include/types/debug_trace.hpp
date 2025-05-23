///
/// File: Debug trace entries that are logged by the logger
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "observables.hpp"

/// @brief Type of entry (single element of a trace)
enum class debug_trace_entry_type_t : uint8_t {
    ENTRY_EOT = 0, // end of trace
    ENTRY_READ = 1,
    ENTRY_WRITE = 2,
    ENTRY_REG_DUMP_ARCH = 3,
    ENTRY_REG_DUMP_SPEC = 4,
    ENTRY_LOC = 5,
    ENTRY_EXCEPTION = 6,
    ENTRY_CHECKPOINT = 7,
    ENTRY_ROLLBACK = 8,
    ENTRY_ROLLBACK_STORE = 9,
};

struct debug_trace_entry_t {
    // What does this entry contain
    debug_trace_entry_type_t type;

    // Union of all possible entry types
    union {
        // ENTRY_REG_DUMP
        struct {
            uint64_t xax;
            uint64_t xbx;
            uint64_t xcx;
            uint64_t xdx;
            uint64_t xsi;
            uint64_t xdi;
            pc_t pc;
        } regs;
        // ENTRY_MEM (read or write)
        struct {
            uint64_t address;
            uint64_t value;
            uint64_t size;
        } mem;
        // ENTRY_LOC (module name and offset, for disassembly)
        struct {
            uint64_t offset;
            std::array<char, 48> module_name; // NOLINT
        } loc;
        // ENTRY_EXCEPTION
        struct {
            int signal;
            uint64_t address;
        } xcpt;
        // ENTRY_CHECKPOINT
        struct {
            pc_t rollback_pc;
            uint64_t cur_window_size;
            size_t cur_store_log_size;
        } checkpoint;
        // ENTRY_ROLLBACK
        struct {
            unsigned nesting;
            pc_t rollback_pc;
        } rollback;
        // ENTRY_ROLLBACK_STORE
        struct {
            uint64_t addr;
            uint64_t val;
            size_t size;
        } rollback_store;
    };

    /// @brief Declare a marker to identify traces of this type
    static constexpr char marker = 'D';
};
