///
/// File: Abstract Model TracerABC
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <dr_ir_instr.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>

#include <drmgr.h>
#include <drreg.h>
#include <drvector.h>

#include "observables.hpp"
#include "tracer_abc.hpp"
#include "util.hpp"

using std::string;

// =================================================================================================
// Local helper functions for allocating and freeing memory
// =================================================================================================

/// @brief Print function for the trace type
static constexpr const char *to_string(const trace_entry_type_t &type)
{
    switch (type) {
    case trace_entry_type_t::ENTRY_EOT:
        return "EOT";
    case trace_entry_type_t::ENTRY_PC:
        return "PC";
    case trace_entry_type_t::ENTRY_READ:
        return "READ";
    case trace_entry_type_t::ENTRY_WRITE:
        return "WRITE";
    case trace_entry_type_t::ENTRY_REG_DUMP_ARCH:
        return "ARCH";
    case trace_entry_type_t::ENTRY_REG_DUMP_SPEC:
        return "SPEC";
    default:
        return "UNKNOWN";
    }
}

/// @brief Print function for normal traces
static void dump(const trace_entry_t &entry, const file_t &where)
{
    dr_fprintf(where, "[%s] addr: %lx  (sz: %u)\n", to_string(entry.type), entry.addr, entry.size);
}

/// @brief Print function for debug traces
static void dump(const dbg_trace_entry_t &entry, const file_t &where)
{
    using type = trace_entry_type_t;
    if (entry.type == trace_entry_type_t::ENTRY_READ or
        entry.type == trace_entry_type_t::ENTRY_WRITE) {
        dr_fprintf(where, "[%s] addr: %lx  val: %lx (sz: %u)\n", to_string(entry.type),
                   entry.mem.address, entry.mem.value, entry.mem.size);
    } else {
        dr_fprintf(
            where,
            "[%s] pc: %lx  (rax: 0x%lx rbx: 0x%lx rcx: 0x%lx rdx: 0x%lx rsi: 0x%lx rdi: 0x%lx)\n",
            to_string(entry.type), entry.regs.pc, entry.regs.xax, entry.regs.xbx, entry.regs.xcx,
            entry.regs.xdx, entry.regs.xsi, entry.regs.xdi);
    }
}

/// @brief Parse traces of type T from a file and dump them to the provided output
/// @tparam T File is expected to contain traces of this typ
/// @param filename File to read traces from
/// @param where Where to print the parsed entries
template <typename T> static void dump_from_file(const std::string &filename, const file_t &where)
{
    std::fstream file(filename, std::ios::in | std::ios::binary);
    T entry{};
    while (not file.eof()) {
        file.read((char *)&entry, sizeof(T));
        dump(entry, where);
    }
}

// =================================================================================================
// Constructors and Destructors
// =================================================================================================
TracerABC::TracerABC(const std::string &out_path, bool print_output_, const std::string &dbg_path,
                     bool print_dbg_, bool enable_dbg_trace_)
    : print_output(print_output_), print_dbg(print_dbg_), enable_dbg_trace(enable_dbg_trace_)
{
    trace.open(out_path);
    if (enable_dbg_trace)
        dbg_trace.open(dbg_path);
}

// =================================================================================================
// Public Methods
// =================================================================================================
void TracerABC::tracing_start(void * /*wrapctx*/, DR_PARAM_OUT void ** /*user_data*/)
{
    tracing_on = true;
    tracing_finalized = false;
}

void TracerABC::tracing_finalize(void * /*wrapctx*/, DR_PARAM_OUT void * /*user_data*/)
{
    if (tracing_finalized) {
        return;
    }
    dr_printf("Done Tracing!\n");

    // Reset the trace buffers
    trace.clear();
    dbg_trace.clear();

    // Tell the user where to find the trace(s)
    dr_printf("Trace saved to %s\n", trace.get_filename().c_str());
    if (enable_dbg_trace)
        dr_printf("Debug trace saved to %s\n", dbg_trace.get_filename().c_str());

    // Optionally, print a string representation of the traces
    if (print_output)
        dump_from_file<trace_entry_t>(trace.get_filename(), STDOUT);
    if (enable_dbg_trace and print_dbg)
        dump_from_file<dbg_trace_entry_t>(dbg_trace.get_filename(), STDERR);

    // Reset the tracing flag
    tracing_on = false;
    tracing_finalized = true;
}

void TracerABC::observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, bool in_speculation)
{
    // Nothing to do if tracing is off
    if (not tracing_on) {
        return;
    }

    // In debug mode, store the register values and PC on the debug trace buffer
    if (enable_dbg_trace) {
        const dbg_trace_entry_t entry = {.type = in_speculation
                                                     ? trace_entry_type_t::ENTRY_REG_DUMP_SPEC
                                                     : trace_entry_type_t::ENTRY_REG_DUMP_ARCH,
                                         .regs{
                                             .xax = mc->xax,
                                             .xbx = mc->xbx,
                                             .xcx = mc->xcx,
                                             .xdx = mc->xdx,
                                             .xsi = mc->xsi,
                                             .xdi = mc->xdi,
                                             .pc = instr.pc,
                                         }};
        dbg_trace.push_back(entry);
    }

    // The rest of the functionality - if any - is implemented by subclasses
}

void TracerABC::observe_mem_access(bool is_write, void *address, uint64_t size)
{
    if (enable_dbg_trace) {
        uint64_t val = 0;
        size_t w_size = 0;
        bool success = dr_safe_read(address, sizeof(uint64_t), &val, &w_size);

        const dbg_trace_entry_t entry = {.type = is_write ? trace_entry_type_t::ENTRY_WRITE
                                                          : trace_entry_type_t::ENTRY_READ,
                                         .mem{
                                             .address = (uint64_t)address,
                                             .value = val,
                                             .size = size,
                                         }};
        dbg_trace.push_back(entry);
    }
}
