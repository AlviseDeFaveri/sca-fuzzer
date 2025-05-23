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
TracerABC::TracerABC(const std::string &out_path, Logger &logger) : logger(logger)
{
    trace.open(out_path);
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

    // Flush the trace buffer
    dr_printf("Done Tracing!\n");
    trace.clear();

    // Tell the user where to find the trace(s)
    dr_printf("Trace saved to %s\n", trace.get_filename().c_str());

    // Reset tracing flags
    tracing_on = false;
    tracing_finalized = true;
}

void TracerABC::observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, bool in_speculation)
{
    logger.log_instruction(instr, mc, in_speculation);
    // The rest of the functionality - if any - is implemented by subclasses
}

void TracerABC::observe_mem_access(bool is_write, void *address, uint64_t size)
{
    logger.log_mem_access(is_write, address, size);
    // The rest of the functionality - if any - is implemented by subclasses
}
