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

static void dump(const trace_entry_t &entry)
{
    dr_fprintf(STDOUT, "[%s] addr: %lx  (sz: %d)\n", to_string(entry.type), entry.addr, entry.size);
}

static void dump(const dbg_trace_entry_t &entry)
{
    using type = trace_entry_type_t;
    if (entry.type == trace_entry_type_t::ENTRY_READ or
        entry.type == trace_entry_type_t::ENTRY_WRITE) {
        dr_fprintf(STDOUT, "[%s] addr: %lx  (sz: %d)\n", to_string(entry.type), entry.pc,
                   entry.xax);
    } else {
        dr_fprintf(
            STDOUT,
            "[%s] pc: %lx  (xax: 0x%lx xbx: 0x%lx xcx: 0x%lx xdx: 0x%lx xsi: 0x%lx xdi: 0x%lx)\n",
            to_string(entry.type), entry.pc, entry.xax, entry.xbx, entry.xcx, entry.xdx, entry.xsi,
            entry.xdi);
    }
}

template <typename T> static void dump_from_file(const std::string &filename)
{
    std::fstream file(filename, std::ios::in | std::ios::binary);
    T entry{};
    while (not file.eof()) {
        file.read((char *)&entry, sizeof(T));
        dump(entry);
    }
}

// =================================================================================================
// Constructors and Destructors
// =================================================================================================
TracerABC::TracerABC(const std::string &out_path, bool print_output_, const std::string &dbg_path)
    : print_output(print_output_)
{
    trace.open(out_path);

    if (dbg_path != "") {
        enable_dbg_trace = true;
        dbg_trace.open(dbg_path);
    }
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
    if (enable_dbg_trace) {
        dr_printf("Debug trace saved to %s\n", dbg_trace.get_filename().c_str());
    }
    dr_printf("Trace saved to %s\n", trace.get_filename().c_str());

    // Optionally, print a string representation of the traces to stdout
    if (print_output) {
        if (enable_dbg_trace) {
            dump_from_file<dbg_trace_entry_t>(dbg_trace.get_filename());
        } else {
            dump_from_file<trace_entry_t>(trace.get_filename());
        }
    }

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
        const dbg_trace_entry_t entry = {
            .type = in_speculation ? trace_entry_type_t::ENTRY_REG_DUMP_SPEC
                                   : trace_entry_type_t::ENTRY_REG_DUMP_ARCH,
            .xax = mc->xax,
            .xbx = mc->xbx,
            .xcx = mc->xcx,
            .xdx = mc->xdx,
            .xsi = mc->xsi,
            .xdi = mc->xdi,
            .pc = instr.pc,
        };
        dbg_trace.push_back(entry);
    }

    // The rest of the functionality - if any - is implemented by subclasses
}

void TracerABC::observe_mem_access(bool is_write, void *address, uint64_t size) {}
