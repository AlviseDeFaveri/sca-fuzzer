///
/// File: Header for the Tracer abstract base class
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <drvector.h>

#include "observables.hpp"

// =================================================================================================
// Constants and Types
// =================================================================================================
enum class trace_entry_type_t : uint8_t {
    ENTRY_EOT = 0, // end of trace
    ENTRY_PC = 1,
    ENTRY_READ = 2,
    ENTRY_WRITE = 3,
    ENTRY_REG_DUMP_ARCH = 4,
    ENTRY_REG_DUMP_SPEC = 5
};

struct trace_entry_t {
    pc_t addr;     // pc for instructions; address for memory accesses
    uint32_t size; // instruction size for instructions; memory access size for memory accesses
    trace_entry_type_t type; // see trace_entry_type_t
};

struct dbg_trace_entry_t {
    trace_entry_type_t type; // always ENTRY_REG_DUMP

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
    };
};
#include "types/file_buffer.hpp"

// =================================================================================================
// Class Definition
// =================================================================================================

/// @brief Abstract base class for all tracers
class TracerABC
{
  public:
    TracerABC(const std::string &out_path, bool print_output_, const std::string &dbg_path,
              bool print_dbg_, bool enable_dbg_trace_);
    virtual ~TracerABC() = default;
    TracerABC(const TracerABC &) = delete;
    TracerABC &operator=(const TracerABC &) = delete;
    TracerABC(TracerABC &&) = delete;
    TracerABC &operator=(TracerABC &&) = delete;

    /// Buffer containing collected trace entries
    static constexpr const unsigned buf_sz = 8 * 1024;
    FileBackedBuf<trace_entry_t, buf_sz> trace;

    /// Buffer containing collected debug trace entries
    FileBackedBuf<dbg_trace_entry_t, buf_sz> dbg_trace;

    // ---------------------------------------------------------------------------------------------
    // Public Methods

    /// @brief Starts the tracing process for a wrapped functions
    /// @param wrapctx The machine context of the wrapped function
    /// @param user_data Unused
    /// @return void
    virtual void tracing_start(void *, DR_PARAM_OUT void **);

    /// @brief Finalizes the tracing process for a wrapped function
    /// @param wrapctx The machine context of the wrapped function
    /// @param user_data Unused
    /// @return void
    virtual void tracing_finalize(void *, DR_PARAM_OUT void *);

    /// @brief Record per-instruction information on the trace (e.g., its address) as defined
    ///        by the target contract.
    ///        Note: some subclasses may not record any information as the corresponding
    ///        contract may not require it. For such subclasses, this method should be a no-op.
    /// @param instr The instruction being executed
    /// @param mc The machine context of the instruction
    /// @param in_speculation Is the current instruction speculative
    /// @return void
    virtual void observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, bool in_speculation);

    /// @brief Record per-memory access information on the trace (e.g., its address and value)
    ///        as defined by the target contract.
    ///        Note: some subclasses may not record any information as the corresponding
    ///        contract may not require it. For such subclasses, this method should be a no-op.
    /// @param is_write The type of the memory access (read or write)
    /// @param address The address of the memory access
    /// @param size The size of the memory access
    /// @return void
    virtual void observe_mem_access(bool is_write, void *address, uint64_t size);

  protected:
    // ---------------------------------------------------------------------------------------------
    // Protected Fields

    /// @param If true, the tracer will print all entries to STDOUT at the end of a run
    bool print_output = false;

    /// @param If true, the tracer will print all debug entries to STDERR at the end of a run
    bool print_dbg = false;

    /// @param If true, the tracer will collect data for Revizor's model debug mode
    bool enable_dbg_trace = false;

    /// @param If true, the tracer will instrument the instructions in the traced function
    bool tracing_on = false;

    /// @param If true, tracing has been finalized; no more tracing is allowed
    bool tracing_finalized = false;
};
