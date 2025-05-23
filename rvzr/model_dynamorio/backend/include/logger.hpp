///
/// File: The Logger centralizes the collection of debug traces from different components
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>

#include <dr_defines.h>
#include <dr_events.h>

#include "observables.hpp"
#include "types/debug_trace.hpp"
#include "types/file_buffer.hpp"

class Logger
{
  public:
    /// @brief Verbosity level of the logger
    enum log_level_t : uint8_t {
        LOG_NONE = 0,   // Disabled
        LOG_BASE = 1,   // Report PC, registers, memory operations and exceptions
        LOG_SPEC = 2,   // Also report rollbacks and checkpoints
        LOG_DISASM = 3, // Also disassemble each instruction and report module+offset of the PC
        LOG_MAX = 4,
    };

    Logger(const std::string &logs_path, log_level_t log_level);
    ~Logger();
    Logger(const Logger &) = delete;
    Logger(Logger &&) = delete;
    Logger &operator=(const Logger &) = delete;
    Logger &operator=(Logger &&) = delete;

    bool is_enabled() { return log_level > LOG_NONE; }

    void log_instruction(instr_obs_t instr, dr_mcontext_t *mc, bool in_speculation);
    void log_mem_access(bool is_write, void *address, uint64_t size);
    void log_exception(dr_siginfo_t *siginfo);

    void log_checkpoint(pc_t rollback_pc, uint64_t cur_window_size, size_t cur_store_log_size);
    void log_rollback(unsigned nesting, pc_t rollback_pc);
    void log_rollback_store(uint64_t addr, uint64_t val, size_t size);

  private:
    static constexpr const unsigned buf_sz = 8 * 1024;
    FileBackedBuf<debug_trace_entry_t, buf_sz> log;

    log_level_t log_level;
};
