///
/// File: Implementation factory functions defined in factory.hpp
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cassert>
#include <sstream>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <dr_ir_instr.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>

#include "logger.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================

static std::pair<std::string, size_t> get_module(uint64_t pc)
{
    module_data_t *mod = dr_lookup_module((byte *)pc);
    if (mod != nullptr) {
        // Calculate the offset from the beginning of the module.
        auto offset = (size_t)(pc - (pc_t)mod->start);

        // Get the name of the current module.
        std::string module_name(mod->full_path);

        // If the name is too long, get only the last part.
        const size_t max_path_size = sizeof(debug_trace_entry_t::loc.module_name) - 1;
        if (module_name.size() > max_path_size)
            module_name = module_name.substr(module_name.size() - max_path_size - 1, max_path_size);

        dr_free_module_data(mod);
        return {module_name, offset};
    }

    return {"Unknown Module", 0};
}

// =================================================================================================
// Constructors and Destructors
// =================================================================================================

Logger::Logger(const std::string &logs_path, log_level_t log_level, bool print)
    : log_level(log_level), log(print)
{
    if (is_enabled())
        log.open(logs_path);
}

Logger::~Logger()
{
    log.clear();
    if (is_enabled()) {
        dr_printf("Debug trace saved to %s\n", log.get_filename().c_str());
    }
}

// =================================================================================================
// Logging functions
// =================================================================================================

void Logger::log_instruction(instr_obs_t instr, dr_mcontext_t *mc, bool in_speculation)
{
    if (is_enabled()) {
        log.push_back({.type = in_speculation ? debug_trace_entry_type_t::ENTRY_REG_DUMP_SPEC
                                              : debug_trace_entry_type_t::ENTRY_REG_DUMP_ARCH,
                       .regs{
                           .xax = mc->xax,
                           .xbx = mc->xbx,
                           .xcx = mc->xcx,
                           .xdx = mc->xdx,
                           .xsi = mc->xsi,
                           .xdi = mc->xdi,
                           .pc = instr.pc,
                       }});

        // Optionally, output each instruction's module and location to aid disassembly
        if (log_level >= LOG_DISASM) {
            // Recover module name from DynamoRIO
            const auto &[module_name, offset] = get_module(instr.pc);
            assert(module_name.size() <= sizeof(debug_trace_entry_t::loc.module_name));

            debug_trace_entry_t loc_entry = {.type = debug_trace_entry_type_t::ENTRY_LOC,
                                             .loc{
                                                 .offset = offset,
                                                 .module_name = {'\0'},
                                             }};
            // Move the recovered module name into the corresponding member of the entry
            std::move(module_name.begin(), module_name.end(), loc_entry.loc.module_name.begin());
            log.push_back(loc_entry);
        }
    }
}

void Logger::log_mem_access(bool is_write, void *address, uint64_t size)
{
    if (is_enabled()) {
        uint64_t val = 0;
        size_t w_size = 0;
        bool success = dr_safe_read(address, sizeof(uint64_t), &val, &w_size);

        log.push_back({.type = is_write ? debug_trace_entry_type_t::ENTRY_WRITE
                                        : debug_trace_entry_type_t::ENTRY_READ,
                       .mem{
                           .address = (uint64_t)address,
                           .value = val,
                           .size = size,
                       }});
    }
}

void Logger::log_exception(dr_siginfo_t *siginfo)
{
    if (is_enabled()) {
        log.push_back({.type = debug_trace_entry_type_t::ENTRY_EXCEPTION,
                       .xcpt{
                           .signal = siginfo->sig,
                           .address = (uint64_t)siginfo->access_address,
                       }});
    }
}

void Logger::log_checkpoint(pc_t rollback_pc, uint64_t cur_window_size, size_t cur_store_log_size)
{
    if (log_level < LOG_SPEC)
        return;

    log.push_back({.type = debug_trace_entry_type_t::ENTRY_CHECKPOINT,
                   .checkpoint{
                       .rollback_pc = rollback_pc,
                       .cur_window_size = cur_window_size,
                       .cur_store_log_size = cur_store_log_size,
                   }});
}

void Logger::log_rollback(unsigned nesting, pc_t rollback_pc)
{
    if (log_level < LOG_SPEC)
        return;

    log.push_back({.type = debug_trace_entry_type_t::ENTRY_ROLLBACK,
                   .rollback{
                       .nesting = nesting,
                       .rollback_pc = rollback_pc,
                   }});
}

void Logger::log_rollback_store(uint64_t addr, uint64_t val, size_t size)
{
    if (log_level < LOG_SPEC)
        return;

    log.push_back({.type = debug_trace_entry_type_t::ENTRY_ROLLBACK_STORE,
                   .rollback_store{
                       .addr = addr,
                       .val = val,
                       .size = size,
                   }});
}
