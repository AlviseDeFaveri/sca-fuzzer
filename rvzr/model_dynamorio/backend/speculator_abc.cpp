///
/// File: Abstract interface to be implemented by all speculators.
///       For implementations of concrete speculators, see speculators/*.cpp files.
///
///      A speculator is a component that modifies the execution process of a test case when it
///      runs on the contract model (e.g., it can emulate misprediction of branches).
///      As such, speculators implement execution clauses of different contracts.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <dr_api.h>

#include <dr_defines.h>
#include <dr_ir_opcodes_x86.h>
#include <dr_tools.h>

#include "dr_ir_opnd.h"
#include "dr_os_utils.h"
#include "observables.hpp"
#include "speculator_abc.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================

// See Intel Manual https://cdrdv2.intel.com/v1/dl/getContent/671200
// chapter 10.3 - Serializing Instructions.
static constexpr const std::array<uint64_t, 35> serializing_opcodes = {
    // Non-privileged memory-ordering instructions
    OP_lfence, OP_mfence, OP_sfence,
    // Privileged serializing instructions
    OP_invd, OP_invept, OP_invlpg, OP_invvpid, OP_lgdt, OP_lidt, OP_lldt, OP_ltr,
    // TODO: add MOV CR (except CR8)
    OP_wbinvd, OP_wrmsr,
    // Non-privileged serializing instructions
    OP_cpuid, OP_iret, OP_rsm, OP_serialize,
    // NOTE: syscalls are not instrumented by Dynamorio, this makes sure that speculation is aborted
    // on speculative syscall instructions.
    OP_syscall,
    // TSX/RTM instructions (not tracked by DynamoRIO).
    OP_xbegin, OP_xabort, OP_xend, OP_xtest,
    // XSAVE no buono
    OP_xsave32, OP_xsave64, OP_xsavec32, OP_xsavec64, OP_xsaves32, OP_xsaves64, OP_xsaveopt32,
    OP_xsaveopt64,

    OP_xrstor32, OP_xrstor64, OP_xrstors32, OP_xrstors64,

    // Other special instructions
    OP_hlt};

static bool is_speculation_barrier(const uint64_t opcode)
{
    return std::any_of(serializing_opcodes.begin(), serializing_opcodes.end(),
                       [&opcode](const uint64_t barrier) { return opcode == barrier; });
}

// =================================================================================================
// Public Methods
// =================================================================================================
void SpeculatorABC::enable() { enabled = true; }

void SpeculatorABC::disable() { enabled = false; }

bool SpeculatorABC::skip_speculation() const
{
    if (not enabled)
        return true;
    if (nesting >= max_nesting)
        return true;
    if (spec_window >= max_spec_window)
        return true;
    return false;
}

void SpeculatorABC::checkpoint(dr_mcontext_t *mc, pc_t pc)
{
    // store the register state and the rollback address
    checkpoints.push_back({.rollback_pc = pc, .spec_window = spec_window, .mc = *mc});
    logger.log_checkpoint(pc, spec_window, store_log.size());

    // update the state machine that tracks the speculation proces
    in_speculation = true;
    nesting += 1;
}

pc_t SpeculatorABC::rollback(dr_mcontext_t *mc)
{

    // restore the last checkpoint
    if (checkpoints.empty()) {
        dr_printf("[ERROR] SpeculatorABC::rollback: no checkpoints to rollback");
        dr_abort();
    }
    const checkpoint_t checkpoint = checkpoints.back();
    checkpoints.pop_back();
    *mc = checkpoint.mc;
    spec_window = checkpoint.spec_window;

    // undo all store operations performed during speculation
    while (store_log.size() > 0) {
        const auto cur_store = store_log.back();

        if (cur_store.nesting_level < nesting)
            break;

        size_t w_size = 0;
        bool success =
            dr_safe_write((byte *)cur_store.addr, cur_store.size, &cur_store.val, &w_size);
        logger.log_rollback_store(cur_store.addr, cur_store.val, w_size, cur_store.nesting_level);

        store_log.pop_back();
        if (not success) {
            dr_printf("[WARNING] Failed rolling back store -- addr: %lx  val: %lx  sx: %d\n",
                      cur_store.addr, cur_store.val, cur_store.size);

            uint prot = -1;
            dr_query_memory((byte *)cur_store.addr, nullptr, nullptr, &prot);
            dr_printf("[WARNING] Page Flags %d\n", prot);

            // dr_abort();
        }
    }

    // update the state machine that tracks the speculation process
    nesting -= 1;
    if (nesting <= 0) {
        nesting = 0;
        in_speculation = false;
        if (not checkpoints.empty() or not store_log.empty()) {
            dr_printf("[ERROR] Speculation ended but there are still %d checkpoints and %d "
                      "store logs to consume\n",
                      checkpoints.size(), store_log.size());
            dr_abort();
        }
    }

    logger.log_rollback(nesting, checkpoint.rollback_pc);
    return checkpoint.rollback_pc;
}

pc_t SpeculatorABC::handle_instruction(instr_obs_t instr, dr_mcontext_t *mc, void * /*dc*/)
{
    if (not in_speculation)
        return 0;

    // rollback if we hit a speculation barrier
    if (is_speculation_barrier(instr.opcode)) {
        return rollback(mc);
    }

    // rollback if we hit a speculation window limit
    spec_window += 1;
    if (spec_window >= max_spec_window) {
        return rollback(mc);
    }

    return 0;
}

void SpeculatorABC::handle_mem_access(bool is_write, void *address, uint64_t size)
{
    if (not in_speculation)
        return;

    // record changes made to the memory
    if (is_write) {
        auto cur_address = (uint64_t)address;
        size_t remaining_size = size;

        // The store might be bigger than 64 bits (e.g. vector ops): save 64 bits at a time
        while (remaining_size > 0) {
            uint64_t cur_size = std::min(remaining_size, sizeof(uint64_t));
            // NOTE: on speculative paths, safe reads are the only way to load from memory, since
            // pointers might be invalid.
            size_t r_size = 0;
            uint64_t val = 0;
            bool success = dr_safe_read((byte *)cur_address, cur_size, (byte *)&val, &r_size);

            if (not success) {
                // If the memory access is illegal, the store is bound to fail: let the exception
                // handler deal with that.
                return;
            }

            // Save the previous memory value to be restored after speculation
            store_log.push_back({
                .addr = cur_address,
                .val = val,
                .size = cur_size,
                .nesting_level = nesting,
            });

            // Advance until all relevant memory has been saved
            cur_address += cur_size;
            remaining_size -= cur_size;
        }
    }
}
