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

#include "observables.hpp"
#include "speculator_abc.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================

// See Intel Manual https://cdrdv2.intel.com/v1/dl/getContent/671200
// chapter 10.3 - Serializing Instructions.
static constexpr const std::array<uint64_t, 23> serializing_opcodes = {
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
    // FIXME: check these
    OP_hlt, OP_xbegin, OP_xabort, OP_xend, OP_xtest};

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
    checkpoints.push_back({.rollback_pc = pc,
                           .spec_window = spec_window,
                           .mc = *mc,
                           .store_log_size = store_log.size()});
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
    while (store_log.size() > checkpoint.store_log_size) {
        const auto cur_store = store_log.back();
        store_log.pop_back();

        if (cur_store.nesting_level < nesting)
            break;

        size_t w_size = 0;
        // FIXME: maybe we can avoid this.
        bool success =
            dr_safe_write((byte *)cur_store.addr, sizeof(uint64_t), &cur_store.val, &w_size);
        logger.log_rollback_store(cur_store.addr, cur_store.val, w_size);
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
        size_t qword_size = size / sizeof(uint64_t);
        if (size % sizeof(uint64_t) != 0)
            qword_size += 1;

        size_t r_size = 0;
        uint64_t val_ptr[8];
        bool success = dr_safe_read(address, qword_size * 8, (byte *)val_ptr, &r_size);
        if (not success)
            // SEGFAULT will be handled by the exception event.
            return;

        uint8_t cur_idx = 0;
        while (cur_idx < qword_size) {
            // Read 64 bits at a time.
            // NOTE: on speculative paths, safe reads are the only way to load
            // from memory, since pointers might be invalid.
            store_log.push_back({
                .addr = (uint64_t)address + (cur_idx * 8),
                .val = val_ptr[cur_idx],
                .nesting_level = nesting,
            });

            // Some writes can be greater than 8 bytes (e.g. vector registers spilling)
            // Insert multiple 64-bit entries in these cases
            cur_idx += 1;
        }
    }
}
