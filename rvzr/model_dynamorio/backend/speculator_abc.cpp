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
#include <dr_api.h>

#include "dr_defines.h"
#include "dr_ir_opcodes_x86.h"
#include "dr_tools.h"
#include "observables.hpp"
#include "speculator_abc.hpp"
#include "util.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================

// See Intel Manual https://cdrdv2.intel.com/v1/dl/getContent/671200
// chapter 10.3 - Serializing Instructions.
static constexpr const std::array<uint64_t, 18> serializing_opcodes = {
    // Non-privileged memory-ordering instructions
    OP_lfence, OP_mfence, OP_sfence,
    // Privileged serializing instructions
    OP_invd, OP_invept, OP_invlpg, OP_invvpid, OP_lgdt, OP_lidt, OP_lldt, OP_ltr,
    // TODO: add MOV CR (except CR8)
    OP_wbinvd, OP_wrmsr,
    // Non-privileged serializing instructions
    OP_cpuid, OP_iret, OP_rsm, OP_serialize,
    // NOTE: syscalls are not inatrumented by Dynamorio, this makes sure that speculation is aborted
    // on speculative syscall instructions.
    OP_syscall};

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
    // dr_printf("[INFO] SpeculatorABC::checkpoint: checkpointing at %llx\n", (long long)pc);

    // store the register state and the rollback address
    checkpoints.push_back({.rollback_pc = pc,
                           .spec_window = spec_window,
                           .mc = *mc,
                           .store_log_size = store_log.size()});

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

        // dr_printf("[Rollback] Writing val: 0x%lx to addr: 0x%lx (nest: %d, sz: %d)\n",
        //           *(uint64_t *)cur_store.val, cur_store.addr, cur_store.nesting_level,
        //           cur_store.size);

        size_t w_size = 0;
        // TODO: maybe we can avoid this.
        bool success = dr_safe_write((uint64_t *)cur_store.addr, cur_store.size,
                                     (byte *)cur_store.val, &w_size);
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

    // dr_printf("[INFO] SpeculatorABC::rollback: Rolling back to pc %llx\n",
    //           (long long)checkpoint.rollback_pc);
    return checkpoint.rollback_pc;
}

pc_t SpeculatorABC::handle_instruction(instr_obs_t instr, dr_mcontext_t *mc, void * /*dc*/)
{
    // dr_printf("[INFO] handling %lx\n", (long)instr.pc);
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

    // if (not success)
    //     dr_printf("[MEM] unsuccessful memory op - addr: %lx  sz:%d\n", address, size);
    // else {
    //     if (is_write)
    //         dr_printf("[MEM] Write - addr: %lx  sz:%d  val:%lx\n", address, size,
    //                   *(uint64_t *)entry.val);
    //     else
    //         dr_printf("[MEM] Read -  addr: %lx  sz:%d  val:%lx\n", address, size,
    //                   *(uint64_t *)entry.val);
    // }

    if (not in_speculation)
        return;

    // record changes made to the memory
    if (is_write) {
        //  NOTE: on speculative paths, safe reads are the only way to load
        // from memory, since pointers might be invalid all the time.
        store_log_entry_t entry{.addr = (uint64_t)address, .nesting_level = nesting};
        bool success = dr_safe_read((uint64_t *)address, size, (byte *)entry.val, &entry.size);
        if (success) {
            store_log.push_back(entry);
            // dr_printf("[STORELOG] Pushing *%lx = %lx (nest: %d, sz: %d) \n", (uint64_t)address,
            //           *(uint64_t *)entry.val, nesting, size);
        }
    }
}
