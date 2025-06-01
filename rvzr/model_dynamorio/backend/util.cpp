///
/// File: Helper functions for DR model
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstddef>

#include <cstdint>
#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_ir_opnd.h>
#include <dr_tools.h>

#include <drreg.h>
#include <drvector.h>

#include "observables.hpp"
#include "util.hpp"

void reserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where,
                              drvector_t *permitted, DR_PARAM_OUT reg_id_t *reg)
{
    if (drreg_reserve_register(drcontext, ilist, where, permitted, reg) != DRREG_SUCCESS) {
        dr_printf("ERROR: failed to reserve a register\n");
        dr_abort();
    }
}

void unreserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg)
{
    if (drreg_unreserve_register(drcontext, ilist, where, reg) != DRREG_SUCCESS) {
        dr_printf("ERROR: failed to unreserve a register\n");
        dr_abort();
    }
}

bool force_write(byte *addr, size_t size, const uint64_t *val, size_t *w_size)
{
    // Read page protections
    uint prot = -1;
    dr_query_memory(addr, nullptr, nullptr, &prot);

    // Make page writable
    dr_memory_protect(addr, size, DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC);
    bool success = dr_safe_write(addr, size, val, w_size);
    // Restore previous protections
    dr_memory_protect(addr, size, prot);

    return success;
}

bool is_illegal_jump(instr_obs_t instr, dr_mcontext_t *mc, void *dc)
{
    // Decode the instruction
    instr_noalloc_t noalloc;
    instr_noalloc_init(dc, &noalloc);
    instr_t *cur_instr = instr_from_noalloc(&noalloc);
    byte *next_pc = decode(dc, (byte *)instr.pc, cur_instr);
    if (next_pc == nullptr) {
        dr_printf("[ERROR] cond_speculator: Failed to decode instruction\n");
        dr_abort();
        return {};
    }

    // Check if it's an indirect call or ret.
    if (instr_is_call_indirect(cur_instr) || instr_is_return(cur_instr)) {
        opnd_t target = instr_get_target(cur_instr);
        app_pc target_addr = nullptr;

        // Get the jump target
        if (opnd_is_memory_reference(target) or instr_is_return(cur_instr)) {
            // For rets and indirect calls with a memory operand, we need to read the value from
            // memory.
            app_pc addr =
                instr_is_return(cur_instr) ? (app_pc)mc->xsp : opnd_compute_address(target, mc);
            // app_pc addr = opnd_compute_address(target, mc);
            uint64_t val = 0;
            if (dr_safe_read(addr, sizeof(uint64_t), &val, nullptr)) {
                target_addr = *(app_pc *)&val;
            } else {
                instr_free(dc, cur_instr);
                return false;
            }
            // Or directly from a register
        } else if (opnd_is_reg(target)) {
            // FIXME: to use this, the target value must be added during instrumentation.
            // target_addr = (app_pc)instr.target;

        } else {
            instr_free(dc, cur_instr);
            return false;
        }

        // Check if the target is executable
        uint prot = -1;
        dr_query_memory(target_addr, nullptr, nullptr, &prot);

        if ((prot & DR_MEMPROT_EXEC) == 0) {
            instr_free(dc, cur_instr);
            return true;
        }
    }

    instr_free(dc, cur_instr);
    return false;
}
