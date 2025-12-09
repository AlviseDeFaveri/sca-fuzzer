///
/// File: Implementation of the MDS Speculator
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cassert>
#include <dr_api.h> // NOLINT

#include "speculator_abc.hpp"
#include "speculators/mds.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================

static bool is_supported_reg(const reg_id_t reg)
{
    // Some registers cannot be modified from the API, see DynamoRIO NYI i#3504
    return reg_is_gpr(reg) or (reg >= DR_REG_START_XMM && reg <= DR_REG_STOP_XMM) or
           (reg >= DR_REG_START_YMM && reg <= DR_REG_STOP_YMM) or
           (reg >= DR_REG_START_ZMM && reg <= DR_REG_STOP_ZMM);
}

/// @brief Decode the instruction at the given PC and return its destination register if it's a load.
/// @return The destination register and its next PC if it's a load; INVALID otherwise.
static std::pair<reg_id_t, byte *> get_destination_register_if_load(void *dc, byte *pc, Decoder &decoder)
{
    // Decode the instruction and get its next PC
    instr_t *cur_instr = decoder.get_decoded_instr(dc, pc);
    byte *next_pc = decoder.get_next_pc(dc, pc);

    // Check that it's a load
    if (not instr_reads_memory(cur_instr))
        return {DR_REG_INVALID, nullptr};

    // Check that it has at least one destination operand
    if (instr_num_dsts(cur_instr) == 0)
        return {DR_REG_INVALID, nullptr};

    // Check that the destination operand is a register
    const opnd_t dst = instr_get_dst(cur_instr, 0);
    if (not opnd_is_reg(dst))
        return {DR_REG_INVALID, nullptr};

    // Check that writing to the register is supported
    // (Not all registers can be written from the API)
    reg_id_t reg = opnd_get_reg(dst);
    reg = reg_to_pointer_sized(reg);
    if (not is_supported_reg(reg))
        return {DR_REG_INVALID, nullptr};


    return {reg, next_pc};
}


// =================================================================================================
// Class implementation
// =================================================================================================

bool SpeculatorMDS::handle_exception(void *dc, dr_siginfo_t *siginfo)
{
    // Use superclass implementation if the speculator is not enabled or
    // we reached speculation limit.
    if (skip_speculation())
        return SpeculatorABC::handle_exception(dc, siginfo);


    // Get faulty instruction's context
    dr_mcontext_t *mc = siginfo->mcontext;


    xcpt_context_t cur_context = xcpt_contexts.back();
    if (cur_context.rollback_pc == (pc_t)mc->pc and cur_context.spec_window == spec_window) {
        // We have already handled this exception in the current speculation context
        return SpeculatorABC::handle_exception(dc, siginfo);
    }

    // Decode the instruction and return its destination if it's a load
    const auto [dest_reg, next_pc] = get_destination_register_if_load(dc, mc->pc, decoder);

    // Inject the poison value is we have a faulty load
    if (dest_reg != DR_REG_INVALID) {
        // TODO: don't assert, make sure this is true by construction
        assert(poison_value.has_value());


        // TODO: implement checkpoint for exceptions
        checkpoint(mc, (pc_t)mc->pc);

        // Create a buffer with the repeated poison value
        constexpr int max_reg_size = 64;
        constexpr int n_elems = max_reg_size / sizeof(uint64_t);
        std::array<uint64_t, n_elems> poison_buf = {};
        std::fill(poison_buf.begin(), poison_buf.end(), poison_value.value());

        // Set the destination register to the poison value
        reg_set_value_ex(dest_reg, mc, (uint8_t *)(poison_buf.data()));
        // Skip to the next instruction
        // TODO: what if the instruction was supposed to have other side effects?
        mc->pc = next_pc;
        return true; // execution was redirected
    }

    // If we're not handling a load, defer to the superclass.
    return SpeculatorABC::handle_exception(dc, siginfo);
}
