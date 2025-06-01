///
/// File: Helper functions for DR model
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "observables.hpp"
#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h> // NOLINT
#include <drvector.h>

#define INSERT_BEFORE instrlist_meta_preinsert

/// @brief A wrapper around drreg_reserve_register that aborts on failure
/// @param drcontext The drcontext of the current thread
/// @param ilist Current instruction list
/// @param where Current instruction
/// @param permitted The set of registers that can be reserved
/// @param [out] reg The reserved register
/// @return void
void reserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where,
                              drvector_t *permitted, DR_PARAM_OUT reg_id_t *reg);

/// @brief A wrapper around drreg_reserve_register that aborts on failure
/// @param drcontext The drcontext of the current thread
/// @param ilist Current instruction list
/// @param where Current instruction
/// @param reg The register to unreserve
/// @return void
void unreserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg);

/// @brief Write to the given addres by overwriting the permission bits (and restoring them after
///        the write).
/// NOTE: Writing to executable memory might clash with DynamoRIO's code cache, use with caution.
bool force_write(byte *addr, size_t size, const uint64_t *val, size_t *w_size);

/// @brief Check if an instruction is an indirect call or return to an illegal instruction.
///        This has to be called from _within_ the dispatcher's clean_call to make sure that the
///        runtime value of the target is known.
/// NOTE: This operation is not cheap, use with caution.
/// @param instr The instruction to check
/// @param mc
/// @param dc
bool is_illegal_jump(instr_obs_t instr, dr_mcontext_t *mc, void *dc);
