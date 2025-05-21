///
/// File: Header for the CT Tracer and its variants
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <dr_api.h> // NOLINT
#include <dr_defines.h>

#include "tracer_abc.hpp"

/// @brief "Constant-Time" (CT) Tracer;
/// This tracer collects addresses of memory accesses and PCs of the executed instructions
class TracerPC : public TracerABC
{
  public:
    using TracerABC::TracerABC;

    /// @brief Record the PC of the executed instruction on the contract trace
    /// @param instr The instruction being executed
    /// @param mc The machine context of the instruction
    /// @param in_speculation Is the current instruction speculative
    /// @return void
    void observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, bool in_speculation) override;
};
