///
/// File: Header for the MDS Speculator
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <dr_api.h> // NOLINT

#include "speculator_abc.hpp"

// =================================================================================================
// Constants and Types
// =================================================================================================

typedef struct {
  pc_t rollback_pc;
  uint64_t spec_window;
} xcpt_context_t;


// =================================================================================================
// Class Definition
// =================================================================================================

/// @brief MDS Speculator;
///        Upon faulty loads, this speculator forwards a predefined poison value
///        to the load's destination register instead of crashing. Changing the
///        poison value across different runs allows to simulate the presence of
//         controlled data in the pipeline that are loaded as a result of MDS.
class SpeculatorMDS : public SpeculatorABC
{
  public:
    using SpeculatorABC::SpeculatorABC;

    /// @brief If the current instruction is among the set of controlled loads,
    ///
    /// @param dc The current DR context
    /// @param siginfo The signal info structure for the exception
    /// @return true if the exception was handled (i.e., redirected), false otherwise
    bool handle_exception(void *dc, dr_siginfo_t *siginfo) override;

  private:
    std::vector<xcpt_context_t> xcpt_contexts;
};
