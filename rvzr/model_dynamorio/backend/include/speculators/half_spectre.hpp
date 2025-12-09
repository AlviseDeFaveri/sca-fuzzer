///
/// File: Header for the Half-Spectre Speculator
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <dr_api.h> // NOLINT

#include "speculator_abc.hpp"

/// @brief Half-Spectre Speculator;
///        This speculator is used as an approximated model for controlled loads:
///        if the PC of the current load belongs to a list of PCs that are
///        considered "controlled", it will forward a predefined poison value
//         to the load's destination register instead of crashing.
class SpeculatorHalfSpectre : public SpeculatorABC
{
  public:
    using SpeculatorABC::SpeculatorABC;

    /// @brief If the current instruction is among the set of controlled loads,
    ///        forward the poison value to the destination register.
    ///
    /// @param dc The current DR context
    /// @param siginfo The signal info structure for the exception
    /// @return true if the exception was handled (i.e., redirected), false otherwise
    bool handle_exception(void *dc, dr_siginfo_t *siginfo) override;
};
