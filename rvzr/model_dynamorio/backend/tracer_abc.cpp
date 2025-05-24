///
/// File: Abstract Model TracerABC
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <dr_ir_instr.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>

#include <drmgr.h>
#include <drreg.h>
#include <drvector.h>

#include "observables.hpp"
#include "tracer_abc.hpp"

using std::string;

// =================================================================================================
// Constructors and Destructors
// =================================================================================================
TracerABC::TracerABC(const std::string &out_path, Logger &logger, bool print)
    : logger(logger), trace(print)
{
    trace.open(out_path);
}

// =================================================================================================
// Public Methods
// =================================================================================================
void TracerABC::tracing_start(void * /*wrapctx*/, DR_PARAM_OUT void ** /*user_data*/)
{
    tracing_on = true;
    tracing_finalized = false;
}

void TracerABC::tracing_finalize(void * /*wrapctx*/, DR_PARAM_OUT void * /*user_data*/)
{
    if (tracing_finalized) {
        return;
    }

    // Flush the trace buffer
    dr_printf("Done Tracing!\n");
    trace.clear();

    // Tell the user where to find the trace(s)
    dr_printf("Trace saved to %s\n", trace.get_filename().c_str());

    // Reset tracing flags
    tracing_on = false;
    tracing_finalized = true;
}

void TracerABC::observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, bool in_speculation)
{
    logger.log_instruction(instr, mc, in_speculation);
    // The rest of the functionality - if any - is implemented by subclasses
}

void TracerABC::observe_mem_access(bool is_write, void *address, uint64_t size)
{
    logger.log_mem_access(is_write, address, size);
    // The rest of the functionality - if any - is implemented by subclasses
}
