///
/// File: Helper functions for DR model
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstddef>

#include <cstdint>
#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h> // NOLINT
#include <drvector.h>
#include <fstream>
#include <string_view>

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

/// @brief Log buffer backed by a file
template <typename T, unsigned BufSize> class FileBackedBuf
{
    static_assert(BufSize % sizeof(T) == 0,
                  "[ASSERT] FileBackedBuf size must fit an exact number of elements");

  private:
    static constexpr const unsigned max_elems = BufSize / sizeof(T);
    unsigned n_elems = 0;
    std::array<T, max_elems> buf;
    std::ofstream stream;
    std::string filename;

  public:
    FileBackedBuf() = default;
    ~FileBackedBuf()
    {
        if (stream.is_open())
            stream.close();
    }
    FileBackedBuf(const FileBackedBuf &) = delete;
    FileBackedBuf(FileBackedBuf &&) = delete;
    FileBackedBuf &operator=(const FileBackedBuf &other) = delete;
    FileBackedBuf &operator=(FileBackedBuf &&other) = delete;

    /// @brief Open the backing ostream
    /// @param filename Path of backing file
    void open(const std::string &filename_)
    {
        stream.open(filename_, std::ios::binary | std::ios::trunc | std::ios::out);
        filename = filename_;
    }

    /// @brief Flush the current buffer contents into the backing file
    void flush()
    {
        uint32_t n_bytes = n_elems * sizeof(T);
        stream.write(reinterpret_cast<const char *>(buf.data()), n_bytes);
        n_elems = 0;
    }

    /// @brief Append an element to the buffer
    /// @param elem The element to add
    void push_back(const T &elem)
    {
        buf[n_elems] = elem;
        n_elems++;
        if (n_elems == max_elems)
            flush();
    }

    /// @brief Close the backing ostream
    void clear()
    {
        if (not stream.is_open())
            return;

        flush();
        stream.close();
    }

    /// @brief Get the name of the backing file
    const std::string &get_filename() const { return filename; }
};
