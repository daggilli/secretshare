#ifndef FILEOPERATIONS_HPP__
#define FILEOPERATIONS_HPP__
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>

#include "commandline.hpp"
using namespace SecretShare;

namespace SecretShare::FileOperations {
  namespace fs = std::filesystem;

  enum FileError { noErr, fileNotFoundErr, emptyFileErr, fileUnreadableErr, lengthMismatchErr };

  static FileError checkFiles(const CommandLine::CommandLineOptions &options, std::uintmax_t &fsize) {
    if (options.mode()) {
      auto filepath = fs::weakly_canonical(fs::absolute(options.filename()));
      if (!fs::exists(filepath)) return fileNotFoundErr;

      {
        auto ifs = std::ifstream(filepath);
        if (!ifs.good()) return fileUnreadableErr;
      }

      fsize = fs::file_size(filepath);
      return noErr;
    }

    std::uintmax_t eachfsize = 0;

    for (auto i : options.shares()) {
      auto share = std::format("{}_{}.dat", options.filename(), i);
      auto filepath = fs::weakly_canonical(fs::absolute(share));

      if (!fs::exists(filepath)) {
        return fileNotFoundErr;
      }

      {
        auto ifs = std::ifstream(filepath);
        if (!ifs.good()) return fileUnreadableErr;
      }

      auto cursize = fs::file_size(filepath);
      if (!cursize) return emptyFileErr;
      if (!eachfsize) eachfsize = cursize;
      if (eachfsize != cursize) {
        return lengthMismatchErr;
      }
    }

    fsize = eachfsize;

    return noErr;
  }
};  // namespace SecretShare::FileOperations
#endif