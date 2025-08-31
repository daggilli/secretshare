#include "secretshare.hpp"

#include <cerrno>
#include <cstdint>
#include <print>
#include <stdexcept>

#include "commandline.hpp"
#include "fileoperations.hpp"
#include "secretshareoperations.hpp"
using namespace SecretShare;

int main(int argc, char *argv[]) {
  CommandLine::CommandLineOptions options;

  try {
    options.parse(argc, argv);
  } catch (std::invalid_argument &e) {
    std::println("Error: {}", e.what());
    CommandLine::CommandLineOptions::usage();
    exit(-EINVAL);
  }

  std::uintmax_t fsize;
  FileOperations::FileError fileErr;
  auto err = -ENOENT;

  try {
    if ((fileErr = FileOperations::checkFiles(options, fsize)) != FileOperations::noErr) {
      std::string errStr;
      switch (fileErr) {
        case FileOperations::fileNotFoundErr: {
          errStr = "File(s) not found";
          break;
        }

        case FileOperations::emptyFileErr: {
          errStr = "File has zero length";
        }

        case FileOperations::fileUnreadableErr: {
          errStr = "File(s) not readable";
          break;
        }

        case FileOperations::lengthMismatchErr: {
          errStr = "Files have differing sizes";
          break;
        }

        default: {
          errStr = "Unknown error";
          break;
        }
      }

      throw std::invalid_argument(errStr);
      err = -EINVAL;
    }
  } catch (std::invalid_argument &e) {
    std::println("!!! Error: {}\n", e.what());
    CommandLine::CommandLineOptions::usage();
    exit(err);
  }

  if (options.mode()) {
    SecretSHareOperations::splitFile(options.filename(), fsize, options.m(), options.k());
  } else {
    SecretSHareOperations::joinFile(options.filename(), fsize, options.m(), options.shares());
  }

  return 0;
}
