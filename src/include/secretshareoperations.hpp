#ifndef SECRETSHAREOPERATIONS_HPP__
#define SECRETSHAREOPERATIONS_HPP__
#include <cstdint>
#include <filesystem>
#include <memory>
#include <print>
#include <set>
#include <vector>

#include "commandline.hpp"
using namespace SecretShare;

namespace SecretShare::SecretSHareOperations {
  namespace fs = std::filesystem;

  static void splitFile(const fs::path &filepath, std::uintmax_t fsize, std::size_t m, std::size_t k) {
    std::shared_ptr<uint8_t[]> input;

    try {
      input = std::make_shared_for_overwrite<uint8_t[]>(fsize);
    } catch (const std::bad_alloc &e) {
      std::println("Can't allocate input buffer: {}", e.what());
      throw;
    }

    {  // RAII
      std::ifstream infile;
      infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
      try {
        infile.open(filepath.c_str(), std::ios::in | std::ifstream::binary);
      } catch (const std::ifstream::failure &e) {
        std::println("Can't open input file {}: {} ({}: {})", filepath.string(), e.what(), e.code().value(),
                     e.code().message());
        throw;
      }

      infile.read(std::bit_cast<char *>(input.get()), fsize);
    }

    std::vector<std::shared_ptr<uint8_t[]>> outputs;

    SecretShare::Scheme scheme(m, k);

    scheme.split(input, fsize, outputs);

    auto ix{1u};
    for (auto &&o : outputs) {
      auto sharename = std::format("{}_{}.dat", filepath.string(), ix++);
      std::ofstream share(sharename, std::ofstream::binary);
      share.write(std::bit_cast<char *>(o.get()), fsize);
    }
  }

  static void joinFile(const fs::path &filepath, std::uintmax_t fsize, std::size_t m,
                       const std::set<uint> &shares) {
    std::vector<std::shared_ptr<uint8_t[]>> inputs;
    std::vector<uint8_t> inPoints;
    inPoints.reserve(shares.size());

    for (auto share : shares) {
      inPoints.push_back(share);
      auto sharename = std::format("{}_{}.dat", filepath.string(), share);

      std::ifstream infile;

      infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
      try {
        infile.open(sharename, std::ifstream::binary);
      } catch (const std::ifstream::failure &e) {
        std::println("Can't open input file {}: {} ({}: {})", sharename, e.what(), e.code().value(),
                     e.code().message());
        throw;
      }
      std::shared_ptr<uint8_t[]> input;
      try {
        input = std::make_shared_for_overwrite<uint8_t[]>(fsize);
      } catch (std::bad_alloc &e) {
        std::println("Can't allocate input buffer: {}", e.what());
        throw;
      }
      infile.read(std::bit_cast<char *>(input.get()), fsize);
      inputs.push_back(input);
      infile.close();
    }

    std::shared_ptr<uint8_t[]> output;
    SecretShare::Scheme scheme(m, shares.size());

    scheme.join(inputs, fsize, inPoints, std::move(output));

    auto outputname = std::format("{}.out", filepath.string());

    std::ofstream outputfile(outputname, std::ofstream::binary);
    outputfile.write(std::bit_cast<char *>(output.get()), fsize);
  }
};  // namespace SecretShare::SecretSHareOperations

#endif