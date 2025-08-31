#pragma once
#ifndef SECRETSHARE_HPP__
#define SECRETSHARE_HPP__

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <memory>
#include <optional>
#include <print>
#include <random>
#include <span>
#include <string>
#include <vector>

using namespace std::string_view_literals;

namespace SecretShare {
  inline constexpr uint8_t nimberMulPowerTable[8][8] = {
      {1, 2, 4, 8, 16, 32, 64, 128},         {2, 3, 8, 12, 32, 48, 128, 192},
      {4, 8, 6, 11, 64, 128, 96, 176},       {8, 12, 11, 13, 128, 192, 176, 208},
      {16, 32, 64, 128, 24, 44, 75, 141},    {32, 48, 128, 192, 44, 52, 141, 198},
      {64, 128, 96, 176, 75, 141, 103, 185}, {128, 192, 176, 208, 141, 198, 185, 222}};

  inline constexpr uint8_t nimberDivTable[256] = {
      0,   1,   3,   2,   15,  12,  9,   11,  10,  6,   8,   7,   5,   14,  13,  4,   170, 160, 109, 107,
      131, 139, 116, 115, 228, 234, 92,  89,  73,  77,  220, 209, 85,  214, 80,  219, 199, 179, 203, 184,
      66,  226, 70,  236, 156, 247, 149, 248, 255, 182, 189, 240, 120, 164, 174, 127, 142, 100, 98,  134,
      193, 152, 145, 205, 119, 207, 40,  227, 112, 195, 42,  237, 76,  28,  186, 97,  72,  29,  177, 103,
      34,  218, 104, 253, 215, 32,  242, 110, 93,  27,  151, 123, 26,  88,  124, 158, 187, 75,  58,  135,
      57,  143, 176, 79,  82,  252, 108, 19,  106, 18,  87,  243, 68,  194, 117, 23,  22,  114, 206, 64,
      52,  165, 150, 91,  94,  159, 175, 55,  238, 146, 138, 20,  196, 222, 59,  99,  224, 155, 130, 21,
      200, 211, 56,  101, 204, 62,  129, 239, 249, 46,  122, 90,  61,  192, 225, 137, 44,  246, 95,  125,
      17,  171, 181, 212, 53,  121, 244, 232, 190, 217, 16,  161, 251, 230, 54,  126, 102, 78,  198, 37,
      213, 162, 49,  254, 39,  202, 74,  96,  241, 50,  168, 216, 153, 60,  113, 69,  132, 223, 178, 36,
      140, 210, 185, 38,  144, 63,  118, 65,  221, 31,  201, 141, 163, 180, 33,  84,  191, 169, 81,  35,
      30,  208, 133, 197, 136, 154, 41,  67,  24,  235, 173, 250, 167, 245, 25,  229, 43,  71,  128, 147,
      51,  188, 86,  111, 166, 233, 157, 45,  47,  148, 231, 172, 105, 83,  183, 48};

#include "nimbermultable.hpp"

  class Scheme {
   public:
    explicit Scheme(std::size_t m, std::size_t k) : m_(m), k_(k) {};

    void split(const std::shared_ptr<uint8_t[]> &input, std::size_t len,
               std::vector<std::shared_ptr<uint8_t[]>> &outputs,
               const std::shared_ptr<uint8_t[]> &ranbuf = {}) {
      outputs.reserve(m_);
      std::vector<uint8_t> inPoints(k_);
      std::vector<uint8_t> outPoints(m_);
      std::vector<uint8_t> inCross(k_);
      std::vector<uint8_t> outCross(m_);

      for (auto i{0u}; i < k_; i++) inPoints[i] = i;
      for (auto i{0u}; i < m_; i++) outPoints[i] = i + 1;

      preflight(inPoints, outPoints, inCross, outCross);

      uint8_t *ranptr = nullptr;
      std::size_t rbuflen = (k_ - 1) * len;
      std::shared_ptr<uint8_t[]> tempranbuf;

      if (ranbuf) {
        ranptr = ranbuf.get();
      } else {
        tempranbuf = std::make_shared_for_overwrite<uint8_t[]>(rbuflen);

        // FILL BUFFER WITH RANDOM DATA
        std::random_device rd;
        std::seed_seq randseed{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
        std::independent_bits_engine<std::mt19937, CHAR_BIT, uint8_t> randeng(randseed);

        std::generate_n(tempranbuf.get(), rbuflen, std::ref(randeng));
        ranptr = tempranbuf.get();
      }

      std::vector<std::span<uint8_t>> inputs;
      inputs.reserve(k_);
      inputs.emplace_back(input.get(), len);

      for (auto i{1u}; i < k_; i++) inputs.emplace_back(ranptr + ((i - 1) * len), len);

      outputs.clear();
      for (auto i{0u}; i < m_; i++) {
        outputs.push_back(std::make_shared_for_overwrite<uint8_t[]>(len));
      }

      evaluatePolynomial(inputs, outputs, inCross, outCross, inPoints, outPoints, len);
    }

    void join(std::vector<std::shared_ptr<uint8_t[]>> &inputs, std::size_t len,
              const std::vector<uint8_t> &inPoints, std::shared_ptr<uint8_t[]> &&output) {
      const std::vector<uint8_t> outPoints{0};
      std::vector<uint8_t> inCross(inputs.size());
      std::vector<uint8_t> outCross(1);

      preflight(inPoints, outPoints, inCross, outCross);

      std::vector<std::shared_ptr<uint8_t[]>> outputv;
      outputv.push_back(std::make_shared_for_overwrite<uint8_t[]>(len));

      evaluatePolynomial(inputs, outputv, inCross, outCross, inPoints, outPoints, len);
      output = std::move(outputv[0]);
    }

   private:
    std::size_t m_;
    std::size_t k_;

    constexpr uint8_t multiplyNimbers(uint8_t a, uint8_t b) {
      uint8_t n;
      uint16_t i, j;

      n = 0;
      for (i = 0; a >> i; i++)
        for (j = 0; b >> j; j++)
          if (((a >> i) & 1) && ((b >> j) & 1)) n ^= nimberMulPowerTable[i][j];
      return n;
    }

    void preflight(const std::vector<uint8_t> &inPoints, const std::vector<uint8_t> &outPoints,
                   std::vector<uint8_t> &inCross, std::vector<uint8_t> &outCross) {
      uint8_t n;
      for (auto i{0u}; i < inPoints.size(); i++) {
        n = 1;
        for (auto j{0u}; j < inPoints.size(); j++) {
          if (j != i) n = nimberMulTable[n][inPoints[i] ^ inPoints[j]];
        }
        inCross[i] = n;
      }

      for (auto i{0u}; i < outPoints.size(); i++) {
        n = 1;
        for (auto j{0u}; j < inPoints.size(); j++) {
          n = nimberMulTable[n][outPoints[i] ^ inPoints[j]];
        }
        outCross[i] = n;
      }
    }

    inline void evaluatePolynomial(const std::vector<std::shared_ptr<uint8_t[]>> &inputs,
                                   const std::vector<std::shared_ptr<uint8_t[]>> &outputs,
                                   const std::vector<uint8_t> &inCross, const std::vector<uint8_t> &outCross,
                                   const std::vector<uint8_t> &inPoints,
                                   const std::vector<uint8_t> &outPoints, std::size_t len) {
      std::vector<std::span<uint8_t>> inputSpans;
      for (auto &in : inputs) inputSpans.emplace_back(in.get(), len);
      evaluatePolynomial(inputSpans, outputs, inCross, outCross, inPoints, outPoints, len);
    }

    inline void evaluatePolynomial(const std::vector<std::span<uint8_t>> &inputs,
                                   const std::vector<std::shared_ptr<uint8_t[]>> &outputs,
                                   const std::vector<uint8_t> &inCross, const std::vector<uint8_t> &outCross,
                                   const std::vector<uint8_t> &inPoints,
                                   const std::vector<uint8_t> &outPoints, std::size_t len) {
      uint8_t n;
      for (auto ix{0u}; ix < len; ix++) {
        for (auto i{0u}; i < outputs.size(); i++) {
          n = 0;
          if (!outCross[i]) {
            for (auto j{0u}; j < inputs.size(); j++)
              if (outPoints[i] == inPoints[j]) n = inputs[j][ix];
          } else {
            for (auto j{0u}; j < inputs.size(); j++)
              n ^= nimberMulTable
                  [inputs[j][ix]]
                  [nimberMulTable[outCross[i]]
                                 [nimberDivTable[nimberMulTable[inCross[j]][outPoints[i] ^ inPoints[j]]]]];
          }
          outputs[i][ix] = n;
        }
      }
    }
  };
};  // namespace SecretShare
#endif
