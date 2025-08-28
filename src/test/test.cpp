#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <print>
#include <vector>

#include "secretshare.hpp"

int main() {
  std::println("COMMANDLINE SHARE UTILITY");

  SecretShare::Scheme s(5, 3);

  const std::size_t len = 26;
  uint8_t *in = new uint8_t[len];
  for (unsigned i = 0; i < len; i++) {
    in[i] = i + 'A';
  }

  uint8_t **out = new uint8_t *[5];
  for (unsigned i = 0; i < 5; i++) {
    out[i] = new uint8_t[len];
  }
  uint8_t *rbuf = new uint8_t[2 * len];
  std::fill(rbuf, rbuf + 2 * len, 0);

  s.split_buffer_oldstyle(in, len, 5, 3, out, rbuf);

  for (unsigned i = 0; i < len; i++) {
    std::print("{} ", static_cast<char>(in[i]));
  }
  std::println("\n");

  for (unsigned i = 0; i < 5; i++) {
    for (unsigned j = 0; j < len; j++) {
      std::print("{:02x} ", out[i][j]);
    }
    std::println("");
  }

  std::println("");

  std::fill(in, in + len, 0);

  const uint8_t *shares[] = {out[0], out[2], out[3]};
  uint8_t pts[] = {1, 3, 4};

  s.join_buffer_oldstyle(shares, len, pts, 3, in);

  for (unsigned i = 0; i < len; i++) {
    std::print("{} ", static_cast<char>(in[i]));
  }
  std::println("\n\n-----------------------\n");

  auto insp = std::make_shared<uint8_t[]>(len);
  for (unsigned i = 0; i < len; i++) {
    insp[i] = i + 'A';
  }
  for (unsigned i = 0; i < len; i++) {
    std::print("{} ", static_cast<char>(insp[i]));
  }
  std::println("\n");

  std::vector<std::shared_ptr<uint8_t[]>> outspv;

  auto ranbuf = std::make_shared<uint8_t[]>(2 * len);
  // s.split(insp, len, 5, 3, outspv, ranbuf);

  s.split(insp, len, 5, 3, outspv);

  std::println("OP SZ {}", outspv.size());
  for (auto &opv : outspv) {
    for (unsigned i = 0; i < len; i++) {
      std::print("{:02x} ", opv[i]);
    }
    std::println("");
  }

  std::vector<std::shared_ptr<uint8_t[]>> inspv{outspv[0], outspv[2], outspv[3]};
  std::shared_ptr<uint8_t[]> opsp;
  std::vector<uint8_t> inpts{1, 3, 4};

  s.join(inspv, len, inpts, std::move(opsp));

  for (unsigned i = 0; i < len; i++) {
    std::print("{} ", static_cast<char>(opsp[i]));
  }

  std::println("");

  return 0;
}
