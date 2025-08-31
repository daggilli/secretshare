#include <memory>
#include <print>
#include <string_view>

#include "secretshare.hpp"

int main() {
  constexpr std::size_t M = 5;
  constexpr std::size_t K = 3;

  // initialise a Scheme object to split or join memory buffers
  SecretShare::Scheme s(M, K);

  // create an input buffer and fill it with A-Z

  const std::size_t len = 26;
  auto inbuffer = std::make_shared<uint8_t[]>(len);
  for (auto i{0u}; i < len; i++) {
    inbuffer[i] = i + 'A';
  }
  std::println("INPUT: {}", std::string(inbuffer.get(), inbuffer.get() + len));

  // create a vector of output buffers to receive the shares
  std::vector<std::shared_ptr<uint8_t[]>> outbufferv;

  // split the input buffer, writing the shares into the vecor of output buffers
  s.split(inbuffer, len, outbufferv);

  std::println("OUTPUT");
  for (auto &opbuf : outbufferv) {
    for (auto i{0}; i < len; i++) {
      std::print("{:02x} ", opbuf[i]);
    }
    std::println("");
  }

  // join K of the shares to recreate the input. The shares are indexed starting from 1, not zero
  std::vector<std::shared_ptr<uint8_t[]>> inbufferv{outbufferv[0], outbufferv[2], outbufferv[3]};
  std::shared_ptr<uint8_t[]> joinbuffer;
  std::vector<uint8_t> inputPoints{1, 3, 4};

  s.join(inbufferv, len, inputPoints, std::move(joinbuffer));

  std::println("JOINED: {}\n", std::string(joinbuffer.get(), joinbuffer.get() + len));

  // providing fewer than K shares does not reconsitute the shared secret
  inbufferv.pop_back();
  inputPoints.pop_back();

  s.join(inbufferv, len, inputPoints, std::move(joinbuffer));

  // gibberish
  std::println("Does NOT contain 41 42 43 ...");
  for (auto i{0}; i < len; i++) {
    std::print("{:02x} ", joinbuffer[i]);
  }
  std::println("");

  return 0;
}