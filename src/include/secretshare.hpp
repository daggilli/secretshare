#include <algorithm>
#include <climits>
#include <cstdint>
#include <fstream>
#include <memory>
#include <optional>
#include <print>
#include <random>
#include <span>
#include <string>
#include <vector>

using namespace std::string_view_literals;

namespace SecretShare {
  class Scheme {
   public:
    explicit Scheme(std::size_t m, std::size_t k) : m_(m), k_(k) { init_secret_sharing(); }

    int split(const std::shared_ptr<uint8_t[]> &input, std::size_t len, uint8_t m, uint8_t k,
              std::vector<std::shared_ptr<uint8_t[]>> &outputs,
              const std::shared_ptr<uint8_t[]> &ranbuf = {}) {
      outputs.reserve(m);
      std::vector<uint8_t> inPoints(k);
      std::vector<uint8_t> outPoints(m);
      std::vector<uint8_t> inCross(k);
      std::vector<uint8_t> outCross(m);

      for (auto i{0u}; i < k; i++) inPoints[i] = i;
      for (auto i{0u}; i < m; i++) outPoints[i] = i + 1;

      preflight(inPoints, outPoints, inCross, outCross);

      std::println("INPTS {}", inPoints);
      std::println("OUTPTS {}", outPoints);
      std::println("IN + {}", inCross);
      std::println("OUT + {}", outCross);

      uint8_t *ranptr = nullptr;
      std::size_t rbuflen = (k - 1) * len;
      std::shared_ptr<uint8_t[]> tempranbuf;

      if (ranbuf) {
        ranptr = ranbuf.get();
      } else {
        std::println("ALLOC RANBUF");
        tempranbuf = std::make_shared_for_overwrite<uint8_t[]>(rbuflen);

        // FILL BUFFER WITH RANDOM DATA
        std::random_device rd;
        std::seed_seq randseed{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
        std::independent_bits_engine<std::mt19937, CHAR_BIT, uint8_t> randeng(randseed);

        std::generate_n(tempranbuf.get(), rbuflen, std::ref(randeng));
        ranptr = tempranbuf.get();
      }

      dumpvx("RANBUF", ranptr, rbuflen);
      std::span<uint8_t> ranbufview{ranptr, rbuflen};

      std::vector<std::span<uint8_t>> inputs;
      inputs.reserve(k);
      inputs.emplace_back(input.get(), len);

      for (auto i{1u}; i < k; i++) inputs.emplace_back(ranptr + ((i - 1) * len), len);

      outputs.clear();
      for (auto i{0u}; i < m; i++) {
        outputs.push_back(std::make_shared_for_overwrite<uint8_t[]>(len));
      }

      std::println("M {} K {}", m, k);
      evaluate_polynomial(inputs, outputs, inCross, outCross, inPoints, outPoints, len);

      return 0;
    }

    int split_buffer_oldstyle(const uint8_t *const input, const size_t len, const uint16_t m,
                              const uint16_t k, uint8_t **outputs, const uint8_t *const ranbuf = nullptr) {
      uint8_t in_pts[256], out_pts[256], in_cross[256], out_cross[256];
      uint16_t i;

      /* input points at which the interpolating polynomial should
         be evaluated range from 0..k-1 */

      for (i = 0; i < k; i++) in_pts[i] = i;

      /* output is evaluated at point 1. This is arbitrary but given
         that the m-1 input sources other than the secret are
         cryptographically random this is OK */

      for (i = 0; i < m; i++) out_pts[i] = i + 1;

      // set up some lookup tables for faster computation

      preflight_oldstyle(in_pts, k, out_pts, m, in_cross, out_cross);

      dumpv("INPTS"sv, in_pts, k);
      dumpv("OUTPTS"sv, out_pts, m);
      dumpv("IN +"sv, in_cross, k);
      dumpv("OUT +"sv, out_cross, m);
      /* the array of m input buffers is an array of m pointers to
         uint8_t (i.e. a matrix - 2D). The indices of the
         pointers in the matrix correspond to the input points for
         the interpolating polynomial. Point 0 is the secret itself */

      const uint8_t **inputs;

      try {
        inputs = new const uint8_t *[k];
      } catch (const std::bad_alloc &e) {
        return -errno;
      }

      // point 0

      inputs[0] = input;

      const uint8_t *ipblock;

      if (ranbuf == nullptr) {
        // allocate storage for points 1..m-1

        try {
          ipblock = new uint8_t[(k - 1) * len];
        } catch (const std::bad_alloc &e) {
          delete[] inputs;
          return -errno;
        }

        // fill ipblock with random data

        std::ifstream urnd;
        urnd.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        try {
          urnd.open("/dev/urandom", std::ios::in | std::ifstream::binary);
        } catch (const std::ifstream::failure &e) {
          delete[] ipblock;
          delete[] inputs;
          return -errno;
        }
        urnd.read(std::bit_cast<char *>(ipblock), (k - 1) * len);
        urnd.close();
      } else
        ipblock = ranbuf;

      // store pointers into ipblock for input points 1..k-1 into inputs array

      for (i = 1; i < k; i++) inputs[i] = ipblock + ((i - 1) * len);

      /* repeatedly evaluate the interpolating polynomial across the
         multiple buffers of input data storing the output point in the
         output buffer */

      evaluate_polynomial_oldstyle(inputs, k, outputs, m, in_cross, out_cross, in_pts, out_pts, len);

      // clean up

      if (ranbuf == nullptr) delete[] ipblock;
      delete[] inputs;

      return 0;
    }

    void join(std::vector<std::shared_ptr<uint8_t[]>> &inputs, std::size_t len,
              const std::vector<uint8_t> &inPoints, std::shared_ptr<uint8_t[]> &&output) {
      const std::vector<uint8_t> outPoints{0};
      std::vector<uint8_t> inCross(inputs.size());
      std::vector<uint8_t> outCross(1);

      preflight(inPoints, outPoints, inCross, outCross);

      std::println("INPTS {}", inPoints);
      std::println("OUTPTS {}", outPoints);
      std::println("IN + {}", inCross);
      std::println("OUT + {}", outCross);

      std::vector<std::shared_ptr<uint8_t[]>> outputv;
      outputv.push_back(std::make_shared_for_overwrite<uint8_t[]>(len));

      evaluate_polynomial(inputs, outputv, inCross, outCross, inPoints, outPoints, len);
      output = std::move(outputv[0]);
    }

    void join_buffer_oldstyle(const uint8_t **inputs, const size_t len, const uint8_t *const in_pts,
                              const uint16_t k, uint8_t *output) {
      uint8_t out_pts[1], in_cross[256], out_cross[256];

      // because our secret was at point 0 in the input matrix when it was
      // split, this will reconstitute it at this location
      out_pts[0] = 0;

      preflight_oldstyle(in_pts, k, out_pts, 1, in_cross, out_cross);

      dumpv("JOS INPTS"sv, in_pts, k);
      dumpv("JOS OUTPTS"sv, out_pts, 1);
      dumpv("JOS IN +"sv, in_cross, k);
      dumpv("JOS OUT +"sv, out_cross, 1);

      evaluate_polynomial_oldstyle(inputs, k, &output, 1, in_cross, out_cross, in_pts, out_pts, len);
    }

   private:
    void dumpv(const std::string_view &msg, const uint8_t *v, std::size_t len) {
      std::print("{} ", msg);
      for (auto i{0u}; i < len; i++) {
        std::print("{} ", v[i]);
      }
      std::println("");
    }

    void dumpvx(const std::string_view &msg, const uint8_t *v, std::size_t len) {
      std::print("{} ", msg);
      for (auto i{0u}; i < len; i++) {
        std::print("{:02x} ", v[i]);
      }
      std::println("");
    }

    std::size_t m_;
    std::size_t k_;

    /* Multiplication table for the first 8 powers of two under nimber
    multiplication. */

    constinit static inline uint8_t nimber_mul_power_table[8][8] = {
        {1, 2, 4, 8, 16, 32, 64, 128},         {2, 3, 8, 12, 32, 48, 128, 192},
        {4, 8, 6, 11, 64, 128, 96, 176},       {8, 12, 11, 13, 128, 192, 176, 208},
        {16, 32, 64, 128, 24, 44, 75, 141},    {32, 48, 128, 192, 44, 52, 141, 198},
        {64, 128, 96, 176, 75, 141, 103, 185}, {128, 192, 176, 208, 141, 198, 185, 222}};

    /* Multiplication table for the nim product up to 255
    (must be filled by calling initialisation routine) */

    static inline uint8_t nimber_mul_table[256][256];

    /* Inversion table for the nim multiplication
    (must be filled by calling initialisation routine) */

    static inline uint8_t nimber_inverse_table[256];

    inline static bool needsInit_ = true;

    uint8_t calc_nimber_mul(const uint8_t a, const uint8_t b) {
      uint8_t n;
      uint16_t i, j;

      n = 0;
      for (i = 0; a >> i; i++)
        for (j = 0; b >> j; j++)
          if (((a >> i) & 1) && ((b >> j) & 1)) n ^= Scheme::nimber_mul_power_table[i][j];
      return n;
    }

    constexpr void fill_nimber_mul_table() {
      uint16_t i, j;

      for (i = 0; i < 256; i++)
        for (j = 0; j < 256; j++) Scheme::nimber_mul_table[i][j] = calc_nimber_mul(i, j);
    }

    constexpr void fill_nimber_inverse_table() {
      uint16_t i, j;

      Scheme::nimber_inverse_table[0] = 0; /* Meaningless */
      for (i = 1; i < 256; i++) {
        for (j = 1; Scheme::nimber_mul_table[i][j] != 1; j++) /* nothing */
          ;
        Scheme::nimber_inverse_table[i] = j;
      }
    }

    void init_secret_sharing() {
      std::println("INIT {}", Scheme::needsInit_);
      if (!Scheme::needsInit_) return;
      // fill up the pre-computed matrices

      fill_nimber_mul_table();
      fill_nimber_inverse_table();

      Scheme::needsInit_ = false;
    }

    void preflight(const std::vector<uint8_t> &inPoints, const std::vector<uint8_t> &outPoints,
                   std::vector<uint8_t> &inCross, std::vector<uint8_t> &outCross) {
      uint8_t n;
      for (auto i{0u}; i < inPoints.size(); i++) {
        n = 1;
        for (auto j{0u}; j < inPoints.size(); j++) {
          if (j != i) n = Scheme::nimber_mul_table[n][inPoints[i] ^ inPoints[j]];
        }
        inCross[i] = n;
      }

      for (auto i{0u}; i < outPoints.size(); i++) {
        n = 1;
        for (auto j{0u}; j < inPoints.size(); j++) {
          n = Scheme::nimber_mul_table[n][outPoints[i] ^ inPoints[j]];
        }
        outCross[i] = n;
      }
    }

    void preflight_oldstyle(const uint8_t *const in_pts, const uint16_t in, const uint8_t *const out_pts,
                            const uint16_t out, uint8_t *const in_cross, uint8_t *const out_cross) {
      uint16_t i, j;
      uint8_t n;

      for (i = 0; i < in; i++) {
        n = 1;
        for (j = 0; j < in; j++)
          if (j != i) n = Scheme::nimber_mul_table[n][in_pts[i] ^ in_pts[j]];
        in_cross[i] = n;
      }

      for (i = 0; i < out; i++) {
        n = 1;
        for (j = 0; j < in; j++) n = Scheme::nimber_mul_table[n][out_pts[i] ^ in_pts[j]];
        out_cross[i] = n;
      }
    }

    inline void evaluate_polynomial(const std::vector<std::shared_ptr<uint8_t[]>> &inputs,
                                    const std::vector<std::shared_ptr<uint8_t[]>> &outputs,
                                    const std::vector<uint8_t> &inCross, const std::vector<uint8_t> &outCross,
                                    const std::vector<uint8_t> &inPoints,
                                    const std::vector<uint8_t> &outPoints, std::size_t len) {
      std::vector<std::span<uint8_t>> inputSpans;
      for (auto &in : inputs) inputSpans.emplace_back(in.get(), len);
      evaluate_polynomial(inputSpans, outputs, inCross, outCross, inPoints, outPoints, len);
    }

    inline void evaluate_polynomial(const std::vector<std::span<uint8_t>> &inputs,
                                    const std::vector<std::shared_ptr<uint8_t[]>> &outputs,
                                    const std::vector<uint8_t> &inCross, const std::vector<uint8_t> &outCross,
                                    const std::vector<uint8_t> &inPoints,
                                    const std::vector<uint8_t> &outPoints, std::size_t len) {
      std::println("INPUTS SZ {}", inputs.size());
      std::println("OUTPUTS SZ {}", outputs.size());
      uint8_t n;
      for (auto ix{0u}; ix < len; ix++) {
        for (auto i{0u}; i < outputs.size(); i++) {
          n = 0;
          if (!outCross[i]) {
            for (auto j{0u}; j < inputs.size(); j++)
              if (outPoints[i] == inPoints[j]) n = inputs[j][ix];
          } else {
            for (auto j{0u}; j < inputs.size(); j++)
              n ^= nimber_mul_table
                  [inputs[j][ix]]
                  [nimber_mul_table[outCross[i]]
                                   [Scheme::nimber_inverse_table
                                        [Scheme::nimber_mul_table[inCross[j]][outPoints[i] ^ inPoints[j]]]]];
          }
          outputs[i][ix] = n;
        }
      }
    }

    inline void evaluate_polynomial_oldstyle(const uint8_t **inputs, const uint16_t num_inputs,
                                             uint8_t **outputs, const uint16_t num_outputs,
                                             const uint8_t *const in_cross, const uint8_t *const out_cross,
                                             const uint8_t *const in_pts, const uint8_t *const out_pts,
                                             const size_t buflen) {
      size_t ix;
      uint16_t i, j;
      uint8_t n;

      for (ix = 0; ix < buflen; ix++) {
        for (i = 0; i < num_outputs; i++) {
          n = 0;
          if (!out_cross[i]) {
            for (j = 0; j < num_inputs; j++)
              if (out_pts[i] == in_pts[j]) n = inputs[j][ix];
          } else {
            for (j = 0; j < num_inputs; j++)  // wow!! This is nasty
              n ^= nimber_mul_table
                  [inputs[j][ix]]
                  [nimber_mul_table[out_cross[i]]
                                   [Scheme::nimber_inverse_table
                                        [Scheme::nimber_mul_table[in_cross[j]][out_pts[i] ^ in_pts[j]]]]];
          }
          outputs[i][ix] = n;
        }
      }
    }
  };

};  // namespace SecretShare