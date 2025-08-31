#ifndef COMMANDLINE_HPP__
#define COMMANDLINE_HPP__
#include <unistd.h>

#include <cstdint>
#include <format>
#include <print>
#include <set>
#include <sstream>
#include <string>

namespace SecretShare::CommandLine {
  class CommandLineOptions {
   public:
    explicit CommandLineOptions() : parsed_(false), split_(true), m_(false), k_(false) {}
    explicit CommandLineOptions(int argc, char* const argv[])
        : parsed_(false), split_(true), m_(false), k_(false) {
      parse(argc, argv);
    }

    void parse(int argc, char* const argv[]) {
      int c;
      opterr = 0;
      bool hasShares = false;

      while ((c = getopt(argc, argv, "m:k:js:r:")) != -1) {
        switch (c) {
          case 'm': {
            m_ = std::stoul(optarg);
            break;
          }

          case 'k': {
            k_ = std::stoul(optarg);
            break;
          }

          case 'j': {
            split_ = false;
            break;
          }

          case 's': {
            hasShares = true;
            uint v;
            std::stringstream shareStr(optarg);

            while (shareStr >> v) {
              shares_.insert(v);
              if (shareStr.peek() == ',') shareStr.ignore();
            }
            break;
          }

          case '?': {
            auto err = std::format("Invalid option '{}'", static_cast<char>(optopt));
            throw std::invalid_argument(err);
            break;
          }
        }
      }
      if (m_ < 1 || m_ > 255)
        throw std::invalid_argument("Number of shares must be a number between 1 and 255");
      if (k_ < 1 || k_ > m_)
        throw std::invalid_argument("Threshold must be a number between 1 and the number of shares");
      if (split_ && hasShares) throw std::invalid_argument("List of shares invalid for split mode");
      if (!split_ && !hasShares)
        throw std::invalid_argument("List of shares must be supplied for split mode");
      if (!split_ && shares_.size() < k_) throw std::invalid_argument("Not enough shares specified");

      int argdiff;

      if ((argdiff = (argc - optind)) == 1)
        filename_.assign(argv[optind]);
      else
        throw std::invalid_argument(argdiff == 0 ? "Missing filename argument"
                                                 : "Too many non-option arguments");
    }

    const auto m() const { return m_; }
    const auto k() const { return k_; }
    const auto& shares() const { return shares_; }
    const auto mode() const { return split_; }
    const auto& filename() const { return filename_; }

    static void usage() {
      std::println("Usage (split): secretshare -m <shares> -k <threshold> <filename>");
      std::println("       (join): secretshare -m <shares> -k <threshold> -j -s <\"s1 s2 ... \"> <filename>");
      std::println("\ne.g.\nsecretshare -m 7 -k 4 plaintextfile \n -> plaintextfile_1.dat");
      std::println(" -> plaintextfile_2.dat\n -> ...\n -> plaintextfile_7.dat\n");
      std::println("secretshare -m 7 -k 4 -j -s \"2 4 5 7\" plaintextfile\n -> plaintextfile.out");
    }

   private:
    bool parsed_;
    bool split_;
    std::size_t m_;
    std::size_t k_;
    std::set<uint> shares_;
    std::string filename_;
  };
};  // namespace SecretShare::CommandLine

#endif
