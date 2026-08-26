#include "forensic_engine.hpp"

#include <charconv>
#include <exception>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
  std::string image_path;
  std::string case_id;
  std::uint64_t offset = 0;

  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if ((argument == "--image" || argument == "--case-id" || argument == "--offset") && index + 1 >= argc) {
      std::cerr << "Missing value for " << argument << '\n';
      return 64;
    }
    if (argument == "--image") image_path = argv[++index];
    else if (argument == "--case-id") case_id = argv[++index];
    else if (argument == "--offset") {
      const std::string input = argv[++index];
      const auto [end, error] = std::from_chars(input.data(), input.data() + input.size(), offset);
      if (error != std::errc{} || end != input.data() + input.size()) {
        std::cerr << "Offset must be an unsigned integer\n";
        return 64;
      }
    } else {
      std::cerr << "Unknown argument: " << argument << '\n';
      return 64;
    }
  }

  if (image_path.empty() || case_id.empty()) {
    std::cerr << "Usage: forensicfs-parser --image <immutable-image-path> --case-id <case-id> [--offset <bytes>]\n";
    return 64;
  }

  try {
    const auto output = forensicfs::analyze_image(image_path, offset);
    std::cout << forensicfs::to_json(output, case_id) << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 70;
  }
}
