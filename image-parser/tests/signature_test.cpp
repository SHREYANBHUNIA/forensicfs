#include "forensic_engine.hpp"

#include <cassert>

int main() {
  const auto png = forensicfs::detect_signature({0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a});
  assert(png.has_value());
  assert(png->label == "PNG image");
  assert(forensicfs::signature_matches_extension(*png, "png"));
  assert(!forensicfs::signature_matches_extension(*png, "txt"));
  assert(forensicfs::extension_of("REPORT.PDF") == "pdf");
  assert(!forensicfs::detect_signature({0x01, 0x02, 0x03}).has_value());
  return 0;
}
