#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace forensicfs {

struct SignatureMatch {
  std::string label;
  std::vector<std::string> expected_extensions;
};

struct MacTimes {
  std::optional<std::string> created_at;
  std::optional<std::string> modified_at;
  std::optional<std::string> accessed_at;
  std::optional<std::string> changed_at;
  std::optional<std::string> deleted_at;
};

struct FileRecord {
  std::string record_id;
  std::string path;
  std::string name;
  std::string parent_path;
  std::string entry_type;
  std::string extension;
  std::uint64_t size_bytes = 0;
  std::string inode;
  std::string allocation_state;
  MacTimes mac_times;
  std::optional<SignatureMatch> signature;
  std::optional<bool> signature_matches_extension;
};

struct Finding {
  std::string finding_id;
  std::optional<std::string> file_record_id;
  std::string severity;
  std::string category;
  std::string title;
  std::string rationale;
};

struct TimelineEvent {
  std::string event_id;
  std::optional<std::string> file_record_id;
  std::string event_type;
  std::string occurred_at;
  std::string path;
  std::string source;
};

struct AnalysisOutput {
  std::string filesystem_type;
  std::vector<FileRecord> files;
  std::vector<Finding> findings;
  std::vector<TimelineEvent> timeline;
  std::vector<std::string> parser_warnings;
};

std::optional<SignatureMatch> detect_signature(const std::vector<unsigned char>& bytes);
std::string extension_of(const std::string& filename);
bool signature_matches_extension(const SignatureMatch& signature, const std::string& extension);
AnalysisOutput analyze_image(const std::string& image_path, std::uint64_t filesystem_offset = 0);
std::string to_json(const AnalysisOutput& output, const std::string& case_id);

}  // namespace forensicfs
