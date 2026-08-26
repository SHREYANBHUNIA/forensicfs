#include "forensic_engine.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

#include <tsk/libtsk.h>

namespace forensicfs {
namespace {

struct WalkContext {
  AnalysisOutput* output;
  std::size_t counter = 0;
};

std::string json_escape(const std::string& value) {
  std::ostringstream out;
  for (const char character : value) {
    switch (character) {
      case '"': out << "\\\""; break;
      case '\\': out << "\\\\"; break;
      case '\b': out << "\\b"; break;
      case '\f': out << "\\f"; break;
      case '\n': out << "\\n"; break;
      case '\r': out << "\\r"; break;
      case '\t': out << "\\t"; break;
      default:
        if (static_cast<unsigned char>(character) < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(static_cast<unsigned char>(character)) << std::dec;
        } else {
          out << character;
        }
    }
  }
  return out.str();
}

std::string quote(const std::string& value) { return "\"" + json_escape(value) + "\""; }

std::string opt_quote(const std::optional<std::string>& value) {
  return value ? quote(*value) : "null";
}

std::optional<std::string> iso_utc(time_t timestamp) {
  if (timestamp <= 0) return std::nullopt;
  std::tm utc{};
  if (gmtime_r(&timestamp, &utc) == nullptr) return std::nullopt;
  std::ostringstream output;
  output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
  return output.str();
}

std::string join_path(const char* directory, const char* name) {
  std::string path = directory == nullptr ? "/" : directory;
  if (path.empty()) path = "/";
  if (path.back() != '/') path += '/';
  path += name == nullptr ? "" : name;
  return path;
}

std::string parent_path(const std::string& path) {
  const std::size_t position = path.find_last_of('/');
  if (position == std::string::npos || position == 0) return "/";
  return path.substr(0, position);
}

std::string entry_type(TSK_FS_META_TYPE_ENUM type) {
  if (TSK_FS_IS_DIR_META(type)) return "directory";
  if (type == TSK_FS_META_TYPE_REG) return "file";
  if (type == TSK_FS_META_TYPE_LNK) return "link";
  return "other";
}

bool is_suspicious_extension(const std::string& extension) {
  static const std::unordered_set<std::string> suspicious = {
      "ade", "adp", "apk", "bat", "cmd", "com", "cpl", "dll", "exe", "hta", "jar", "js", "jse", "lnk", "msi", "ps1", "scr", "vbe", "vbs", "wsf"};
  return suspicious.contains(extension);
}

void append_event(AnalysisOutput& output, const FileRecord& record, const std::string& event_type,
                  const std::optional<std::string>& occurred_at, const std::string& source, std::size_t sequence) {
  if (!occurred_at) return;
  output.timeline.push_back({"evt-" + std::to_string(sequence), record.record_id, event_type,
                             *occurred_at, record.path, source});
}

void append_findings(AnalysisOutput& output, const FileRecord& record, std::size_t sequence) {
  if (record.signature && record.signature_matches_extension && !*record.signature_matches_extension) {
    output.findings.push_back({"finding-signature-" + std::to_string(sequence), record.record_id, "high", "signature",
                               "File signature conflicts with extension", "The observed " + record.signature->label +
                                   " signature does not match the ." + record.extension + " filename extension."});
  }
  if (is_suspicious_extension(record.extension)) {
    output.findings.push_back({"finding-extension-" + std::to_string(sequence), record.record_id, "medium", "extension",
                               "Potentially executable extension", "The file extension ." + record.extension +
                                   " is commonly associated with executable or script content."});
  }
  if (record.allocation_state == "deleted") {
    output.findings.push_back({"finding-recovery-" + std::to_string(sequence), record.record_id, "medium", "recovery",
                               "Unallocated directory entry", "Filesystem metadata marks this entry as unallocated; recovery confidence depends on overwritten content."});
  }
  if (record.mac_times.created_at && record.mac_times.modified_at && *record.mac_times.modified_at < *record.mac_times.created_at) {
    output.findings.push_back({"finding-metadata-modified-" + std::to_string(sequence), record.record_id, "medium", "metadata",
                               "Modification predates creation", "The recorded modification timestamp precedes the creation timestamp and should be corroborated against filesystem semantics and clock context."});
  }
  if (record.mac_times.created_at && record.mac_times.accessed_at && *record.mac_times.accessed_at < *record.mac_times.created_at) {
    output.findings.push_back({"finding-metadata-accessed-" + std::to_string(sequence), record.record_id, "low", "metadata",
                               "Access predates creation", "The recorded access timestamp precedes the creation timestamp and may indicate metadata copying, timestamp manipulation, or filesystem-specific behavior."});
  }
}

TSK_WALK_RET_ENUM collect_file(TSK_FS_FILE* file, const char* directory, void* raw_context) {
  auto* context = static_cast<WalkContext*>(raw_context);
  if (file == nullptr || file->name == nullptr || file->meta == nullptr || file->name->name == nullptr) {
    return TSK_WALK_CONT;
  }

  const std::string name = file->name->name;
  if (name == "." || name == "..") return TSK_WALK_CONT;

  FileRecord record;
  record.record_id = "file-" + std::to_string(++context->counter);
  record.path = join_path(directory, file->name->name);
  record.name = name;
  record.parent_path = parent_path(record.path);
  record.entry_type = entry_type(file->meta->type);
  record.extension = extension_of(name);
  record.size_bytes = static_cast<std::uint64_t>(std::max<TSK_OFF_T>(0, file->meta->size));
  record.inode = std::to_string(file->meta->addr);
  record.allocation_state = (file->meta->flags & TSK_FS_META_FLAG_UNALLOC) ? "deleted" : "allocated";
  record.mac_times.created_at = iso_utc(file->meta->crtime);
  record.mac_times.modified_at = iso_utc(file->meta->mtime);
  record.mac_times.accessed_at = iso_utc(file->meta->atime);
  record.mac_times.changed_at = iso_utc(file->meta->ctime);

  if (record.allocation_state == "deleted") {
    record.mac_times.deleted_at = record.mac_times.changed_at ? record.mac_times.changed_at : record.mac_times.modified_at;
  }

  if (record.entry_type == "file" && record.allocation_state == "allocated" && record.size_bytes > 0) {
    std::array<char, 32> prefix{};
    const ssize_t bytes_read = tsk_fs_file_read(file, 0, prefix.data(), prefix.size(), TSK_FS_FILE_READ_FLAG_NONE);
    if (bytes_read > 0) {
      record.signature = detect_signature(std::vector<unsigned char>(prefix.begin(), prefix.begin() + bytes_read));
      if (record.signature) record.signature_matches_extension = signature_matches_extension(*record.signature, record.extension);
    }
  }

  append_findings(*context->output, record, context->counter);
  append_event(*context->output, record, "created", record.mac_times.created_at, "filesystem creation timestamp", context->counter);
  append_event(*context->output, record, "modified", record.mac_times.modified_at, "filesystem modification timestamp", context->counter);
  append_event(*context->output, record, "accessed", record.mac_times.accessed_at, "filesystem access timestamp", context->counter);
  append_event(*context->output, record, "changed", record.mac_times.changed_at, "filesystem change timestamp", context->counter);
  append_event(*context->output, record, "deleted", record.mac_times.deleted_at, "derived from unallocated metadata", context->counter);
  context->output->files.push_back(std::move(record));
  return TSK_WALK_CONT;
}

std::string filesystem_type_name(TSK_FS_TYPE_ENUM type) {
  const char* name = tsk_fs_type_toname(type);
  return name == nullptr ? "unknown" : name;
}

}  // namespace

std::optional<SignatureMatch> detect_signature(const std::vector<unsigned char>& bytes) {
  const auto starts_with = [&bytes](std::initializer_list<unsigned char> magic) {
    return bytes.size() >= magic.size() && std::equal(magic.begin(), magic.end(), bytes.begin());
  };
  if (starts_with({0x25, 0x50, 0x44, 0x46, 0x2d})) return SignatureMatch{"PDF document", {"pdf"}};
  if (starts_with({0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a})) return SignatureMatch{"PNG image", {"png"}};
  if (starts_with({0xff, 0xd8, 0xff})) return SignatureMatch{"JPEG image", {"jpg", "jpeg"}};
  if (starts_with({0x50, 0x4b, 0x03, 0x04})) return SignatureMatch{"ZIP archive", {"zip", "docx", "xlsx", "pptx", "jar", "apk"}};
  if (starts_with({0x7f, 0x45, 0x4c, 0x46})) return SignatureMatch{"ELF executable", {"elf", "so", "bin"}};
  if (starts_with({0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00})) return SignatureMatch{"SQLite database", {"db", "sqlite", "sqlite3"}};
  if (starts_with({0x4d, 0x5a})) return SignatureMatch{"PE executable", {"exe", "dll", "sys", "scr"}};
  return std::nullopt;
}

std::string extension_of(const std::string& filename) {
  const auto dot = filename.find_last_of('.');
  if (dot == std::string::npos || dot == filename.size() - 1) return "";
  std::string extension = filename.substr(dot + 1);
  std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char character) { return std::tolower(character); });
  return extension;
}

bool signature_matches_extension(const SignatureMatch& signature, const std::string& extension) {
  return extension.empty() || std::find(signature.expected_extensions.begin(), signature.expected_extensions.end(), extension) != signature.expected_extensions.end();
}

AnalysisOutput analyze_image(const std::string& image_path, std::uint64_t filesystem_offset) {
  TSK_IMG_INFO* image = tsk_img_open_sing(image_path.c_str(), TSK_IMG_TYPE_DETECT, 0);
  if (image == nullptr) throw std::runtime_error("Unable to open image: " + std::string(tsk_error_get_errstr()));

  TSK_FS_INFO* filesystem = tsk_fs_open_img(image, filesystem_offset, TSK_FS_TYPE_DETECT);
  if (filesystem == nullptr) {
    const std::string error = tsk_error_get_errstr();
    tsk_img_close(image);
    throw std::runtime_error("Unable to detect a supported filesystem at offset " + std::to_string(filesystem_offset) + ": " + error);
  }

  AnalysisOutput output;
  output.filesystem_type = filesystem_type_name(filesystem->ftype);
  WalkContext context{&output, 0};
  const auto flags = static_cast<TSK_FS_DIR_WALK_FLAG_ENUM>(TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE);
  if (tsk_fs_dir_walk(filesystem, filesystem->root_inum, flags, collect_file, &context) != 0) {
    output.parser_warnings.push_back("Directory traversal completed with an error: " + std::string(tsk_error_get_errstr()));
  }
  std::sort(output.timeline.begin(), output.timeline.end(), [](const TimelineEvent& left, const TimelineEvent& right) {
    return left.occurred_at == right.occurred_at ? left.event_id < right.event_id : left.occurred_at < right.occurred_at;
  });
  tsk_fs_close(filesystem);
  tsk_img_close(image);
  return output;
}

std::string to_json(const AnalysisOutput& output, const std::string& case_id) {
  std::ostringstream json;
  json << "{\"case_id\":" << quote(case_id) << ",\"filesystem_type\":" << quote(output.filesystem_type) << ",\"files\":[";
  for (std::size_t index = 0; index < output.files.size(); ++index) {
    const auto& file = output.files[index];
    if (index) json << ',';
    json << "{\"record_id\":" << quote(file.record_id) << ",\"path\":" << quote(file.path)
         << ",\"name\":" << quote(file.name) << ",\"parent_path\":" << quote(file.parent_path)
         << ",\"entry_type\":" << quote(file.entry_type) << ",\"extension\":" << quote(file.extension)
         << ",\"size_bytes\":" << file.size_bytes << ",\"inode\":" << quote(file.inode)
         << ",\"allocation_state\":" << quote(file.allocation_state)
         << ",\"mac_times\":{\"created_at\":" << opt_quote(file.mac_times.created_at)
         << ",\"modified_at\":" << opt_quote(file.mac_times.modified_at)
         << ",\"accessed_at\":" << opt_quote(file.mac_times.accessed_at)
         << ",\"changed_at\":" << opt_quote(file.mac_times.changed_at)
         << ",\"deleted_at\":" << opt_quote(file.mac_times.deleted_at) << "}"
         << ",\"signature\":" << (file.signature ? quote(file.signature->label) : "null")
         << ",\"signature_matches_extension\":";
    if (file.signature_matches_extension) json << (*file.signature_matches_extension ? "true" : "false"); else json << "null";
    json << '}';
  }
  json << "],\"findings\":[";
  for (std::size_t index = 0; index < output.findings.size(); ++index) {
    const auto& finding = output.findings[index];
    if (index) json << ',';
    json << "{\"finding_id\":" << quote(finding.finding_id) << ",\"file_record_id\":" << opt_quote(finding.file_record_id)
         << ",\"severity\":" << quote(finding.severity) << ",\"category\":" << quote(finding.category)
         << ",\"title\":" << quote(finding.title) << ",\"rationale\":" << quote(finding.rationale) << '}';
  }
  json << "],\"timeline\":[";
  for (std::size_t index = 0; index < output.timeline.size(); ++index) {
    const auto& event = output.timeline[index];
    if (index) json << ',';
    json << "{\"event_id\":" << quote(event.event_id) << ",\"file_record_id\":" << opt_quote(event.file_record_id)
         << ",\"event_type\":" << quote(event.event_type) << ",\"occurred_at\":" << quote(event.occurred_at)
         << ",\"path\":" << quote(event.path) << ",\"source\":" << quote(event.source) << '}';
  }
  json << "],\"parser_warnings\":[";
  for (std::size_t index = 0; index < output.parser_warnings.size(); ++index) {
    if (index) json << ',';
    json << quote(output.parser_warnings[index]);
  }
  json << "]}";
  return json.str();
}

}  // namespace forensicfs
