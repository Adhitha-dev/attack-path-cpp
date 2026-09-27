#include "Scanner.hpp"
#include <iostream>
#include <filesystem>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

namespace fs = std::filesystem;

void scanRealDirectory(const std::string &directoryPath, PermissionGraph &graph) {
  std::cout << "[+] Scanning real directory: " << directoryPath << std::endl;
  std::string anyoneId = "u:ANYONE";
  graph.addNode(anyoneId, "World/Others", NodeType::USER);

  auto it = fs::recursive_directory_iterator(directoryPath);
  for (auto end = fs::recursive_directory_iterator(); it != end; ++it) {
    const auto &entry = *it;
    std::string filename = entry.path().filename().string();

    if (!filename.empty() && filename[0] == '.') {
        if (entry.is_directory()) {
            it.disable_recursion_pending();
        }
        continue;
    }

    std::string filePath = entry.path().string();
    NodeType nType = entry.is_directory() ? NodeType::DIRECTORY : NodeType::FILE_NODE;
    graph.addNode("f:" + filePath, filePath, nType);

    struct stat fileStat;
    if (stat(filePath.c_str(), &fileStat) == 0) {
      struct passwd *pw = getpwuid(fileStat.st_uid);
      std::string ownerName = pw ? pw->pw_name : std::to_string(fileStat.st_uid);
      std::string ownerId = "u:" + ownerName;

      graph.addNode(ownerId, ownerName, NodeType::USER);
      graph.addEdge(ownerId, "f:" + filePath, EdgeType::OWNS);

      struct group *gr = getgrgid(fileStat.st_gid);
      std::string groupName = gr ? gr->gr_name : std::to_string(fileStat.st_gid);
      std::string groupId = "g:" + groupName;

      graph.addNode(groupId, groupName, NodeType::GROUP);

      fs::perms p = entry.status().permissions();

      if ((p & fs::perms::owner_read) != fs::perms::none) graph.addEdge(ownerId, "f:" + filePath, EdgeType::CAN_READ);
      if ((p & fs::perms::owner_write) != fs::perms::none) graph.addEdge(ownerId, "f:" + filePath, EdgeType::CAN_WRITE);
      if ((p & fs::perms::owner_exec) != fs::perms::none) graph.addEdge(ownerId, "f:" + filePath, EdgeType::CAN_EXECUTE);

      if ((p & fs::perms::group_read) != fs::perms::none) graph.addEdge(groupId, "f:" + filePath, EdgeType::CAN_READ);
      if ((p & fs::perms::group_write) != fs::perms::none) graph.addEdge(groupId, "f:" + filePath, EdgeType::CAN_WRITE);
      if ((p & fs::perms::group_exec) != fs::perms::none) graph.addEdge(groupId, "f:" + filePath, EdgeType::CAN_EXECUTE);

      if ((p & fs::perms::others_read) != fs::perms::none) graph.addEdge(anyoneId, "f:" + filePath, EdgeType::CAN_READ);
      if ((p & fs::perms::others_write) != fs::perms::none) graph.addEdge(anyoneId, "f:" + filePath, EdgeType::CAN_WRITE);
      if ((p & fs::perms::others_exec) != fs::perms::none) graph.addEdge(anyoneId, "f:" + filePath, EdgeType::CAN_EXECUTE);
    }
  }
}
