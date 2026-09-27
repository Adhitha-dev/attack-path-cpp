#include "PermissionGraph.hpp"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <queue>

void PermissionGraph::addNode(const std::string &id, const std::string &name, NodeType type) {
  nodes[id] = {id, name, type};
  if (adjList.find(id) == adjList.end()) {
    adjList[id] = std::vector<Edge>();
  }
}

void PermissionGraph::addEdge(const std::string &sourceId, const std::string &targetId, EdgeType type, int weight) {
  adjList[sourceId].push_back({targetId, type, weight});
}

void PermissionGraph::calculateBlastRadius(const std::string &startNodeId) {
  if (nodes.find(startNodeId) == nodes.end()) {
    std::cout << "Error: Start node not found or is invalid." << std::endl;
    return;
  }
  std::unordered_set<std::string> visited;
  std::queue<std::string> q;
  q.push(startNodeId);
  visited.insert(startNodeId);
  std::cout << "[+] Calculating Blast Radius for: " << nodes[startNodeId].name << std::endl;
  while (!q.empty()) {
    std::string currentId = q.front();
    q.pop();
    if (currentId != startNodeId) {
      std::cout << " Compromised: " << nodes[currentId].name << " (" << currentId << ")" << std::endl;
    }
    for (const Edge &edge : adjList[currentId]) {
      if (visited.find(edge.targetNodeId) == visited.end()) {
        visited.insert(edge.targetNodeId);
        q.push(edge.targetNodeId);
      }
    }
  }
  std::cout << " ------ End of Radius." << std::endl;
}

std::vector<std::string> PermissionGraph::findAttackPath(const std::string &sourceId, const std::string &targetId) {
  if (nodes.find(sourceId) == nodes.end() || nodes.find(targetId) == nodes.end()) {
    std::cout << "Error: Source or Target nodes not found." << std::endl;
    return {};
  }
  std::unordered_map<std::string, std::string> parent;
  std::unordered_set<std::string> visited;
  std::queue<std::string> q;
  q.push(sourceId);
  visited.insert(sourceId);
  parent[sourceId] = "";
  bool found = false;
  while (!q.empty()) {
    std::string currentId = q.front();
    q.pop();
    if (currentId == targetId) {
      found = true;
      break;
    }
    for (const Edge &edge : adjList[currentId]) {
      if (visited.find(edge.targetNodeId) == visited.end()) {
        visited.insert(edge.targetNodeId);
        q.push(edge.targetNodeId);
        parent[edge.targetNodeId] = currentId;
      }
    }
  }
  if (!found) {
    std::cout << "No Attack path exists between " << nodes[sourceId].name << " and " << nodes[targetId].name << std::endl;
    return {};
  }
  std::vector<std::string> path;
  std::string current = targetId;
  while (current != "") {
    path.push_back(current);
    current = parent[current];
  }
  std::reverse(path.begin(), path.end());
  return path;
}

void PermissionGraph::printGraph() {
  std::cout << "------- OUTBREAK REPORT ------" << std::endl;
  for (const auto &pair : adjList) {
    const std::string &sourceId = pair.first;
    const std::vector<Edge> &edges = pair.second;
    std::cout << "Node: " << nodes[sourceId].name << " (" << sourceId << ")" << std::endl;
    for (const Edge &edge : edges) {
      std::string edgeTypeName;
      switch (edge.type) {
      case EdgeType::CAN_EXECUTE: edgeTypeName = "CAN_EXECUTE"; break;
      case EdgeType::CAN_WRITE: edgeTypeName = "CAN_WRITE"; break;
      case EdgeType::CAN_READ: edgeTypeName = "CAN_READ"; break;
      case EdgeType::OWNS: edgeTypeName = "OWNS"; break;
      case EdgeType::MEMBER_OF: edgeTypeName = "MEMBER_OF"; break;
      }
      std::cout << " --[" << edgeTypeName << "]--> " << nodes[edge.targetNodeId].name << " (" << edge.targetNodeId << ")" << std::endl;
    }
  }
  std::cout << "-----------------------" << std::endl;
}

void PermissionGraph::exportToDOT(const std::string& filename) {
  std::ofstream out(filename);
  if (!out.is_open()) return;
  out << "digraph PermissionGraph {\n";
  out << "  rankdir=LR;\n";
  for (const auto& pair : nodes) {
      const Node& n = pair.second;
      std::string shape = "ellipse";
      if (n.type == NodeType::GROUP) shape = "diamond";
      else if (n.type == NodeType::FILE_NODE) shape = "box";
      else if (n.type == NodeType::DIRECTORY) shape = "folder";
      out << "  \"" << n.id << "\" [label=\"" << n.name << "\", shape=" << shape << "];\n";
  }
  for (const auto& pair : adjList) {
      const std::string& src = pair.first;
      for (const Edge& edge : pair.second) {
          std::string label;
          std::string color = "black";
          switch(edge.type) {
              case EdgeType::MEMBER_OF: label = "MEMBER_OF"; color = "blue"; break;
              case EdgeType::OWNS: label = "OWNS"; color = "green"; break;
              case EdgeType::CAN_READ: label = "CAN_READ"; color = "gray"; break;
              case EdgeType::CAN_WRITE: label = "CAN_WRITE"; color = "red"; break;
              case EdgeType::CAN_EXECUTE: label = "CAN_EXECUTE"; color = "orange"; break;
          }
          out << "  \"" << src << "\" -> \"" << edge.targetNodeId << "\" [label=\"" << label << "\", color=\"" << color << "\", fontsize=10];\n";
      }
  }
  out << "}\n";
  out.close();
}

bool PermissionGraph::isEmpty() const {
  return adjList.empty();
}

void PermissionGraph::saveSnapshot(const std::string& filename) {
  std::ofstream out(filename);
  if (!out.is_open()) return;
  for (const auto& pair : nodes) {
      out << "N," << pair.second.id << "," << pair.second.name << "," << static_cast<int>(pair.second.type) << "\n";
  }
  for (const auto& pair : adjList) {
      for (const Edge& edge : pair.second) {
          out << "E," << pair.first << "," << edge.targetNodeId << "," << static_cast<int>(edge.type) << "\n";
      }
  }
  out.close();
}

void PermissionGraph::loadSnapshot(const std::string& filename) {
  std::ifstream in(filename);
  if (!in.is_open()) return;
  std::string line;
  while (std::getline(in, line)) {
      if (line.empty()) continue;
      if (line[0] == 'N') {
          size_t p1 = line.find(',', 2);
          size_t p2 = line.rfind(',');
          if (p1 == std::string::npos || p2 == std::string::npos) continue;
          std::string id = line.substr(2, p1 - 2);
          std::string name = line.substr(p1 + 1, p2 - p1 - 1);
          int type = std::stoi(line.substr(p2 + 1));
          addNode(id, name, static_cast<NodeType>(type));
      } else if (line[0] == 'E') {
          size_t p1 = line.find(',', 2);
          size_t p2 = line.rfind(',');
          if (p1 == std::string::npos || p2 == std::string::npos) continue;
          std::string src = line.substr(2, p1 - 2);
          std::string tgt = line.substr(p1 + 1, p2 - p1 - 1);
          int type = std::stoi(line.substr(p2 + 1));
          addEdge(src, tgt, static_cast<EdgeType>(type));
      }
  }
  in.close();
}

void PermissionGraph::compareWith(const PermissionGraph& oldGraph) {
  std::cout << "\n=== SECURITY DELTA REPORT ===\n";
  bool changes = false;
  for (const auto& pair : adjList) {
      const std::string& src = pair.first;
      for (const Edge& newEdge : pair.second) {
          bool found = false;
          if (oldGraph.adjList.find(src) != oldGraph.adjList.end()) {
              for (const Edge& oldEdge : oldGraph.adjList.at(src)) {
                  if (oldEdge.targetNodeId == newEdge.targetNodeId && oldEdge.type == newEdge.type) {
                      found = true;
                      break;
                  }
              }
          }
          if (!found) {
              std::string threatLevel = "LOW";
              std::string reason = "";
              if (src == "u:ANYONE" && newEdge.type == EdgeType::CAN_WRITE) {
                  threatLevel = "CRITICAL";
                  reason = "World-Writable! Any rogue user or guest can maliciously modify this file.";
              }
              else if (src == "u:ANYONE" && newEdge.type == EdgeType::CAN_EXECUTE && newEdge.targetNodeId.find(".sh") != std::string::npos) {
                  threatLevel = "HIGH";
                  reason = "World-Executable Script! Anyone can run this script, which could lead to arbitrary code execution.";
              }
              else if (src == "u:root" && newEdge.type == EdgeType::OWNS) {
                  threatLevel = "MEDIUM";
                  reason = "Root took ownership. Ensure this wasn't an unintended privilege escalation.";
              }
              if (threatLevel != "LOW") {
                  std::cout << "[ " << threatLevel << " THREAT ]\n";
                  std::cout << " -> Entity : " << src << "\n";
                  std::cout << " -> Target : " << newEdge.targetNodeId << "\n";
                  std::cout << " -> Risk   : " << reason << "\n\n";
                  changes = true;
              }
          }
      }
  }
  if (!changes) std::cout << "[-] No dangerous permission changes detected.\n";
}
