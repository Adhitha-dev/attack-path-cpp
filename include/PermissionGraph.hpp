#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <queue>

enum class NodeType { USER, GROUP, FILE_NODE, DIRECTORY };
enum class EdgeType { MEMBER_OF, OWNS, CAN_READ, CAN_WRITE, CAN_EXECUTE };

struct Node {
  std::string id;
  std::string name;
  NodeType type;
};

struct Edge {
  std::string targetNodeId;
  EdgeType type;
  int weight;
};

class PermissionGraph {
private:
  std::unordered_map<std::string, Node> nodes;
  std::unordered_map<std::string, std::vector<Edge>> adjList;

public:
  void addNode(const std::string &id, const std::string &name, NodeType type);
  void addEdge(const std::string &sourceId, const std::string &targetId, EdgeType type, int weight = 1);
  void calculateBlastRadius(const std::string &startNodeId);
  std::vector<std::string> findAttackPath(const std::string &sourceId, const std::string &targetId);
  void printGraph();
  void exportToDOT(const std::string& filename);
  bool isEmpty() const;
  void saveSnapshot(const std::string& filename);
  void loadSnapshot(const std::string& filename);
  void compareWith(const PermissionGraph& oldGraph);
};
