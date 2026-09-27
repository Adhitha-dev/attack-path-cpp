#include <iostream>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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
  void addNode(const std::string &id, const std::string &name, NodeType type) {
    nodes[id] = {id, name, type};
    if (adjList.find(id) == adjList.end()) {
      adjList[id] = std::vector<Edge>();
    }
  }

  void addEdge(const std::string &sourceId, const std::string &targetId,
               EdgeType type, int weight = 1) {
    adjList[sourceId].push_back({targetId, type, weight});
  }

  void calculateBlastRadius(const std::string &startNodeId) {
    if (nodes.find(startNodeId) == nodes.end()) {
      std::cout << "Error: Start node not found or is invalid." << std::endl;
      return;
    }

    std::unordered_set<std::string> visited;
    std::queue<std::string> q;

    q.push(startNodeId);
    visited.insert(startNodeId);

    std::cout << "[+] Calculating Blast Radius for: " << nodes[startNodeId].name
              << std::endl;

    while (!q.empty()) {
      std::string currentId = q.front();
      q.pop();

      if (currentId != startNodeId) {
        std::cout << " Compromised: " << nodes[currentId].name << " ("
                  << currentId << ")" << std::endl;
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
  std::vector<std::string> findAttackPath(const std::string &sourceId,
                                          const std::string &targetId);
  void printGraph() {
    std::cout << "------- OUTBREAK REPORT ------" << std::endl;
    for (const auto &pair : adjList) {
      const std::string &sourceId = pair.first;
      const std::vector<Edge> &edges = pair.second;

      std::cout << "Node: " << nodes[sourceId].name << " (" << sourceId << ")"
                << std::endl;

      for (const Edge &edge : edges) {
        std::string edgeTypeName;
        switch (edge.type) {
        case EdgeType::CAN_EXECUTE:
          edgeTypeName = "CAN_EXECUTE";
          break;
        case EdgeType::CAN_WRITE:
          edgeTypeName = "CAN_WRITE";
          break;
        case EdgeType::CAN_READ:
          edgeTypeName = "CAN_READ";
          break;
        case EdgeType::OWNS:
          edgeTypeName = "OWNS";
          break;
        case EdgeType::MEMBER_OF:
          edgeTypeName = "MEMBER_OF";
          break;
        }

        std::cout << " --[" << edgeTypeName << "]--> "
                  << nodes[edge.targetNodeId].name << " (" << edge.targetNodeId
                  << ")" << std::endl;
      }
    }
    std::cout << "-----------------------" << std::endl;
  }
};

int main() {
  PermissionGraph graph;

  graph.addNode("u:guest", "guest", NodeType::USER);
  graph.addNode("g:dev", "dev", NodeType::GROUP);
  graph.addNode("f:backup.sh", "/opt/scripts/backup.sh", NodeType::FILE_NODE);

  graph.addEdge("u:guest", "g:dev", EdgeType::MEMBER_OF);
  graph.addEdge("g:dev", "f:backup.sh", EdgeType::CAN_WRITE);

  graph.printGraph();
  graph.calculateBlastRadius("u:guest");

  return 0;
}
