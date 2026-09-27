#include <algorithm>
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
                                          const std::string &targetId) {
    if (nodes.find(sourceId) == nodes.end() ||
        nodes.find(targetId) == nodes.end()) {
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
      std::cout << "No Attack path exists between " << nodes[sourceId].name
                << " and " << nodes[targetId].name << std::endl;
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

void populateDummyEnvironment(PermissionGraph &graph) {
  graph.addNode("u:guest", "Guest User", NodeType::USER);
  graph.addNode("u:intern", "Intern", NodeType::USER);
  graph.addNode("u:www-data", "Web Service", NodeType::USER);
  graph.addNode("u:admin", "System Admin", NodeType::USER);

  graph.addNode("g:staff", "Staff Group", NodeType::GROUP);
  graph.addNode("g:dev", "Developers Group", NodeType::GROUP);
  graph.addNode("g:docker", "Docker Group", NodeType::GROUP);
  graph.addNode("g:wheel", "Sudoers (Wheel)", NodeType::GROUP);

  graph.addNode("f:public_html", "/var/www/html", NodeType::DIRECTORY);
  graph.addNode("f:backup.sh", "/opt/scripts/backup.sh", NodeType::FILE_NODE);
  graph.addNode("f:docker_sock", "/var/run/docker.sock", NodeType::FILE_NODE);
  graph.addNode("f:shadow", "/etc/shadow", NodeType::FILE_NODE);
  graph.addNode("f:ssh_keys", "/root/.ssh/authorized_keys",
                NodeType::FILE_NODE);

  graph.addEdge("u:guest", "g:staff", EdgeType::MEMBER_OF);
  graph.addEdge("u:intern", "g:dev", EdgeType::MEMBER_OF);
  graph.addEdge("u:www-data", "g:staff", EdgeType::MEMBER_OF);
  graph.addEdge("u:admin", "g:wheel", EdgeType::MEMBER_OF);
  graph.addEdge("u:admin", "g:dev", EdgeType::MEMBER_OF);

  graph.addEdge("g:dev", "g:docker",
                EdgeType::MEMBER_OF); // Devs can use docker

  graph.addEdge("g:staff", "f:public_html", EdgeType::CAN_READ);
  graph.addEdge("u:www-data", "f:public_html", EdgeType::OWNS);
  graph.addEdge("g:dev", "f:backup.sh", EdgeType::CAN_WRITE);

  graph.addEdge("g:docker", "f:docker_sock", EdgeType::CAN_WRITE);
  graph.addEdge("f:docker_sock", "f:shadow", EdgeType::CAN_WRITE);
  graph.addEdge("f:docker_sock", "f:ssh_keys", EdgeType::CAN_WRITE);

  graph.addEdge("g:wheel", "f:shadow", EdgeType::CAN_READ);
  graph.addEdge("g:wheel", "f:ssh_keys", EdgeType::CAN_WRITE);
}

int main() {
  PermissionGraph graph;
  populateDummyEnvironment(graph);

  std::cout << "\n=== BLAST RADIUS ANALYSIS ===" << std::endl;
  graph.calculateBlastRadius("u:intern");

  std::cout << "\n=== ATTACK PATH ANALYSIS ===" << std::endl;
  std::vector<std::string> path = graph.findAttackPath("u:intern", "f:shadow");

  if (!path.empty()) {
    std::cout << "CRITICAL VULNERABILITY FOUND! Attack path ("
              << path.size() - 1 << " hops):\n";
    for (size_t i = 0; i < path.size(); ++i) {
      std::cout << path[i];
      if (i != path.size() - 1) {
        std::cout << " -> ";
      }
    }
    std::cout << "\n\n";
  }

  return 0;
}
