#include "PermissionGraph.hpp"
#include "Scanner.hpp"
#include <iostream>

int main() {
  std::string snapshotFile = "/home/dew/projects/spl_proj/snapshot.csv";
  
  PermissionGraph oldGraph;
  oldGraph.loadSnapshot(snapshotFile);
  
  PermissionGraph newGraph;
  scanRealDirectory(".", newGraph);
  
  if (!oldGraph.isEmpty()) {
      newGraph.compareWith(oldGraph);
  } else {
      std::cout << "\n[i] No baseline found. Creating new baseline snapshot.\n";
  }
  
  newGraph.saveSnapshot(snapshotFile);
  newGraph.exportToDOT("/home/dew/projects/spl_proj/outbreak_map.dot");
  
  return 0;
}
