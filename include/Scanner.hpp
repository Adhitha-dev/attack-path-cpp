#pragma once
#include "PermissionGraph.hpp"
#include <string>

void scanRealDirectory(const std::string &directoryPath, PermissionGraph &graph);
