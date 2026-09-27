# Attack Path Permission Analyzer

A Linux file permission scanner and threat detector built in C++. I built this to learn graph theory properly while also doing something that actually makes sense in the real world.

---

## Why I built this

I was learning DSA and I kept feeling like the problems I was solving (linked lists, sorting arrays) had no connection to anything I actually cared about. I wanted a project where the data structure was the point, not just a means to an end.

File permissions on Linux are basically a graph problem. Users connect to groups, groups connect to files, and permissions are just edges with different types. Once I saw it that way, BFS made total sense. You're just traversing that graph to see how far a compromised user can reach.

---

## What it does

- Scans a directory recursively and builds a directed graph of users, groups, and files based on real Linux permissions using stat(), getpwuid(), and getgrgid()
- Takes a snapshot of the permission graph and saves it to a CSV file
- On the next run, it loads the old snapshot, builds the new graph, and diffs them
- If a new dangerous permission shows up (world-writable file, executable script with open permissions, root taking ownership of something), it flags it with a threat level
- Exports the whole graph to a .dot file so you can visualize it in Graphviz or VS Code

---

## How the graph is structured

Each node is one of four types: USER, GROUP, FILE, or DIRECTORY.

Edges represent POSIX permission relationships:
- OWNS
- MEMBER_OF
- CAN_READ
- CAN_WRITE
- CAN_EXECUTE

The adjacency list is an unordered_map<string, vector<Edge>> which gives O(1) lookup per node. The BFS for blast radius and attack path detection runs in O(V + E).

The snapshot is just the adjacency list serialized to a flat CSV with N (node) and E (edge) rows. Loading it back is a linear scan through the file.

---

## Project structure

```
spl_proj/
├── Makefile
├── README.md
├── include/
│   ├── PermissionGraph.hpp
│   └── Scanner.hpp
└── src/
    ├── main.cpp
    ├── PermissionGraph.cpp
    └── Scanner.cpp
```

PermissionGraph handles everything graph-related: building the graph, running BFS, serializing and deserializing snapshots, and running the diff.

Scanner handles all the Linux-specific OS work. It uses the C++17 filesystem library to walk directories and POSIX headers to read actual permission bits and resolve UIDs/GIDs to names.

main.cpp just connects the two and runs the program.

---

## How to build and run

```bash
make
./scan
```

To test the threat detection manually:

```bash
./scan                               # creates the baseline snapshot
touch backdoor.sh && chmod 777 backdoor.sh
./scan                               # should flag it as CRITICAL/HIGH threat
```

To wipe everything and start fresh:

```bash
make clean
```

---

## Requirements

- g++ with C++17 support
- Linux (uses POSIX headers, won't compile on Windows)

---

## What I want to improve

The snapshot format right now is a plain CSV which works but is fragile. File paths with commas would break the parser. I should probably move to a proper delimiter or use a binary format.

Memory management is something I haven't thought hard about yet. The entire graph sits in memory which is fine for small directories but would probably fall over on something like /usr. I want to look into building the graph in chunks or doing lazy loading at some point.

The heuristic rules in compareWith are hardcoded. A config file that lets you define your own threat rules would make this way more useful.

I also want to eventually add Dijkstra's algorithm so the attack path finder doesn't just find the shortest path by hop count but the easiest path based on how exploitable each permission type is.

---