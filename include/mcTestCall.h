#pragma once

#include <vector>

using ParseFn = bool(*)(const char*, std::vector<unsigned char>&);

int run(int argc, char** argv, int seg_size, ParseFn parser);

