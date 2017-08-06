#pragma once

#include <string>
#include <vector>

namespace Util
{
	class Directory
	{
	public:
		static void Create(const std::string& dirPath);
		static bool Exists(const std::string& dirPath);
		static std::vector<std::string> GetFileNames(std::string dirPath);
	};
}