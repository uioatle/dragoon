#include "directory.h"
#include "common.h"
#include <Windows.h>

namespace Util
{
	void Directory::Create(const std::string& dirPath)
	{
		if (!CreateDirectoryA(dirPath.c_str(), NULL))
		{
			UTIL_THROW_WIN32("CreateDirectory failed");
		}
	}

	bool Directory::Exists(const std::string& dirPath)
	{
		const DWORD fileAttrs = GetFileAttributesA(dirPath.c_str());

		if (fileAttrs == INVALID_FILE_ATTRIBUTES)
		{
			UTIL_THROW_WIN32("GetFileAttributes failed");
		}

		return fileAttrs & FILE_ATTRIBUTE_DIRECTORY;
	}

	/*
	 * Returns all file names in the given directory. Does not include other directory names, only file names.
	 * Credit herohuyongtao (http://stackoverflow.com/questions/612097/how-can-i-get-the-list-of-files-in-a-directory-using-c-or-c).
	 */
	std::vector<std::string> Directory::GetFileNames(std::string dirPath)
	{
		if (!Exists(dirPath))
		{
			throw std::exception("Directory does not exist");
		}

		// Remove trailing slash (if any exists).
		const auto lastChar = dirPath[dirPath.size() - 1];
		if (lastChar == '\\' || lastChar == '/')
		{
			dirPath.pop_back();
		}

		// Scan directory for files.
		std::vector<std::string> fileNames;
		std::string searchPath = dirPath + "/*.*";

		WIN32_FIND_DATA searchData;
		HANDLE hSearch = FindFirstFile((LPCWSTR)searchPath.c_str(), &searchData);

		if (hSearch != INVALID_HANDLE_VALUE)
		{
			do
			{
				// Don't include folders.
				if (!(searchData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				{
					const std::wstring unicodeFileName = searchData.cFileName;
					const std::string ansiFileName(unicodeFileName.begin(), unicodeFileName.end());
					fileNames.push_back(ansiFileName);
				}
			} while (FindNextFile(hSearch, &searchData));

			FindClose(hSearch);
		}

		return fileNames;
	}
}