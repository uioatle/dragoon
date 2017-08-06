#include "dragoon.h"
#include "DragoonGlobal\common.h"

#include <iostream>
#include <string>

namespace Dragoon
{
	typedef struct
	{
		std::string targetApplicationPath;
		bool recordFromBeginning;
	} ParsedCommandLineArgs;

	void DisplayUsage()
	{
		// TODO
		std::cout << "USAGE HERE" << std::endl;
	}

	bool ParseCommandLineArgs(const int argc, char** argv, ParsedCommandLineArgs& cmdLineArgs)
	{
		if (argc < 2 || argc > 3)
		{
			DisplayUsage();
			return false;
		}

		cmdLineArgs.targetApplicationPath = argv[1];
		cmdLineArgs.recordFromBeginning = (argc == 3); // argc==2 = false, argc==3 = true
		return true;
	}

	int Main(int argc, char** argv)
	{
		try
		{
			ParsedCommandLineArgs cmdLineArgs;
			if (!ParseCommandLineArgs(argc, argv, cmdLineArgs))
			{
				return -2;
			}

			Start(cmdLineArgs.targetApplicationPath, cmdLineArgs.recordFromBeginning);
			return 0;
		}
		catch (const std::exception& e)
		{
			DragoonGlobal::Logging::Log(std::string("Uncaught exception: ") + e.what());
			std::cout << "A fatal error occurred which forced Dragoon to exit. The incident has been written to the log. Dragoon will now exit..." << std::endl;
			return -1;
		}
	}
}

int main(int argc, char** argv)
{
	// TODO Get rid of this
	argv[1] = "C:/Code/Projects/Dragoon/Release/TestExecutable.exe";
	argv[2] = "<anything>";
	argc = 3; // Remember to update this

	return Dragoon::Main(argc, argv);
}