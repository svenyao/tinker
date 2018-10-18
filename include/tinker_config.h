//
// Created by sven on 6/6/17.
//

#ifndef TINKER_CONFIG_H
#define TINKER_CONFIG_H

#ifdef _WIN32
#ifdef TINKER_EXPORTS
#	ifndef TINKER_API_STATIC
#	define	TINKER_API	__declspec(dllexport)
#	else
#	define TINKER_API
#	endif
#else
#	ifndef TINKER_API_STATIC
#	define	TINKER_API	__declspec(dllimport)
#	else
#	define TINKER_API
#	endif
#endif	// end TINKER_EXPORTS
#else
#	define	TINKER_API
#endif	// end _win32

#endif //TINKER_CONFIG_H
