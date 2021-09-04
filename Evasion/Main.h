/**
	Daniel Zajork - @danzajork

	Evasion works to bypass antivirus software using a number of different techniques.
	* Payload encryption
	* In memory loading of a packed executable (no files dropped to disk)
	* Process hollowing

	Use evasion_cryptor.py to encrypt the PE file to be executed.

	NOTE:
	Compile with flag /Zc:threadSafeInit-
	source: https://github.com/fancycode/MemoryModule/issues/31
**/
#pragma once


