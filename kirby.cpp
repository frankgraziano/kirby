#include <fstream>
#include <iostream>
#include <stdint.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

using namespace std;

typedef uint8_t  Elf32_Char;	// Unsigned char

void print_banner() {
cout << string(50, '\n');
cout <<"  _    _      _             _   _            ______ _      ______ 	"<<endl;
cout <<" | |  (_)    | |           | | | |          |  ____| |    |  ____|	"<<endl;
cout <<" | | ___ _ __| |__  _   _  | |_| |__   ___  | |__  | |    | |__   	"<<endl;
cout <<" | |/ / | '__| '_ \\| | | | | __| '_ \\ / _ \\ |  __| | |    |  __|  	"<<endl;
cout <<" |   <| | |  | |_) | |_| | | |_| | | |  __/ | |____| |____| |     	"<<endl;
cout <<" |_|\\_\\_|_|  |_.__/ \\__, |  \\__|_| |_|\\___| |______|______|_|     	"<<endl;
cout <<"                     __/ |						"<<endl;
cout <<"                    |___/						"<<endl;
cout <<"						┌─┐┌─┐┬─┐┌─┐┌─┐┬─┐	"<<endl;
cout <<"						├─┘├─┤├┬┘└─┐├┤ ├┬┘	"<<endl;
cout <<"						┴  ┴ ┴┴└─└─┘└─┘┴└─ v0.1	"<<endl;
cout <<"									"<<endl;
cout <<"									"<<endl;
}

int elf_check_file(Elf32_Ehdr *hdr) {
	if(!hdr) return 0;
	if(hdr->e_ident[EI_MAG0] != ELFMAG0) {
		cout << "[x] ELF Header EI_MAG0 incorrect.\n";
		return 0;
	}
	if(hdr->e_ident[EI_MAG1] != ELFMAG1) {
		cout << "[x] ELF Header EI_MAG1 incorrect.\n";
		return 0;
	}
	if(hdr->e_ident[EI_MAG2] != ELFMAG2) {
		cout << "[x] ELF Header EI_MAG2 incorrect.\n";
		return 0;
	}
	if(hdr->e_ident[EI_MAG3] != ELFMAG3) {
		cout << "[x] ELF Header EI_MAG3 incorrect.\n";
		return 0;
	}
	cout << "[+] Magic bytes are correct...\n";
	return 1;
}

/* Checks if we support this architecture */
int elf_check_supported(Elf32_Ehdr *hdr) {
        if(!elf_check_file(hdr)) {
                cout <<"[x] Invalid ELF File.\n";
                return 0;
        }
        if(hdr->e_ident[EI_CLASS] != ELFCLASS32) {
                cout <<"[x] Unsupported ELF File Class.\n";
                return 0;
        }
        if(hdr->e_ident[EI_DATA] != ELFDATA2LSB) {
                cout <<"[x] Unsupported ELF File byte order.\n";
                return 0;
        }
        if(hdr->e_machine != EM_386) {
                cout <<"[x] Unsupported ELF File target.\n";
                return 0;
        }
        if(hdr->e_ident[EI_VERSION] != EV_CURRENT) {
                cout <<"[x] Unsupported ELF File version.\n";
                return 0;
        }
        if(hdr->e_type != ET_REL && hdr->e_type != ET_EXEC) {
                cout <<"[x] Unsupported ELF File type.\n";
                return 0;
        }
	cout << "[+] We support this ELF architecture...\n";
        return 1;
}

int ReadAt(int hFile, int pos, void *buf, int count)
{
    if(pos == lseek(hFile, pos, SEEK_SET))
        return read(hFile, buf, count);
    return -1;
}

int WriteAt(int hFile, int pos, void* buf, int count)
{
    if(pos == lseek(hFile, pos, SEEK_SET))
        return write(hFile, buf, count);
    return -1;
}

char *ReadSection(int hFile, Elf32_Ehdr *hdr)
{
	char *pbuf;
	Elf32_Shdr shdr;

	int offset;
	if (hdr->e_shstrndx <0 || hdr->e_shstrndx > hdr->e_shnum)
		return NULL;

	offset = ((hdr->e_shstrndx)*hdr->e_shentsize)+hdr->e_shoff;

    if (sizeof(shdr) != ReadAt(hFile, offset, &shdr, sizeof(shdr)))
        return NULL;

	 pbuf = (char *)malloc(shdr.sh_size);
    if(pbuf != NULL) {
        if(shdr.sh_size == ReadAt(hFile, shdr.sh_offset, pbuf, shdr.sh_size))
            return pbuf;
        free(pbuf);
    }
    return NULL;

}

void printSection(char *fileNameOfElf)
{
    int hFile;
    int offset;
    Elf32_Ehdr ehdr;
    Elf32_Shdr shdr;
    char *strTable;
    strTable = NULL;

    hFile = open(fileNameOfElf, O_RDONLY, 0);
    if(hFile < 0) {
        printf("can not open file:%s\n", fileNameOfElf);
        return;
    }

    if(sizeof(ehdr) != ReadAt(hFile, 0, &ehdr, sizeof(ehdr)))
        goto error;

    if(!elf_check_file(&ehdr) || !elf_check_supported(&ehdr)) {
        goto error;
	}
    if(ehdr.e_shnum <= 0|| ehdr.e_shoff == 0) {
        printf("this ELF have not Section Head Table! \n");
        goto close_file;
    }

    strTable = ReadSection(hFile, &ehdr);
    if(strTable == NULL)
        goto error;

    int i;
    cout << "There are " << ehdr.e_shnum << " Section Headers." <<endl;

    for(i = 0;i < ehdr.e_shnum; i++) {
        if(sizeof(shdr) == ReadAt(hFile,
                    ehdr.e_shoff + i*ehdr.e_shentsize,
                    &shdr,
                    sizeof(shdr))) {
		printf("section name = %s\n"
                    "\tfstart = 0x%x,\tfsize = 0x%x,\tmemstart = 0x%x\n",
                    &strTable[shdr.sh_name],
                    shdr.sh_offset,
                    shdr.sh_size,
                    shdr.sh_addr);
        }
    }

    goto close_file;

error:
    printf("Error reading Section Headers!\n");
close_file:
    if(strTable)
        free(strTable);
	close(hFile);
}

char *readProgram(int hFile, Elf32_Ehdr *hdr)
{
        char *pbuf;
        Elf32_Phdr phdr;
	int idx = 1;
        int offset;

        offset = hdr->e_phoff + hdr->e_phentsize * idx;

    if (sizeof(phdr) != ReadAt(hFile, offset, &phdr, sizeof(phdr)))
        return NULL;

         pbuf = (char *)malloc(phdr.p_filesz);
    if(pbuf != NULL) {
        if(phdr.p_filesz == ReadAt(hFile, phdr.p_offset, pbuf, phdr.p_filesz))
            return pbuf;
        free(pbuf);
    }
    return NULL;

}

void printProgram(char *fileNameOfElf)
{
	int hFile;
    	int offset;
    	Elf32_Ehdr ehdr;
    	Elf32_Phdr phdr;
    	char *segTable;
    	segTable = NULL;

    	hFile = open(fileNameOfElf, O_RDONLY, 0);
    	if(hFile < 0)
	{
        	printf("can not open file:%s\n", fileNameOfElf);
        	goto error;
    	}

    	if(sizeof(ehdr) != ReadAt(hFile, 0, &ehdr, sizeof(ehdr)))
        	goto error;

    	if(ehdr.e_phnum <= 0|| ehdr.e_phoff == 0)
	{
        	printf("This ELF doesn't have a Program Header Table! \n");
        	goto close_file;
	}

	segTable = readProgram(hFile, &ehdr);

	if(segTable == NULL)
        	goto error;

	int i;
	cout << "There are " << ehdr.e_phnum << " Program Headers." <<endl;

    	for(i = 0;i < ehdr.e_phnum; i++)
	{
		if(sizeof(phdr) == ReadAt(hFile, ehdr.e_phoff + i*ehdr.e_phentsize, &phdr, sizeof(phdr)))
		{
			string ph_name = "";
			Elf32_Word type = 0;

			switch (phdr.p_type)
			{
			case 0:
				type = PT_NULL;
				ph_name = "PT_NULL";
				break;
			case 1:
				type = PT_LOAD;
				ph_name = "PT_LOAD";
				break;
			case 2:
				type = PT_DYNAMIC;
				ph_name = "PT_DYNAMIC";
				break;
			case 3:
				type = PT_INTERP;
				ph_name = "PT_INTERP";
				break;
			case 4:
				type = PT_NOTE;
				ph_name = "PT_NOTE";
				break;
			case 5:
				type = PT_SHLIB;
				ph_name = "PT_SHLIB";
				break;
			case 6:
				type = PT_PHDR;
				ph_name = "PT_PHDR";
				break;
			case 7:
				type = PT_TLS;
				ph_name = "PT_TLS";
				break;
			case 8:
				type = PT_NUM;
				ph_name = "PT_NUM";
				break;
			default:
				type = 0;
				ph_name = "Unknown";
				break;
			}

			cout << "Name: " << ph_name
			<< "\tType: 0x" << type
			<< "\tFlags: 0x" << phdr.p_flags
			<< "\tOffset: 0x" << hex <<phdr.p_offset
			<< "\tMemsize: 0x" << phdr.p_memsz
			<< "\tVaddr: 0x" << hex << phdr.p_vaddr 
			<<"\n" << endl;
        	}
    	}
	goto close_file;

error:
    printf("Error Reading Program Headers!\n");
close_file:
    if(segTable)
        free(segTable);
        close(hFile);
}

int main ( int argc, char *argv[] )
{
	if ( argc < 2 )
	{
		cout<<"Normal Mode: "<< argv[0] <<" <filename>\n";
		cout<<"Basic Mode:  "<< argv[0] <<" <filename> -v\n";
	}

else
{
	fstream our_file;
	char *arg1 = argv[1];

/* Ehdr structure pointers */
Elf32_Ehdr elf32_ehdr;
Elf32_Ehdr *pe_elf32;
pe_elf32 = &elf32_ehdr;

our_file.open( argv[1], ios::in|ios::binary);
	if ( our_file.is_open() )
    	{
		string mode = "";
		if (argc == 3)
			mode = argv[2];

		print_banner();
		our_file.read(reinterpret_cast<char *>(&elf32_ehdr), sizeof(Elf32_Ehdr));
		our_file.close();
		cout << "[+] " << argv[1] <<" has been loaded into memory\n";
		if (mode == "-b")
		{
			cout << "\n[------------------ ELF Header -----------------]\n";
			cout << "[*] ELF header is " << pe_elf32->e_ehsize << " bytes.\n"; 
			cout << "[*] Program Entry Point is: 0x" << hex << pe_elf32->e_entry <<"\n";
			cout << "\n[------------------ Program Header -----------------]\n";
			cout << "[*] Program Header count is (Dec): " << dec << pe_elf32->e_phnum <<"\n";
			cout << "[*] Program Header offset is: 0x" << hex << pe_elf32->e_entry + pe_elf32->e_phoff << "\n";
			cout << "[*] Program Header ent size is (Dec): " << dec << pe_elf32->e_phentsize <<" bytes.\n";
			cout << "[*] Program Header total size is (Dec): " << dec << pe_elf32->e_phnum * pe_elf32->e_phentsize <<" bytes.\n";
			cout << "\n[------------------ Section Header -----------------]\n";
			cout << "[*] Section Header count is (Dec): " << dec << pe_elf32->e_shnum <<"\n";
			cout << "[*] Section Header offset is: 0x" << hex << pe_elf32->e_entry + pe_elf32->e_shoff << "\n";
			cout << "[*] Section Header ent size is (Dec): " << dec << pe_elf32->e_shentsize <<" bytes.\n";
                	cout << "[*] Section Header total size is (Dec): " << dec << pe_elf32->e_shnum * pe_elf32->e_shentsize <<" bytes.\n";
			cout << "[*] Section Header Table Index: " << pe_elf32->e_shstrndx <<"\n";
			cout << "\n\n";
		}
		else
		{
		cout << "[*] Dumping ELF Info...\n";
		printSection(arg1);
		cout << "[*] Dumping ELF Info...\n";
                printProgram(arg1);
		}

    	}
	else cout << "Error loading file.\n";
	return 0;
  }
}
