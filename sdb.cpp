#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <libgen.h>
#include "elftool.h"

#include <string>
#include <map>
#define	PEEKSIZE	8

using namespace std;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

typedef struct range_s {
	unsigned long begin, end;
}	range_t;

typedef struct map_entry_s {
	range_t range;
	int perm;
	long offset;
	std::string name;
}	map_entry_t;

bool operator<(range_t r1, range_t r2) {
	if(r1.begin < r2.begin && r1.end < r2.end) return true;
	return false;
}

unsigned long long strtonum (char* str){
    unsigned long long ret;
    
    if(strstr(str, "0x") != NULL){
        sscanf(str, "%llx", &ret);
    }
        
    else
        ret = atoll(str);
    
    return ret;
} 

void cmddetect(char*);
int load(char*);
void elfquit();
void vmmap(int);
void get(char*);
void getregs(void);
void setregs(char*, unsigned long long);
void dump(unsigned long long);
void print_dump(void);
void disasm(unsigned long long);
unsigned long long checkoffset(char*);
void con(void);

int state = -1;// -1 not loaded, 0 loaded, 1 started
char path[50] = "";
char cmd[10] = "";
char l_name[50] = "";
char r_name[10] = "";
unsigned long long start_rip;
unsigned long long last_dump_addr = 0;
int status;
pid_t child;
struct user_regs_struct regs;
elf_handle_t *eh = NULL;
elf_strtab_t *tab = NULL;

int b_idx = 0;
unsigned long long b_addr[100] = {0};
long b_temp[100] = {0};
bool b_flag = 0;
int b_tempidx = 0;
struct user_regs_struct b_reg;


class instruction1 {
public:
	unsigned char bytes[16];
	int size;
	string opr, opnd;
};
static csh cshandle = 0;
static map<long long, instruction1> instructions;


int main(int argc, char* argv[]){

    if(argc > 1){
        strcpy(l_name, argv[1]);
        load(l_name);
    }
    
    while(1){
        printf("sdb> ");
        scanf( "%s", cmd );
        cmddetect(cmd);
    }
    return 0;
}

void cmddetect(char* cmd){
    
    if(strcmp(cmd,"break") == 0 || strcmp(cmd,"b") == 0){
        if(state < 0){
            printf("** not loaded.\n");
        }
        else{
            char buf[40] = "";
            unsigned long long addr;
            fgets(buf, sizeof(buf), stdin);
            if(strlen(buf) <= 1) printf("** no addr is given.\n");
            else{
                sscanf(buf, "%llx", &addr);
                b_addr[b_idx] = addr;
                long val = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
                unsigned char *ptr = (unsigned char *) &val;
                b_temp[b_idx] = ptr[0];
                ptr[0] = 0xcc;
                ptrace(PTRACE_POKETEXT, child, addr, val);
                b_idx++;
            }
        }
    }

    else if(strcmp(cmd,"cont") == 0 || strcmp(cmd,"c") == 0){
        if(state < 0){
            printf("** not loaded.\n");
        }
        else if(state == 0){
            printf("** not started.\n");
        }
        else{
            con();
        }
    }

    else if(strcmp(cmd,"delete") == 0){
        int n;
        char buf[40] = "";
        fgets(buf, sizeof(buf), stdin);
        if(strlen(buf) <= 1) printf("** no breakpoint number is given.\n");
        else{
            sscanf(buf, "%d", &n);
            if(b_addr[n] != 0){
                long val = ptrace(PTRACE_PEEKTEXT, child, b_addr[n], 0);
                unsigned char *ptr = (unsigned char *) &val;
                ptr[0] = b_temp[n];
                ptrace(PTRACE_POKETEXT, child, b_addr[n], val);
                b_idx--;
                printf("** breakpoint %d deleted.\n", n);
                
                if( b_addr[n+1] == 0){
                    b_addr[n] = 0;
                    b_temp[n] = 0;
                }
                else{
                    while(b_addr[n+1] != 0){
                    b_addr[n] = b_addr[n+1];
                    b_addr[n+1] = 0;
                    b_temp[n] = b_temp[n+1];
                    b_temp[n+1] = 0;
                    n++;
                    }
                }
            }    
        }
    }

    else if(strcmp(cmd,"disasm") == 0 || strcmp(cmd,"d") == 0){
        if(state < 0){
            printf("** not loaded.\n");
        }
        else{
            if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK){
                perror("cs_open\n");
                return;
            }
            unsigned long long addr = 0LL;
            char buf[40] = "";
            fgets(buf, sizeof(buf), stdin);
            if(strlen(buf) <= 1) printf("** no addr is given.\n");
            else{
                sscanf(buf, "%llx", &addr);
                disasm(addr);
            }
            cs_close(&cshandle);
        }
    }
    
    else if(strcmp(cmd,"dump") == 0 || strcmp(cmd,"x") == 0){
        if(state < 0){
            printf("** not loaded.\n");
        }
        else if(state == 0){
            printf("** not started.\n");
        }
        else{
            unsigned long long addr = 0LL;
            char buf[40] = "";
            if(fgets(buf, sizeof(buf) , stdin) != NULL) {
                sscanf(buf, "%llx", &addr);
                dump(addr);
            }   
            else dump(0);
        }
    }

    else if(strcmp(cmd,"exit") == 0 || strcmp(cmd,"q") == 0){
        elfquit();
        exit(0);
    }

    else if(strcmp(cmd,"get") == 0 || strcmp(cmd,"g") == 0){
        if(state < 0){
            printf("** not loaded.\n");
        }
        else if(state == 0){
            printf("** not started.\n");
        }
        else{
            scanf( "%s", r_name );
            get(r_name);
        }
    }

    else if(strcmp(cmd,"getregs") == 0){
        if(state < 0){
            printf("** not loaded.\n");
        }
        else if(state == 0){
            printf("** not started.\n");
        }
        else{
            getregs();
        }
    }

    else if(strcmp(cmd,"help") == 0 || strcmp(cmd,"h")  == 0){
        printf("- break {instruction-address}: add a break point\n");
        printf("- cont: continue execution\n");
        printf("- delete {break-point-id}: remove a break point\n");
        printf("- disasm addr: disassemble instructions in a file or a memory region\n");
        printf("- dump addr [length]: dump memory content\n");
        printf("- exit: terminate the debugger\n");
        printf("- get reg: get a single value from a register\n");
        printf("- getregs: show registers\n");
        printf("- help: show this message\n");
        printf("- list: list break points\n");
        printf("- load {path/to/a/program}: load a program\n");
        printf("- run: run the program\n");
        printf("- vmmap: show memory layout\n");
        printf("- set reg val: get a single value to a register\n");
        printf("- si: step into instruction\n");
        printf("- start: start the program and stop at the first instruction\n");
    }

    else if(strcmp(cmd,"list") == 0 || strcmp(cmd,"l")  == 0){
        int i = 0;
        while(b_addr[i] != 0){
            printf("%d: %llx\n", i, b_addr[i]);
            i++;
        }
    }

    else if(strcmp(cmd,"load") == 0){
        if(state > -1){
            printf("** already loaded.\n");
        }
        else{
            scanf( "%s", l_name );
            load(l_name);
        }
    }

    else if(strcmp(cmd,"run") == 0){
        if(state < 0){
            printf("** not loaded.\n");
        }
        else if(state > 0){
            printf("** program %s is already running.\n", l_name);
            con();
        }
        else{
            printf("** pid %d\n", child);
            state = 1;
            con();
        }
    }

    else if(strcmp(cmd,"vmmap") == 0 || strcmp(cmd,"m")  == 0){
        if(state < 0){
            printf("** not loaded.\n");
        }
        else{
            vmmap(state);
        }
    }

    else if(strcmp(cmd,"set") == 0 || strcmp(cmd,"s")  == 0){
        char buf[40] = "";
        char reg[10];
        char sval[20];
        unsigned long long val;
        if(state < 0){
            printf("** not loaded.\n");
        }
        else if(state == 0){
            printf("** not started.\n");
        }
        else{
            getchar();
            fgets(buf, sizeof(buf) , stdin);
            sscanf(buf, "%s %s", reg, sval);
            val = strtonum(sval);
            //printf("%s %llx\n", reg, val);

            setregs(reg, val);
        }
    }

    else if(strcmp(cmd,"si") == 0){
        ptrace(PTRACE_SINGLESTEP, child, 0, 0);
    }

    else if(strcmp(cmd,"start") == 0){
        if(state < 0){
            printf("** not loaded.\n");
        }
        else if(state > 0){
            printf("** already started.\n");
        }
        else{
            printf("** pid %d\n", child);
            state = 1;
        }
    }

    else{
        printf("** invalid command.\n");
    }
}

int load(char* arg){
    if(arg[0] != '/'){
        getcwd(path, sizeof(path));
        strcat(path, "/");
    }
    strcat(path, arg);
    char *_argv[] = { NULL };
    if((child = fork()) < 0) errquit("fork");
    if(child == 0){
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
        execvp(path, _argv);
        errquit("execvp");
    }
    else{
        unsigned long long rip;
        struct user_regs_struct regs;

        elf_init();
        if((eh = elf_open(path)) == NULL) {
		    fprintf(stderr, "** Unable to open '%s'.\n", path);
		    return -1;
	    }

        if(elf_load_all(eh) < 0) {
		    fprintf(stderr, "** unable to load '%s.\n", path);
		    elfquit();
            return -1;
	    }

        for(tab = eh->strtab; tab != NULL; tab = tab->next) {
		    if(tab->id == eh->shstrndx) break;
	    }

	    if(tab == NULL) {
		    fprintf(stderr, "** section header string table not found.\n");
		    elfquit();
            return -1;
	    }

        if(waitpid(child, &status, 0) < 0) errquit("waitpid");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
			rip = regs.rip;
        }

        printf("** program '%s' loaded. entry point 0x%llx, vaddr 0x%llx, offset 0x%llx, size 0x%llx\n",
            path, rip, eh->shdr[1].addr, eh->shdr[1].offset, eh->shdr[1].size);
        
        start_rip = ptrace(PTRACE_PEEKUSER, child, ((unsigned char *) &regs.rip) - ((unsigned char *) &regs));
    }

    state = 0;
    return 0;
}

void elfquit(){
    if(eh) {
		elf_close(eh);
		eh = NULL;
	}
}

void vmmap(int f){
    if(f == 0){
        printf("%016llx-%016llx r-w %-6llx       %s\n", eh->shdr[1].addr, (eh->shdr[1].addr + eh->shdr[1].size), eh->shdr[1].offset, l_name);
    }
    else{
        FILE *file;
        char vmpath[50] = "/proc/";
        char child_str[10];
        sprintf(child_str, "%d", child);
        strcat(vmpath, child_str);
        strcat(vmpath, "/maps");
        
        if( (file = fopen( vmpath, "r")) == NULL ){
            printf("** open failure.");
        }
        
        char buffer[50] = "";
        while((fscanf(file, "%s", buffer)) != EOF){
            char addr1[17]= {0};
            char addr2[17]= {0};
            unsigned long long adr1 = 0;
            unsigned long long adr2 = 0;
            int i = 0;
            int k = 0;
            int f = 0;
            
            while(buffer[i] != '\0'){
                if(buffer[i] == '-'){
                    f = 1;
                    i++;
                    continue;
                }
                if(f == 0){
                    addr1[i] = buffer[i];
                    i++;
                }
                else{
                    addr2[k] = buffer[i];
                    i++;
                    k++;
                } 
            }
            
            adr1 = (unsigned long long)strtol(addr1, NULL, 16);
            adr2 = (unsigned long long)strtol(addr2, NULL, 16);

            char per[5] = {0};
            fscanf(file, "%s", per);
            per[3]='\0';

            char offs[10] = {0};
            fscanf(file, "%s", offs);
            int offi = (int)strtol(offs, NULL, 16);

            fscanf(file, "%s", buffer);
            fscanf(file, "%s", buffer);
            
            char pathn[50] = {0};
            fscanf(file, "%s", pathn);

            printf("%016llx-%016llx %s %-6x       %s\n", adr1, adr2, per, offi, pathn);
        }
        

        fclose(file);
    }  
}

void getregs(void){
    ptrace( PTRACE_GETREGS, child, NULL, &regs );
    printf("RAX %llx    RBX %llx    RCX %llx    RDX %llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
    printf("R8  %llx    R9  %llx    R10 %llx    R11 %llx\n", regs.r8, regs.r9, regs.r10, regs.r11);
    printf("R12 %llx    R13 %llx    R14 %llx    R15 %llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
    printf("RDI %llx    RSI %llx    RBP %llx    RSP %llx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
    printf("RIP %llx    FLAGS %016llx\n", regs.rip, regs.eflags);
}

void get(char* r){
    unsigned long long offset = checkoffset(r);
    if(offset == 0xffffffffffffffff){
        printf("** invalid register name\n");
        return;
    }
    unsigned long long val = ptrace( PTRACE_PEEKUSER, child, offset, NULL );
    printf("%s = %lld (0x%llx)\n", r, val, val);
}

void setregs(char* r, unsigned long long val){
    unsigned long long offset = checkoffset(r);
    if(offset == 0xffffffffffffffff){
        printf("** invalid register name\n");
        return;
    }
    if(ptrace(PTRACE_POKEUSER, child, offset, val) != 0){
        perror("PTRACE_POKEUSER.");
    }
}

void dump(unsigned long long addr){
    if(addr != 0){
        last_dump_addr = addr;
        print_dump();
    }
    else{
        if(last_dump_addr == 0){
            last_dump_addr = start_rip;
            print_dump();    
        }
        else
            print_dump();
    }    
}

void print_dump(){
    long long counter = 0LL;
    while (counter < 5){
        long ret = ptrace(PTRACE_PEEKTEXT, child, last_dump_addr, 0);
	    unsigned char *ptr = (unsigned char *) &ret;
        printf("0x%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x",
			last_dump_addr, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);
        long ret2 = ptrace(PTRACE_PEEKTEXT, child, last_dump_addr + 0x8, 0);
        unsigned char *ptr2 = (unsigned char *) &ret2;
        printf(" %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x",
			ptr2[0], ptr2[1], ptr2[2], ptr2[3], ptr2[4], ptr2[5], ptr2[6], ptr2[7]);
                
        printf("\t|");
        for(int i = 0; i < 8; i++){
            if(ptr[i] < 0x20 || ptr[i] > 0x7E){
                printf(".");
            }
            else{
                printf("%c", ptr[i]);
            }
        }
        for(int i = 0; i < 8; i++){
            if(ptr2[i] < 0x20 || ptr2[i] > 0x7E){
            printf(".");
            }
            else{
                printf("%c", ptr2[i]);
            }
        }
        printf("|\n");
        last_dump_addr += 0x10;
        counter++;
    }
}

int load_maps(pid_t pid, map<range_t, map_entry_t>& loaded) {
	char fn[128];
	char buf[256];
	FILE *fp;
	snprintf(fn, sizeof(fn), "/proc/%u/maps", pid);
	if((fp = fopen(fn, "rt")) == NULL) return -1;
	while(fgets(buf, sizeof(buf), fp) != NULL) {
		int nargs = 0;
		char *token, *saveptr, *args[8], *ptr = buf;
		map_entry_t m;
		while(nargs < 8 && (token = strtok_r(ptr, " \t\n\r", &saveptr)) != NULL) {
			args[nargs++] = token;
			ptr = NULL;
		}
		if(nargs < 6) continue;
		if((ptr = strchr(args[0], '-')) != NULL) {
			*ptr = '\0';
			m.range.begin = strtol(args[0], NULL, 16);
			m.range.end = strtol(ptr+1, NULL, 16);
		}
		m.name = basename(args[5]);
		m.perm = 0;
		if(args[1][0] == 'r') m.perm |= 0x04;
		if(args[1][1] == 'w') m.perm |= 0x02;
		if(args[1][2] == 'x') m.perm |= 0x01;
		m.offset = strtol(args[2], NULL, 16);
		//printf("XXX: %lx-%lx %04o %s\n", m.range.begin, m.range.end, m.perm, m.name.c_str());
		loaded[m.range] = m;
	}
	return (int) loaded.size();
}

void print_instruction(long long addr, instruction1 *in, const char *module) {
	int i;
	char bytes[128] = "";
	if(in == NULL) {
		fprintf(stderr, "%llx<%s>:\t<cannot disassemble>\n", addr, module);
	} else {
		for(i = 0; i < in->size; i++) {
			snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
		}
		fprintf(stderr, "%llx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(), in->opnd.c_str());
	}
}

int disassemble(pid_t proc, unsigned long long rip, const char *module) {
	int count;
	char buf[64] = { 0 };
	unsigned long long ptr = rip;
	cs_insn *insn;
	map<long long, instruction1>::iterator mi; // from memory addr to instruction


	if((mi = instructions.find(rip)) != instructions.end()) {
		print_instruction(rip, &mi->second, module);
        
		return mi->second.size;
	}
    
	for(ptr = rip; ptr < rip + sizeof(buf); ptr += PEEKSIZE) {
		long long peek;
		errno = 0;
		peek = ptrace(PTRACE_PEEKTEXT, proc, ptr, NULL);
		if(errno != 0) break;
		memcpy(&buf[ptr-rip], &peek, PEEKSIZE);
	}

	if(ptr == rip)  {
		print_instruction(rip, NULL, module);
		return mi->second.size;
	}

	if((count = cs_disasm(cshandle, (uint8_t*) buf, rip-ptr, rip, 0, &insn)) > 0) {
		int i;
		for(i = 0; i < count; i++) {
			instruction1 in;
			in.size = insn[i].size;
			in.opr  = insn[i].mnemonic;
			in.opnd = insn[i].op_str;
			memcpy(in.bytes, insn[i].bytes, insn[i].size);
			instructions[insn[i].address] = in;
		}
		cs_free(insn, count);
	}
    
	if((mi = instructions.find(rip)) != instructions.end()) {
		print_instruction(rip, &mi->second, module);
	} else {
		print_instruction(rip, NULL, module);
	}
	return mi->second.size;
}

void disasm(unsigned long long addr){
    long long counter = 0LL;
	int wait_status;
    map<range_t, map_entry_t> m;
    map<range_t, map_entry_t>::iterator mi;

    if(load_maps(child, m) > 0) {
#if 0
	    for(mi = m.begin(); mi != m.end(); mi++) {
		    fprintf(stderr, "## %lx-%lx %04o %s\n",
		    mi->second.range.begin, mi->second.range.end,
		    mi->second.perm, mi->second.name.c_str());
	    }
#endif
	}

	while (counter < 10) {
        if( state == 0 && addr >= (start_rip + 0x23))
            break;
	    struct user_regs_struct regs;
		counter++;

        range_t r = { addr, addr };
		mi = m.find(r);
		if(mi == m.end()) {
			m.clear();
			load_maps(child, m);
			fprintf(stderr, "## %zu map entries re-loaded.\n", m.size());
			mi = m.find(r);
		}
		int o = disassemble(child, addr, mi != m.end() ? mi->second.name.c_str() : "unknown");
        addr += o;
	}
}



unsigned long long checkoffset(char* r){
    unsigned long long offset;
    unsigned char* ptr = (unsigned char*) &regs;

    if(strcmp(r,"r15") == 0){
        offset = ((unsigned char*) &regs.r15) - ptr;
    }
    else if(strcmp(r,"r14") == 0){
        offset = ((unsigned char*) &regs.r14) - ptr;
    }
    else if(strcmp(r,"r13") == 0){
        offset = ((unsigned char*) &regs.r13) - ptr;
    }
    else if(strcmp(r,"r12") == 0){
        offset = ((unsigned char*) &regs.r12) - ptr;
    }
    else if(strcmp(r,"rbp") == 0){
        offset = ((unsigned char*) &regs.rbp) - ptr;
    }
    else if(strcmp(r,"rbx") == 0){
        offset = ((unsigned char*) &regs.rbx) - ptr;
    }
    else if(strcmp(r,"r11") == 0){
        offset = ((unsigned char*) &regs.r11) - ptr;
    }
    else if(strcmp(r,"r10") == 0){
        offset = ((unsigned char*) &regs.r10) - ptr;
    }
    else if(strcmp(r,"r9") == 0){
        offset = ((unsigned char*) &regs.r9) - ptr;
    }
    else if(strcmp(r,"r8") == 0){
        offset = ((unsigned char*) &regs.r8) - ptr;
    }
    else if(strcmp(r,"rax") == 0){
        offset = ((unsigned char*) &regs.rax) - ptr;
    }
    else if(strcmp(r,"rcx") == 0){
        offset = ((unsigned char*) &regs.rcx) - ptr;
    }
    else if(strcmp(r,"rdx") == 0){
        offset = ((unsigned char*) &regs.rdx) - ptr;
    }
    else if(strcmp(r,"rsi") == 0){
        offset = ((unsigned char*) &regs.rsi) - ptr;
    }
    else if(strcmp(r,"rdi") == 0){
        offset = ((unsigned char*) &regs.rdi) - ptr;
    }
    else if(strcmp(r,"orig_rax") == 0){
        offset = ((unsigned char*) &regs.orig_rax) - ptr;
    }
    else if(strcmp(r,"rip") == 0){
        offset = ((unsigned char*) &regs.rip) - ptr;
    }
    else if(strcmp(r,"cs") == 0){
        offset = ((unsigned char*) &regs.cs) - ptr;
    }
    else if(strcmp(r,"eflags") == 0){
        offset = ((unsigned char*) &regs.eflags) - ptr;
    }
    else if(strcmp(r,"rsp") == 0){
        offset = ((unsigned char*) &regs.rsp) - ptr;
    }
    else if(strcmp(r,"ss") == 0){
        offset = ((unsigned char*) &regs.ss) - ptr;
    }
    else if(strcmp(r,"fs_base") == 0){
        offset = ((unsigned char*) &regs.fs_base) - ptr;
    }
    else if(strcmp(r,"gs_base") == 0){
        offset = ((unsigned char*) &regs.gs_base) - ptr;
    }
    else if(strcmp(r,"ds") == 0){
        offset = ((unsigned char*) &regs.ds) - ptr;
    }
    else if(strcmp(r,"es") == 0){
        offset = ((unsigned char*) &regs.es) - ptr;
    }
    else if(strcmp(r,"fs") == 0){
        offset = ((unsigned char*) &regs.fs) - ptr;
    }
    else if(strcmp(r,"gs") == 0){
        offset = ((unsigned char*) &regs.gs) - ptr;
    }
    else{
        offset = 0xffffffffffffffff;
    }

    return offset;
}

void con(void){
    char r[5] = "rip";
    char d[5] = "rdx";

    if(b_flag == 1){
        b_reg.rip = b_reg.rip - 1;
        b_reg.rdx = b_reg.rax;
        ptrace(PTRACE_SETREGS, child, 0, &b_reg);

        long val = ptrace(PTRACE_PEEKTEXT, child, b_addr[b_tempidx], 0);
        unsigned char *ptr = (unsigned char *) &val;
        ptr[0] = b_temp[b_tempidx];
        ptrace(PTRACE_POKETEXT, child, b_addr[b_tempidx], val);

        b_flag = 0;
        b_tempidx = 0;
    }

    ptrace(PTRACE_CONT, child, 0, 0);
    waitpid(child, &status, 0);

    if(WIFEXITED(status)){
        printf("** child process %d terminiated normally (code %d)\n", child, WEXITSTATUS(status));
        state = -1;
    }
    else if(WIFSIGNALED(status)){
        printf("** child process %d terminiated abnormally (code %d)\n", child, WTERMSIG(status));
        state = -1;
    }
    else{
        ptrace(PTRACE_GETREGS, child, 0, &b_reg);
        unsigned long long addr = b_reg.rip;
        while(1){
            if(b_addr[b_tempidx] == addr-1){
                break;
            }
            b_tempidx++;
        }
        printf("** breakpoint @    %llx\n", addr-1);
        b_flag = 1;
    }
}