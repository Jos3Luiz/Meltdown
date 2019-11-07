#include <stdio.h>
#include <stdlib.h>

#define NUM_ITERACOES 10
#define CACHE_LINE_LEN	128
#define LEN_MEM_ARRAY	50


static inline void Flush(char *);

unsigned GetDS(){
	unsigned ds;
	asm __volatile__(
			"mov %%DS , %0"
			: "=r"(ds) :
			);
	return ds;
}
void PrintLista(int lista[])
{
	printf("Possiveis valores: ");
	for (int i=0; lista[i]!=-1;i++)
	{
		printf(" %i = %c",lista[i],lista[i]);
	}
	printf("\n");
}

char p1[] = 	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";


static inline long ProbeFlush(char *addr) {
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


static inline long Probe(char *addr) {
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

static inline void Flush(char *addr)
{
	asm __volatile__(
			"mfence		;"
			"clflush 0(%0)	;"
			"mfence		;"
			"lfence		;"
			: : "r" (addr)
			);
}





unsigned Treshold(char *baseSrc)
{

	char* base=baseSrc;
	unsigned i=0;
	unsigned j=0;
	unsigned probe;
	unsigned long long totalComFlush=0;
	unsigned long long totalSemFlush=0;
	//Flush(base);
	while (i<NUM_ITERACOES)
	{
		for (j=0;j<255;j++)
		{
		
		
			//Flush(base+j*4096);
			probe=Probe(base+j*4096);
			totalComFlush+=probe;
			//printf("com flush %8X\n",probe);
		
			probe=ProbeFlush(base+j*4096);
			totalSemFlush+=probe;
			i++;
		
			//printf("sem flush %8X\n",probe);
	
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
	register char *inicio=base;
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
	while (i<256)
	{
		
		
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

void fillArrayMemSpace(char *memspace[],char *original[])
{
	//avoid calling clflush all the time.
	char *bufferFill;
	for(int i=0;i<LEN_MEM_ARRAY;i++)
	{
		
		bufferFill=(char *)malloc(4096*256+0xFFFFFF);
		original[i]=bufferFill;
		bufferFill+=0xFFFFFF;
		bufferFill=(char *)((unsigned long)bufferFill & 0xFFFFFFFFF000000);
		memspace[i]=bufferFill;
	}
}

int main(void)
{
	int ret,i;
	int lista[256];
	unsigned treshold;
	char *ptrArray;
	
	char *segredo="isso eh secreto, esse texto eh realmente muito longo. Cuidado com instrucoes especuladas";

	char *memspace[LEN_MEM_ARRAY];
	char *original[LEN_MEM_ARRAY];

	fillArrayMemSpace(memspace,original);

	treshold=Treshold(memspace[0]);
	//treshold=0x300;

	for (i=1;i<LEN_MEM_ARRAY;i++ )
	{
	
		ptrArray=memspace[i];
		ret=*((int *)(ptrArray+(int)segredo[i-1]*4096));
		FindSecretLineCache(ptrArray,treshold,lista);
		PrintLista(lista);
		FlushAll(ptrArray);
		free(original[i]);	

		
	
	}

	//exit friendly
	for (i=0;i< LEN_MEM_ARRAY;i++)
	{
		//free(original[i]);
	}
	return 0;

}


















