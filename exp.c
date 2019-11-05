#include <stdio.h>

char *probe="OLAMUNDOO";
char *probe2;

int lerCacheNoFlush(void *addr) {
    unsigned long result;
    				/* M 3 l T d 0 w N  - cache+reload */
    __asm__ __volatile__ ( 	
		    		"mfence ;"
				"lfence ;"
		    		"mov %1, %%rbx;"
				"lfence;"

				"rdtsc;"
				"lfence;"
				"shl $32,%%rdx;"
				"mov %%eax,%%edx;"
				"mov %%rdx,%%rcx;"
				"lfence;"

				"mov (%%rbx),%%r9;"
				"lfence;"
				"rdtsc;"
				"lfence;"
				"shl $32,%%rdx;"
				"mov %%eax,%%edx;"
				"sub %%rcx,%%rdx;"
				"mov %%rdx,%0;"
				

				: "=g" (result) : "g" (probe)
    );
    printf("resultado %p :(tempo) 0x%lX  \n",addr,result);

    return result ;
}


int lerCache(void *addr) {
    unsigned long result;
    				/* M 3 l T d 0 w N  - cache+reload */
    __asm__ __volatile__ ( 	
		    		"mfence ;"
				"lfence ;"
		    		"mov %1, %%rbx;"
				"clflush  0(%1);"
				"lfence;"

				"rdtsc;"
				"lfence;"
				"shl $32,%%rdx;"
				"mov %%eax,%%edx;"
				"mov %%rdx,%%rcx;"
				"lfence;"

				"mov (%%rbx),%%r9;"
				"lfence;"
				"rdtsc;"
				"lfence;"
				"shl $32,%%rdx;"
				"mov %%eax,%%edx;"
				"sub %%rcx,%%rdx;"
				"mov %%rdx,%0;"
				

				: "=g" (result) : "g" (probe)
    );
    printf("resultado %p :(tempo) 0x%lX  \n",addr,result);

    return result ;
}

int main() {
    probe2=probe+100000;
    lerCache(probe);
    lerCacheNoFlush(probe);
    lerCacheNoFlush(probe2);
    return 0 ;
}
