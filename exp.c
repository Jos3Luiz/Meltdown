#include <stdio.h>

int lerCache(void) {
    int lixo=10;
    int result;
    int result2;
    void *addr=&lixo;
    /* Compute Greatest Common Divisor using Euclid's Algorithm */
    __asm__ __volatile__ ( 	"rdtsc;"
				"mov %%eax,%0;"
		    		"mov %2, %%rbx;"
				"mov (%%rbx),%%rcx;"
				"rdtsc;"
				
				
                          	"mov %%eax, %1;" : "=g" (result),"=g"(result2) : "g" (addr)
    );
    printf("resultaio=0x%16X\n",result);
    printf("resultaio=0x%16X\n",result2);

    return result ;
}

int main() {
    int first, second ;
    //printf( "Enter two integers : " ) ;
    //scanf( "%d%d", &first, &second );

    //printf( "GCD of %d & %d is %d\n", first, second, gcd(first, second) ) ;
    lerCache();
    return 0 ;
}
