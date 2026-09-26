#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>
static int printable(const unsigned char*p,size_t n){int a=0;for(size_t i=0;i<n;i++){if(p[i]<32||p[i]>126)return 0;if(isalpha(p[i]))a++;}return a>0;}
int my_memcmp(const void*a,const void*b,size_t n){
  if(n>=3&&n<=64){
    const unsigned char*A=a,*B=b;
    if(printable(A,n)||printable(B,n)){
      fprintf(stderr,"MEMCMP n=%zu\n  A=%.*s\n  B=%.*s\n",n,(int)n,A,(int)n,B);
    }
  }
  return memcmp(a,b,n);
}
__attribute__((used)) static struct{const void*r;const void*f;}
 _i0 __attribute__((section("__DATA,__interpose")))={(const void*)my_memcmp,(const void*)memcmp};
