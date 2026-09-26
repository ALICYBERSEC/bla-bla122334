#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static long c_malloc,c_free,c_memcpy,c_memmove,c_memset,c_strlen,c_realloc;
extern void* malloc(size_t); extern void free(void*);
void* my_malloc(size_t n){c_malloc++;return malloc(n);}
void my_free(void*p){c_free++;free(p);}
void* my_memcpy(void*a,const void*b,size_t n){c_memcpy++;return memcpy(a,b,n);}
void* my_memmove(void*a,const void*b,size_t n){c_memmove++;return memmove(a,b,n);}
void* my_memset(void*a,int v,size_t n){c_memset++;return memset(a,v,n);}
size_t my_strlen(const char*s){c_strlen++;return strlen(s);}
void* my_realloc(void*p,size_t n){c_realloc++;return realloc(p,n);}
#define I(r,f) __attribute__((used)) static struct{const void*a;const void*b;} _##f __attribute__((section("__DATA,__interpose")))={(const void*)r,(const void*)f};
I(my_malloc,malloc) I(my_free,free) I(my_memcpy,memcpy) I(my_memmove,memmove) I(my_memset,memset) I(my_strlen,strlen) I(my_realloc,realloc)
__attribute__((destructor)) static void done(void){
  fprintf(stderr,"CNT malloc=%ld free=%ld memcpy=%ld memmove=%ld memset=%ld strlen=%ld realloc=%ld\n",
    c_malloc,c_free,c_memcpy,c_memmove,c_memset,c_strlen,c_realloc);
}
