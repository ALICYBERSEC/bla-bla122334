#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>
static void pr(const char*tag,const void*a,const void*b,size_t n){
  size_t m=n>96?96:n;
  fprintf(stderr,"[%s n=%zu]\n  A=",tag,n);
  for(size_t i=0;i<m;i++){unsigned char c=((unsigned char*)a)[i];fprintf(stderr,"%c",isprint(c)?c:'.');}
  fprintf(stderr,"\n  B=");
  for(size_t i=0;i<m;i++){unsigned char c=((unsigned char*)b)[i];fprintf(stderr,"%c",isprint(c)?c:'.');}
  fprintf(stderr,"\n");
}
int my_memcmp(const void*a,const void*b,size_t n){ if(n>=2&&n<=128) pr("memcmp",a,b,n); return memcmp(a,b,n); }
int my_bcmp(const void*a,const void*b,size_t n){ if(n>=2&&n<=128) pr("bcmp",a,b,n); return bcmp(a,b,n); }
int my_strcmp(const char*a,const char*b){ pr("strcmp",a,b,strlen(a)<strlen(b)?strlen(a):strlen(b)); return strcmp(a,b); }
int my_strncmp(const char*a,const char*b,size_t n){ pr("strncmp",a,b,n); return strncmp(a,b,n); }
__attribute__((used)) static struct{const void*r;const void*f;}
 _i0 __attribute__((section("__DATA,__interpose")))={(const void*)my_memcmp,(const void*)memcmp},
 _i1 __attribute__((section("__DATA,__interpose")))={(const void*)my_bcmp,(const void*)bcmp},
 _i2 __attribute__((section("__DATA,__interpose")))={(const void*)my_strcmp,(const void*)strcmp},
 _i3 __attribute__((section("__DATA,__interpose")))={(const void*)my_strncmp,(const void*)strncmp};
