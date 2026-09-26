#include <stdio.h>
#include <stdlib.h>
#include <unwind.h>
static long cnt=0;
typedef _Unwind_Reason_Code (*rex_t)(struct _Unwind_Exception*);
extern _Unwind_Reason_Code _Unwind_RaiseException(struct _Unwind_Exception*);
_Unwind_Reason_Code my_rex(struct _Unwind_Exception* e){ cnt++; return _Unwind_RaiseException(e); }
__attribute__((used)) static struct{const void*r;const void*f;}
 _i0 __attribute__((section("__DATA,__interpose")))={(const void*)my_rex,(const void*)_Unwind_RaiseException};
__attribute__((destructor)) static void done(void){ fprintf(stderr,"UNWIND_COUNT=%ld\n",cnt); }
