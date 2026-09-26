#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
static const char* NEEDLES[] = {"flare-on", "@flare", "flare_on", "flareon.com"};
static void scan_once(void){
  task_t task = mach_task_self();
  mach_vm_address_t addr = 1;
  mach_vm_size_t size = 0;
  natural_t depth = 0;
  while (1){
    struct vm_region_submap_info_64 info; mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(task,&addr,&size,&depth,(vm_region_recurse_info_t)&info,&cnt);
    if (kr != KERN_SUCCESS) break;
    if (info.is_submap){ depth++; continue; }
    if ((info.protection & VM_PROT_READ) && size>0 && size < (64ULL<<20)){
      char* buf = (char*)addr;
      // guard: try reading; wrap in try via mach_vm_read is safer but slow; just scan directly
      for (unsigned long i=0;i+12<(unsigned long)size;i++){
        for (int n=0;n<4;n++){
          size_t L=strlen(NEEDLES[n]);
          if (buf[i]==NEEDLES[n][0] && memcmp(buf+i,NEEDLES[n],L)==0){
            // print up to 60 printable chars around
            long s=i-40; if(s<0)s=0;
            fprintf(stderr,"[HIT %s] ",NEEDLES[n]);
            for(long k=s;k<(long)i+30 && k<(long)size;k++){unsigned char c=buf[k];fputc(isprint(c)?c:'.',stderr);}
            fprintf(stderr,"\n"); fflush(stderr);
          }
        }
      }
    }
    addr += size;
  }
}
static void* worker(void* a){ for(int i=0;i<600;i++){ scan_once(); usleep(30000);} return 0; }
__attribute__((constructor)) static void init(void){
  pthread_t t; pthread_create(&t,0,worker,0); pthread_detach(t);
  fprintf(stderr,"[scanner started]\n");
}
