#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
typedef uint32_t u32; typedef uint64_t u64;
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static const u32 K[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static const u32 IV[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
#define RND(a,b,c,d,e,f,g,h,ki,wi){u32 S1=ROR(e,6)^ROR(e,11)^ROR(e,25),ch=(e&f)^(~e&g),t1=h+S1+ch+ki+wi,S0=ROR(a,2)^ROR(a,13)^ROR(a,22),mj=(a&b)^(a&c)^(b&c);h=t1+S0+mj;d+=t1;}
static inline void compress(const u32 M[16],u32 H[8]){
  u32 w[64];
  #pragma GCC unroll 16
  for(int i=0;i<16;i++)w[i]=M[i];
  for(int i=16;i<64;i++){u32 x=w[i-15],y=w[i-2];w[i]=w[i-16]+(ROR(x,7)^ROR(x,18)^(x>>3))+w[i-7]+(ROR(y,17)^ROR(y,19)^(y>>10));}
  u32 a=IV[0],b=IV[1],c=IV[2],d=IV[3],e=IV[4],f=IV[5],g=IV[6],h=IV[7];
  for(int i=0;i<64;i+=8){
    RND(a,b,c,d,e,f,g,h,K[i],w[i]) RND(h,a,b,c,d,e,f,g,K[i+1],w[i+1]) RND(g,h,a,b,c,d,e,f,K[i+2],w[i+2]) RND(f,g,h,a,b,c,d,e,K[i+3],w[i+3])
    RND(e,f,g,h,a,b,c,d,K[i+4],w[i+4]) RND(d,e,f,g,h,a,b,c,K[i+5],w[i+5]) RND(c,d,e,f,g,h,a,b,K[i+6],w[i+6]) RND(b,c,d,e,f,g,h,a,K[i+7],w[i+7])
  }
  H[0]=IV[0]+a;H[1]=IV[1]+b;H[2]=IV[2]+c;H[3]=IV[3]+d;H[4]=IV[4]+e;H[5]=IV[5]+f;H[6]=IV[6]+g;H[7]=IV[7]+h;
}
static uint8_t CT[51]; static const char SUF[14]="@flare-on.com";
static volatile int found=0; static u64 counters[8]; static u32 NONCE=0x0b501e7e;
static inline void trial(u32 s,uint8_t*Sbox){
  u32 M1[16]={s,NONCE,0x80000000u,0,0,0,0,0,0,0,0,0,0,0,0,0x40}; u32 H1[8]; compress(M1,H1);
  u32 M2[16]={H1[0],H1[1],H1[2],H1[3],H1[4],H1[5],H1[6],H1[7],0x80000000u,0,0,0,0,0,0,0x100}; u32 H2[8]; compress(M2,H2);
  uint8_t keyLE[16],keyBE[16];
  for(int i=0;i<4;i++){keyLE[i*4]=H2[i];keyLE[i*4+1]=H2[i]>>8;keyLE[i*4+2]=H2[i]>>16;keyLE[i*4+3]=H2[i]>>24;
                       keyBE[i*4]=H2[i]>>24;keyBE[i*4+1]=H2[i]>>16;keyBE[i*4+2]=H2[i]>>8;keyBE[i*4+3]=H2[i];}
  uint8_t*keys[2]={keyLE,keyBE};const char*tag[2]={"LE","BE"};
  for(int v=0;v<2;v++){uint8_t*key=keys[v];
    for(int i=0;i<256;i++)Sbox[i]=i; int j=0;
    for(int i=0;i<256;i++){j=(j+Sbox[i]+key[i&15])&0xff;uint8_t t=Sbox[i];Sbox[i]=Sbox[j];Sbox[j]=t;}
    int i=0;j=0;uint8_t out[52];int bad=0;
    for(int k=0;k<51;k++){i=(i+1)&0xff;j=(j+Sbox[i])&0xff;uint8_t t=Sbox[i];Sbox[i]=Sbox[j];Sbox[j]=t;uint8_t p=Sbox[(Sbox[i]+Sbox[j])&0xff]^CT[k];if(p<0x20||p>0x7e){bad=1;break;}out[k]=p;}
    if(bad)continue;
    if(!memcmp(out+38,SUF,13)){out[51]=0;printf("HIT serial=%08x variant=%s flag=%s\n",s,tag[v],out);fflush(stdout);found=1;}
  }
}
typedef struct{u32 lo,hi;int id;}rng;
static void*worker(void*a){rng*r=(rng*)a;uint8_t Sbox[256];u64 c=0;
  for(u64 s=r->lo;;s++){if(found)break;trial((u32)s,Sbox);if((++c&0xfffff)==0){counters[r->id]=c;if(found)break;}if(s==r->hi)break;}
  counters[r->id]=c;return 0;}
int main(int argc,char**argv){const char*hex="f4f9659f31f3da5cf137a1b8cf90a1581eebe499a7c11b1502af7463d3b2192866de3de97163e775dfe4ab616fb90c2789fc87";
  for(int i=0;i<51;i++){unsigned v;sscanf(hex+i*2,"%2x",&v);CT[i]=v;}
  int NT=4;pthread_t th[8];rng rg[8];int SH=argc>1?atoi(argv[1]):0,NS=argc>2?atoi(argv[2]):1;u64 span=0x100000000ULL/NS;u64 glo=(u64)SH*span,ghi=(SH==NS-1)?0xffffffffULL:(glo+span-1);u64 per=(ghi-glo+1)/NT;
  struct timespec t0;clock_gettime(1,&t0);
  for(int t=0;t<NT;t++){rg[t].lo=glo+t*per;rg[t].hi=(t==NT-1)?ghi:(glo+(t+1)*per-1);rg[t].id=t;pthread_create(&th[t],0,worker,&rg[t]);}
  for(int loop=0;!found;loop++){struct timespec ts={2,0};nanosleep(&ts,0);int alive=0;for(int t=0;t<NT;t++)if(counters[t]<(rg[t].hi-rg[t].lo))alive++;
    struct timespec t1;clock_gettime(1,&t1);double dt=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;u64 tot=0;for(int t=0;t<NT;t++)tot+=counters[t];
    fprintf(stderr,"\r%.0f%% done, %.2fM/s, %.0fs elapsed   ",tot/42949672.96,tot/dt/1e6,dt);if(!alive)break;}
  for(int t=0;t<NT;t++)pthread_join(th[t],0);
  fprintf(stderr,"\n");if(!found)printf("no hit variant A\n");return 0;}
