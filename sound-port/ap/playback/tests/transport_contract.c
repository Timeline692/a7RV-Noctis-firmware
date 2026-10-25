/* One host fixture exercises the real transport source and its native ABI. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "native_transport.h"
static unsigned char wire[1000];
static uint32_t actual,free_count,tail_fault,size_fault,session_fault,source_fault;
static uint32_t sub(void){return 0x105;}
static int dynamic(uint32_t op,uint32_t scope,uintptr_t out){
 if(op==0x2a){assert(scope==0x105);*(uint32_t*)out=0x81050001;return 0;}
 assert(op==0x4a&&scope==0&&out==0x81050001);return 0;
}
static int statq(uint32_t ep,uint32_t *s){assert(ep==0x81050001);memset(s,0,16);return 0;}
static int allocate(uint32_t dst,void **out,uint32_t bytes,uint32_t wait){
 assert(dst==0x9061003c&&bytes>=40&&bytes<=1000&&!wait);actual=bytes;*out=wire;return 0;
}
static uint32_t rd32(const unsigned char *p){return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void w16(unsigned char*p,uint32_t x){p[0]=x;p[1]=x>>8;}
static void w32(unsigned char*p,uint32_t x){w16(p,x);w16(p+2,x>>16);}
static void setsrc(void *p,uint32_t ep){assert(p==wire&&ep==0x81050001);}
static int sendmsg(uint32_t dst,void *p){
 assert(dst==0x9061003c&&p==wire);
 uint32_t op=rd32(wire+4),session=rd32(wire+8),token=wire[20]|(uint32_t)wire[21]<<8;
 assert(op>=1&&op<=6&&rd32(wire+12)==0x4e535343&&rd32(wire+16)==session);
 if(op==6)assert(rd32(wire+36)==actual-40);
 memset(wire,0,actual);w16(wire,0x807e);w16(wire+4,24);w16(wire+6,token);
 w32(wire+8,session+session_fault);w32(wire+12,op);
 if(tail_fault)wire[actual-1]=1;
 return 0;
}
static int recvmsg(uint32_t ep,void **p,uint32_t wait){assert(ep==0x81050001&&!wait);*p=wire;return 0;}
static uint32_t msgsize(void *p){assert(p==wire);return actual-size_fault;}
static uint32_t getsrc(void*p){assert(p==wire);return 0x61003c+source_fault;}
static int freemsg(uint32_t ep,void*p){assert(ep==0x81050001&&p==wire);free_count++;return 0;}
static void *binding(uintptr_t a){
 switch(a){case 0x16dc1c0:return sub;case 0x16daae0:return dynamic;case 0x16d9e80:return statq;
 case 0x16dc740:return allocate;case 0x16d99c0:return setsrc;case 0x16dafc0:return sendmsg;
 case 0x16dae10:return recvmsg;case 0x16dabe0:return msgsize;case 0x16dbd50:return getsrc;case 0x16dca60:return freemsg;}
 assert(0);return 0;
}
#define F(o,t) ((t)binding(o))
/* Rename only this fixture's reader to avoid the production static helper. */
#define rd32 production_rd32
#include "../src/native_transport.c"
#undef rd32
static void reset(void){tail_fault=size_fault=session_fault=source_fault=0;}
static void copy_case(uint32_t n,uint32_t expected){
 ns_rpc c={0};unsigned char data[960]={1};
 assert(csnd_private_copy(0,&c,0,7,9,0,data,n,100)==NT_PENDING);
 assert(c.expected_reply_bytes==40+n&&actual==40+n);
 assert(csnd_rpc_poll(0,&c,1)==expected);
 if(expected==NT_REPLIED)assert(csnd_rpc_finish(0,&c,0)==NT_EMPTY);
 else assert(c.reason==NT_REASON_PROTOCOL&&c.endpoint==0x81050001&&c.reply[0]==0x7e&&c.reply[1]==0x80);
}
int main(void){
 reset();copy_case(32,NT_REPLIED);copy_case(960,NT_REPLIED);
 tail_fault=1;copy_case(32,NT_UNCERTAIN);reset();size_fault=1;copy_case(32,NT_UNCERTAIN);
 reset();session_fault=1;copy_case(32,NT_UNCERTAIN);reset();source_fault=1;copy_case(32,NT_UNCERTAIN);
 reset();ns_rpc c={0};uint32_t a[4]={0};
 assert(csnd_private_start(0,&c,5,0,a,100)==NT_PENDING&&actual==40);
 assert(csnd_rpc_poll(0,&c,1)==NT_REPLIED&&csnd_rpc_finish(0,&c,0)==NT_EMPTY);
 assert(free_count==7);return 0;
}
