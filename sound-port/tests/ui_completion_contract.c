/* Host-only interleaving/failed-save contract. All native/FS APIs below are mocks. */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ap_runtime.h"
#include "ap_native_policy.h"
#include "private_selector.h"
#include "menu_callbacks.h"
extern char *strstr(const char *,const char *);
extern int strcmp(const char *,const char *);

extern int csnd_volume_worker_tick(void),csnd_volume_enqueue(uint32_t,uint32_t);
extern int csnd_volume_blocked(uint32_t);
extern uint32_t csnd_volume_get(uint32_t),csnd_volume_completion(uint32_t),csnd_volume_request_ticket(uint32_t);
extern uint32_t csnd_volume_electronic_getter(void);
extern void csnd_volume_electronic_setter(uint32_t);
extern int csnd_volume_electronic_commit(uint32_t),csnd_ui_event(void *,void *,uint32_t);
csnd_runtime csnd_ap_state;
static uint32_t available=1,parent=1592,refreshes,updates,scope,fail_sync;
static uint32_t finish_old_in_available,try_enqueue_in_write,saw_busy;
static uint32_t focus_selection=SS_SELECTION_CUSTOM;
static csnd_private_session *last_session;
typedef struct {unsigned char b[25];size_t n,at;int exists;} mock_file;
static mock_file files[3];static int error_value;
static int file_id(const char *p){if(strstr(p,".tmp"))return 1;if(strstr(p,".bak"))return 2;return 0;}
void *csnd_malloc(size_t n){return malloc(n);}void csnd_free(void *p){free(p);}
int *csnd_errno(void){return &error_value;}
int csnd_open(const char *p,int flags,...){
 if(!strcmp(p,"/setting/csnd"))return 8;
 int i=file_id(p);if(flags==0x88241){memset(&files[i],0,sizeof(files[i]));files[i].exists=1;}
 if(!files[i].exists){error_value=2;return -1;}files[i].at=0;return i+1;
}
long csnd_read(int fd,void *p,size_t n){mock_file *f=files+fd-1;size_t k=f->n-f->at;if(k>n)k=n;memcpy(p,f->b+f->at,k);f->at+=k;return (long)k;}
long csnd_write(int fd,const void *p,size_t n){
 if(try_enqueue_in_write){try_enqueue_in_write=0;saw_busy=csnd_volume_enqueue(0,7)==8;}
 mock_file *f=files+fd-1;if(f->at+n>sizeof(f->b))return -1;memcpy(f->b+f->at,p,n);f->at+=n;f->n=f->at;return (long)n;
}
int csnd_close(int fd){(void)fd;return 0;}
int csnd_fsync(int fd){(void)fd;if(fail_sync){fail_sync=0;return -1;}return 0;}
int csnd_remove(const char *p){mock_file *f=files+file_id(p);if(!f->exists){error_value=2;return -1;}memset(f,0,sizeof(*f));return 0;}
int csnd_rename(const char *a,const char *b){int x=file_id(a),y=file_id(b);if(!files[x].exists){error_value=2;return -1;}files[y]=files[x];memset(files+x,0,sizeof(files[x]));return 0;}
int csnd_mkdir(const char *p,unsigned mode){(void)p;(void)mode;return 0;}
int csnd_ap_enabled(uint32_t slot){return csnd_ap_state.pending[slot]!=0;}
int csnd_ap_import_available(uint32_t slot){
 (void)slot;if(finish_old_in_available){finish_old_in_available=0;assert(csnd_volume_worker_tick()==0);}return (int)available;
}
int csnd_ap_mechanical_pending(void){return 0;}
int csnd_ap_menu_view(uint32_t slot,ss_menu_view *view){(void)slot;memset(view,0,sizeof(*view));view->selection=focus_selection;return SS_OK;}
int csnd_ap_read_native(uint32_t p,uint32_t a,uint32_t b,ss_native *n){(void)p;(void)a;(void)b;memset(n,0,sizeof(*n));n->shutter=SS_SHUTTER_ELECTRONIC;return SS_OK;}
uint32_t csnd_original_menu_blocked(uint32_t m){(void)m;return 0;}
uint32_t csnd_previous_menu_blocked(uint32_t m){(void)m;return 0;}
void *csnd_native_manager_get(void){return (void *)1;}
csnd_private_session *csnd_private_session_create(uint32_t generation,uint32_t slot,const uint8_t *media,uint32_t card){
 (void)media;(void)card;last_session=calloc(1,sizeof(*last_session));last_session->generation=generation;last_session->slot=slot;return last_session;
}
void csnd_private_session_release(csnd_private_session *s){free(s);if(last_session==s)last_session=0;}
int csnd_private_submit(void *m,csnd_private_session *s,uint32_t op,uint32_t row,uint32_t enabled,uint32_t shutter){(void)m;(void)op;(void)row;(void)enabled;(void)shutter;s->phase=CSND_QUEUED;return SS_OK;}
int csnd_private_cancel(csnd_private_session *s,uint32_t g){(void)g;s->phase=CSND_CANCELED;return SS_OK;}
int csnd_private_list_copy(csnd_private_session *s,uint32_t g,csnd_picker_list *l){(void)s;(void)g;(void)l;return CSND_AP_BUSY;}
int csnd_original_event(void *c,void *m,uint32_t code){(void)c;(void)m;(void)code;return 37;}
uint32_t *csnd_parent_parameter(void){return &parent;}
void csnd_rv_model_scope_enter(void *g){(void)g;++scope;}
void csnd_rv_model_scope_leave(void *g){(void)g;assert(scope);--scope;}
void csnd_original_profile_update(void *c,uint32_t id){(void)c;assert(id==1593||id==1594||id==1598);++updates;}
void csnd_original_parent_refresh(void *c,void *m){(void)c;assert(m);++refreshes;}
static unsigned char controller[0x200];static uint32_t message=0x2d7;
static void event(void){assert(csnd_ui_event(controller,&message,0x20f0000)==37);assert(!scope);}
int main(void){
 *(uint32_t *)(controller+0x178)=0x2d7;csnd_ap_state.initialized=1;
 assert(csnd_volume_worker_tick()==0&&csnd_volume_get(0)==5);
 focus_selection=SS_SELECTION_DEFAULT;assert(csnd_volume_blocked(1)==1&&csnd_volume_enqueue(1,8)==6);
 focus_selection=SS_SELECTION_CUSTOM;assert(csnd_volume_blocked(1)==0);
 csnd_volume_electronic_setter(9);assert(csnd_volume_electronic_getter()==9);
 assert(csnd_volume_electronic_commit(5620)==0);assert(csnd_volume_request_ticket(0)==1);
 try_enqueue_in_write=1;assert(csnd_volume_worker_tick()==0&&saw_busy);
 assert(csnd_volume_get(0)==10&&csnd_volume_completion(0)==1);event();assert(refreshes==1&&updates==3);
 csnd_volume_electronic_setter(1);assert(csnd_volume_electronic_commit(5612)==0);
 fail_sync=1;assert(csnd_volume_worker_tick()==4);assert(csnd_volume_get(0)==10);event();assert(refreshes==2&&csnd_volume_electronic_getter()==9);
 /* Finish A inside B's availability check, after the old wrapper would have
  * sampled its completion baseline. B must wait for its own ticket. */
 assert(csnd_volume_electronic_commit(5613)==0);finish_old_in_available=1;
 assert(csnd_volume_electronic_commit(5614)==0);assert(csnd_volume_completion(0)==3&&csnd_volume_request_ticket(0)==4);
 event();assert(refreshes==2);assert(csnd_volume_worker_tick()==0);event();assert(refreshes==3&&csnd_volume_get(0)==4);
 available=0;csnd_volume_electronic_setter(8);assert(csnd_volume_electronic_commit(5619)==6);event();assert(refreshes==4&&csnd_volume_electronic_getter()==3);available=1;
 /* A completed/failed old session cannot overwrite a newly staged setter. */
 csnd_menu_electronic_setter(0);assert(csnd_menu_electronic_commit(5607)==0);
 last_session->status=SS_STORAGE;last_session->phase=CSND_COMPLETE;
 csnd_menu_electronic_setter(0);csnd_ap_state.pending[0]=0;
 assert(csnd_menu_electronic_getter()==0);event();assert(refreshes==5);
 assert(csnd_menu_electronic_commit(5607)==0);last_session->status=SS_STORAGE;last_session->phase=CSND_COMPLETE;event();assert(csnd_menu_electronic_getter()==1);
 csnd_private_session canceled={0};canceled.generation=9;canceled.phase=CSND_CANCELED;
 csnd_selector selector={0};selector.magic=0x53475549;selector.generation=9;selector.session=&canceled;selector.phase=CSND_UI_SAVING;
 assert(csnd_selector_poll(&selector)==SS_DISABLED&&selector.phase==CSND_UI_CANCELED);
 assert(csnd_ui_event(controller,0,0x20f0000)==37);
 puts("PASS volume tickets, in-flight BUSY, failed-save restoration, staged toggle, selector cancel and GUI refresh");return 0;
}
