/* RV GUI timer consumes actual worker completion, including failed commits. */
#include <stdint.h>
extern int csnd_old_electronic_commit(uint32_t),csnd_old_focus_commit(uint32_t);
extern int csnd_old_volume_electronic_commit(uint32_t),csnd_old_volume_focus_commit(uint32_t);
extern int csnd_menu_request_status(uint32_t,uint32_t *,uint32_t *);
extern uint32_t csnd_volume_completion(uint32_t);
extern uint32_t csnd_volume_request_ticket(uint32_t);
extern int csnd_original_event(void *,void *,uint32_t);
extern uint32_t *csnd_parent_parameter(void);
extern void csnd_original_profile_update(void *,uint32_t);
extern void csnd_original_parent_refresh(void *,void *);
extern void csnd_rv_model_scope_enter(void *),csnd_rv_model_scope_leave(void *);
static uint32_t pending[2],volume_pending[2],volume_ticket[2],dirty[2];
int csnd_menu_electronic_commit(uint32_t alias){int r=csnd_old_electronic_commit(alias);pending[0]=1;return r;}
int csnd_menu_focus_commit(uint32_t alias){int r=csnd_old_focus_commit(alias);pending[1]=1;return r;}
static int volume_commit(uint32_t slot,uint32_t alias){
    int status=slot?csnd_old_volume_focus_commit(alias):csnd_old_volume_electronic_commit(alias);
    if(!status){volume_ticket[slot]=csnd_volume_request_ticket(slot);volume_pending[slot]=1;}
    else dirty[slot]=1;
    return status;
}
int csnd_volume_electronic_commit(uint32_t alias){return volume_commit(0,alias);}
int csnd_volume_focus_commit(uint32_t alias){return volume_commit(1,alias);}
int csnd_ui_event(void *controller,void *message,uint32_t code){
    int result=csnd_original_event(controller,message,code);
    uint32_t parent,slot,refresh=0,queued=1,status=0;uint64_t guard=0;const uint32_t *parameter;
    if(code!=0x20f0000u || !controller || !message || *(uint32_t *)((uint8_t *)controller+0x178)!=0x2d7)return result;
    csnd_rv_model_scope_enter(&guard);parameter=csnd_parent_parameter();parent=parameter?*parameter:0xffffffffu;csnd_rv_model_scope_leave(&guard);
    if(parent==1592)slot=0;else if(parent==1595)slot=1;else return result;
    refresh=dirty[slot];dirty[slot]=0;
    if(pending[slot] && !csnd_menu_request_status(slot,&queued,&status) && !queued){pending[slot]=0;refresh=1;}
    if(volume_pending[slot] && csnd_volume_completion(slot)==volume_ticket[slot]){volume_pending[slot]=0;refresh=1;}
    if(refresh){
        csnd_original_profile_update(controller,parent+1);
        csnd_original_profile_update(controller,parent+2);
        csnd_original_profile_update(controller,1598+slot);
        csnd_original_parent_refresh(controller,message);
    }
    return result;
}
