.syntax unified
.arch armv7-a
.thumb
.text
.global csnd_cp_lookup_hook,csnd_cp_lookup_original,csnd_cp_exists_original
.global csnd_cp_start_original,csnd_cp_validate_original
.global rv_cp_dmm_dispatch_original,csnd_driver_entry_hook,csnd_driver_exit_hook
.global csnd_cp_owner_reply_original,csnd_custom_gain_hook
.thumb_func
csnd_cp_lookup_hook:
 mov r3,lr
 b.w csnd_cp_lookup
.thumb_func
csnd_cp_lookup_original:
 add.w r12,r0,#0x14
 .balign 4
 ldr.w pc,[pc,#0]
 .word 0x6566a1
.thumb_func
csnd_cp_exists_original:
 adds r0,#0x14
 movs r2,#0
 .balign 4
 ldr.w pc,[pc,#0]
 .word 0x65660f
.thumb_func
csnd_cp_start_original:
 push {r4-r7,lr}
 add r7,sp,#12
 .balign 4
 ldr.w pc,[pc,#0]
 .word 0x6545cd
.thumb_func
csnd_cp_validate_original:
 push {r4,r5,r7,lr}
 add r7,sp,#8
 .balign 4
 ldr.w pc,[pc,#0]
 .word 0x198cf5
.thumb_func
rv_cp_dmm_dispatch_original:
 push {r4-r7,lr}
 add r7,sp,#12
 .balign 4
 ldr.w pc,[pc,#0]
 .word 0xbdb987
.thumb_func
csnd_cp_owner_reply_original:
 b.w csnd_cp_owner_reply
.thumb_func
csnd_driver_entry_hook:
 push {r0-r12,lr}
 mrs r2,apsr
 push {r2,r3}
 add r0,sp,#64
 bl csnd_driver_pre
 pop {r2,r3}
 msr apsr_nzcvqg,r2
 pop {r0-r12,lr}
 push {r4,r6,r7,lr}
 add r7,sp,#8
 .balign 4
 ldr.w pc,[pc,#0]
 .word 0xb35837
.thumb_func
csnd_driver_exit_hook:
 push {r0-r12,lr}
 mrs r2,apsr
 push {r2,r3}
 add r0,sp,#88
 mov r1,r4
 bl csnd_driver_post
 pop {r2,r3}
 msr apsr_nzcvqg,r2
 pop {r0-r12,lr}
 mov r0,r4
 add sp,#8
 pop {r4,r6,r7,pc}
.thumb_func
csnd_custom_gain_hook:
 push {r0-r12,lr}
 mrs r2,apsr
 push {r2,r3}
 ldrb r0,[r5,#4]
 ldrb r1,[r5,#5]
 add r2,sp,#264
 ldr r3,[sp,#164]
 bl csnd_custom_gain_scalar
 strb r0,[sp,#68]
 str r0,[sp,#8]
 pop {r2,r3}
 msr apsr_nzcvqg,r2
 pop {r0-r12,lr}
 .balign 4
 ldr.w pc,[pc,#0]
 .word 0x1998bf

/* Primary cold path at5E3F04 originally calls A32 zero(1197418,8A2030).
 * This wrapper preserves that call, initializes our private BSS, and returns
 * before5E3F18 publishes the secondary-core release flag. */
.arm
.align 2
.global rv_cp_cold_zero_hook
.type rv_cp_cold_zero_hook,%function
rv_cp_cold_zero_hook:
 push {r4,lr}
 ldr r12,=0x5f58b0
 blx r12
 ldr r12,=rv_cp_module_cold_init
 blx r12
 pop {r4,pc}
.ltorg

/* Existing module text ends BEF218; the remaining page padding is zero.
 * Candidate veneers occupy BEF220..BEF268, without relying on a random cave. */
.section .rv_veneer,"ax",%progbits
.thumb
.align 2
.macro THUMB_VENEER name,target
.global \name
.thumb_func
\name:
 ldr.w pc,[pc,#0]
 .word \target
.endm
THUMB_VENEER rv_veneer_lookup,csnd_cp_lookup_hook
THUMB_VENEER rv_veneer_exists,csnd_cp_exists
THUMB_VENEER rv_veneer_start,csnd_cp_start
THUMB_VENEER rv_veneer_validate,csnd_cp_validate
THUMB_VENEER rv_veneer_gain,csnd_custom_gain_hook
THUMB_VENEER rv_veneer_driver_entry,csnd_driver_entry_hook
THUMB_VENEER rv_veneer_driver_exit,csnd_driver_exit_hook
THUMB_VENEER rv_veneer_dmm,rv_cp_dmm_dispatch
.arm
.global rv_veneer_cold
.type rv_veneer_cold,%function
rv_veneer_cold:
 ldr pc,[pc,#-4]
 .word rv_cp_cold_zero_hook
