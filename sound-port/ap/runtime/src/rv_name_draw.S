/* Original calls remain untouched for presenters outside the private flow.
 * RV row23787a8 has presenter=x19,row=w27; confirmation23791b8 uses x19.
 * Native assign_text and snprintf consume a stack-owned UTF-8 projection. */
.text
.p2align 2
.global csnd_rv_row_name_draw
.hidden csnd_rv_row_name_draw
.type csnd_rv_row_name_draw,%function
csnd_rv_row_name_draw:
 stp x29,x30,[sp,#-176]!
 mov x29,sp
 stp x0,x1,[sp,#16]
 mov x0,x19
 mov w1,w27
 add x2,sp,#32
 bl csnd_selector_copy_row_name
 cbz w0,1f
 add x1,sp,#32
 str x1,[sp,#24]
1:
 ldp x0,x1,[sp,#16]
 bl csnd_native_assign_text
 ldp x29,x30,[sp],#176
 ret
.size csnd_rv_row_name_draw,.-csnd_rv_row_name_draw

.p2align 2
.global csnd_rv_confirmation_name_draw
.hidden csnd_rv_confirmation_name_draw
.type csnd_rv_confirmation_name_draw,%function
csnd_rv_confirmation_name_draw:
 stp x29,x30,[sp,#-192]!
 mov x29,sp
 stp x0,x1,[sp,#16]
 stp x2,x3,[sp,#32]
 mov x0,x19
 add x1,sp,#48
 bl csnd_controller_copy_confirmation_name
 cbz w0,2f
 add x3,sp,#48
 str x3,[sp,#40]
2:
 ldp x0,x1,[sp,#16]
 ldp x2,x3,[sp,#32]
 bl csnd_native_snprintf
 ldp x29,x30,[sp],#192
 ret
.size csnd_rv_confirmation_name_draw,.-csnd_rv_confirmation_name_draw
.section .note.GNU-stack,"",%progbits
