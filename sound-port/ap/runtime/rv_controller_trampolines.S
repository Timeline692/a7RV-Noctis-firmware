/* RV 4.00, one displaced instruction per entry. */
.section .text.rv_gui_trampolines,"ax",%progbits
.p2align 2
.global csnd_original_card_ctor
.hidden csnd_original_card_ctor
.type csnd_original_card_ctor,%function
csnd_original_card_ctor:
    .word 0xd10703ff
    b rv_native_resume_card_ctor
.size csnd_original_card_ctor, .-csnd_original_card_ctor
.global csnd_original_file_ctor
.hidden csnd_original_file_ctor
.type csnd_original_file_ctor,%function
csnd_original_file_ctor:
    .word 0xd10703ff
    b rv_native_resume_file_ctor
.size csnd_original_file_ctor, .-csnd_original_file_ctor
.global csnd_original_confirm_ctor
.hidden csnd_original_confirm_ctor
.type csnd_original_confirm_ctor,%function
csnd_original_confirm_ctor:
    .word 0xd10703ff
    b rv_native_resume_confirm_ctor
.size csnd_original_confirm_ctor, .-csnd_original_confirm_ctor
.global csnd_original_wait_ctor
.hidden csnd_original_wait_ctor
.type csnd_original_wait_ctor,%function
csnd_original_wait_ctor:
    .word 0xd10703ff
    b rv_native_resume_wait_ctor
.size csnd_original_wait_ctor, .-csnd_original_wait_ctor
.global csnd_original_card_dtor
.hidden csnd_original_card_dtor
.type csnd_original_card_dtor,%function
csnd_original_card_dtor:
    .word 0xa9be7bfd
    b rv_native_resume_card_dtor
.size csnd_original_card_dtor, .-csnd_original_card_dtor
.global csnd_original_file_dtor
.hidden csnd_original_file_dtor
.type csnd_original_file_dtor,%function
csnd_original_file_dtor:
    .word 0xa9be7bfd
    b rv_native_resume_file_dtor
.size csnd_original_file_dtor, .-csnd_original_file_dtor
.global csnd_original_confirm_dtor
.hidden csnd_original_confirm_dtor
.type csnd_original_confirm_dtor,%function
csnd_original_confirm_dtor:
    .word 0xa9be7bfd
    b rv_native_resume_confirm_dtor
.size csnd_original_confirm_dtor, .-csnd_original_confirm_dtor
.global csnd_original_wait_dtor
.hidden csnd_original_wait_dtor
.type csnd_original_wait_dtor,%function
csnd_original_wait_dtor:
    .word 0xa9be7bfd
    b rv_native_resume_wait_dtor
.size csnd_original_wait_dtor, .-csnd_original_wait_dtor
.global csnd_original_card_confirm
.hidden csnd_original_card_confirm
.type csnd_original_card_confirm,%function
csnd_original_card_confirm:
    .word 0xa9bc7bfd
    b rv_native_resume_card_confirm
.size csnd_original_card_confirm, .-csnd_original_card_confirm
.global csnd_original_card_cancel
.hidden csnd_original_card_cancel
.type csnd_original_card_cancel,%function
csnd_original_card_cancel:
    .word 0xa9bf7bfd
    b rv_native_resume_card_cancel
.size csnd_original_card_cancel, .-csnd_original_card_cancel
.global csnd_original_file_init
.hidden csnd_original_file_init
.type csnd_original_file_init,%function
csnd_original_file_init:
    .word 0xa9b77bfd
    b rv_native_resume_file_init
.size csnd_original_file_init, .-csnd_original_file_init
.global csnd_original_file_confirm
.hidden csnd_original_file_confirm
.type csnd_original_file_confirm,%function
csnd_original_file_confirm:
    .word 0xa9b87bfd
    b rv_native_resume_file_confirm
.size csnd_original_file_confirm, .-csnd_original_file_confirm
.global csnd_original_file_cancel
.hidden csnd_original_file_cancel
.type csnd_original_file_cancel,%function
csnd_original_file_cancel:
    .word 0xa9bc7bfd
    b rv_native_resume_file_cancel
.size csnd_original_file_cancel, .-csnd_original_file_cancel
.global csnd_original_confirm
.hidden csnd_original_confirm
.type csnd_original_confirm,%function
csnd_original_confirm:
    .word 0xa9ba7bfd
    b rv_native_resume_confirm
.size csnd_original_confirm, .-csnd_original_confirm
.global csnd_original_confirm_cancel
.hidden csnd_original_confirm_cancel
.type csnd_original_confirm_cancel,%function
csnd_original_confirm_cancel:
    .word 0xa9be7bfd
    b rv_native_resume_confirm_cancel
.size csnd_original_confirm_cancel, .-csnd_original_confirm_cancel
.global csnd_original_wait_tick
.hidden csnd_original_wait_tick
.type csnd_original_wait_tick,%function
csnd_original_wait_tick:
    .word 0xb9430401
    b rv_native_resume_wait_tick
.size csnd_original_wait_tick, .-csnd_original_wait_tick
.global csnd_original_file_previous
.hidden csnd_original_file_previous
.type csnd_original_file_previous,%function
csnd_original_file_previous:
    .word 0xa9b97bfd
    b rv_native_resume_file_previous
.size csnd_original_file_previous, .-csnd_original_file_previous
.global csnd_original_file_next
.hidden csnd_original_file_next
.type csnd_original_file_next,%function
csnd_original_file_next:
    .word 0xa9b97bfd
    b rv_native_resume_file_next
.size csnd_original_file_next, .-csnd_original_file_next
.global csnd_original_row_event
.hidden csnd_original_row_event
.type csnd_original_row_event,%function
csnd_original_row_event:
    .word 0xa9b97bfd
    b rv_native_resume_row_event
.size csnd_original_row_event, .-csnd_original_row_event
.global csnd_original_file_snapshot
.hidden csnd_original_file_snapshot
.type csnd_original_file_snapshot,%function
csnd_original_file_snapshot:
    .word 0x913aa001
    b rv_native_resume_file_snapshot
.size csnd_original_file_snapshot, .-csnd_original_file_snapshot
.global csnd_original_file_rec_notify
.hidden csnd_original_file_rec_notify
.type csnd_original_file_rec_notify,%function
csnd_original_file_rec_notify:
    .word 0xa9bc7bfd
    b rv_native_resume_file_rec_notify
.size csnd_original_file_rec_notify, .-csnd_original_file_rec_notify
.global csnd_original_file_half_press
.hidden csnd_original_file_half_press
.type csnd_original_file_half_press,%function
csnd_original_file_half_press:
    .word 0xa9bc7bfd
    b rv_native_resume_file_half_press
.size csnd_original_file_half_press, .-csnd_original_file_half_press
.global csnd_original_file_half_release
.hidden csnd_original_file_half_release
.type csnd_original_file_half_release,%function
csnd_original_file_half_release:
    .word 0xa9bc7bfd
    b rv_native_resume_file_half_release
.size csnd_original_file_half_release, .-csnd_original_file_half_release
.global csnd_original_file_aux_property
.hidden csnd_original_file_aux_property
.type csnd_original_file_aux_property,%function
csnd_original_file_aux_property:
    .word 0xa9b97bfd
    b rv_native_resume_file_aux_property
.size csnd_original_file_aux_property, .-csnd_original_file_aux_property
.global csnd_original_confirm_rec_notify
.hidden csnd_original_confirm_rec_notify
.type csnd_original_confirm_rec_notify,%function
csnd_original_confirm_rec_notify:
    .word 0xa9bc7bfd
    b rv_native_resume_confirm_rec_notify
.size csnd_original_confirm_rec_notify, .-csnd_original_confirm_rec_notify
.global csnd_original_confirm_half_press
.hidden csnd_original_confirm_half_press
.type csnd_original_confirm_half_press,%function
csnd_original_confirm_half_press:
    .word 0xa9bc7bfd
    b rv_native_resume_confirm_half_press
.size csnd_original_confirm_half_press, .-csnd_original_confirm_half_press
.global csnd_original_confirm_half_release
.hidden csnd_original_confirm_half_release
.type csnd_original_confirm_half_release,%function
csnd_original_confirm_half_release:
    .word 0xa9bc7bfd
    b rv_native_resume_confirm_half_release
.size csnd_original_confirm_half_release, .-csnd_original_confirm_half_release
.global csnd_original_wait_rec_notify
.hidden csnd_original_wait_rec_notify
.type csnd_original_wait_rec_notify,%function
csnd_original_wait_rec_notify:
    .word 0xa9bc7bfd
    b rv_native_resume_wait_rec_notify
.size csnd_original_wait_rec_notify, .-csnd_original_wait_rec_notify
.global csnd_original_wait_half_press
.hidden csnd_original_wait_half_press
.type csnd_original_wait_half_press,%function
csnd_original_wait_half_press:
    .word 0xa9bc7bfd
    b rv_native_resume_wait_half_press
.size csnd_original_wait_half_press, .-csnd_original_wait_half_press
.global csnd_original_wait_half_release
.hidden csnd_original_wait_half_release
.type csnd_original_wait_half_release,%function
csnd_original_wait_half_release:
    .word 0xa9bc7bfd
    b rv_native_resume_wait_half_release
.size csnd_original_wait_half_release, .-csnd_original_wait_half_release
.global csnd_original_wait_cancel_command
.hidden csnd_original_wait_cancel_command
.type csnd_original_wait_cancel_command,%function
csnd_original_wait_cancel_command:
    .word 0xa9bd7bfd
    b rv_native_resume_wait_cancel_command
.size csnd_original_wait_cancel_command, .-csnd_original_wait_cancel_command
.global csnd_original_wait_command_result
.hidden csnd_original_wait_command_result
.type csnd_original_wait_command_result,%function
csnd_original_wait_command_result:
    .word 0xa9bb7bfd
    b rv_native_resume_wait_command_result
.size csnd_original_wait_command_result, .-csnd_original_wait_command_result
.global csnd_original_wait_media_result
.hidden csnd_original_wait_media_result
.type csnd_original_wait_media_result,%function
csnd_original_wait_media_result:
    .word 0xa9b67bfd
    b rv_native_resume_wait_media_result
.size csnd_original_wait_media_result, .-csnd_original_wait_media_result
.global csnd_original_wait_aux_status
.hidden csnd_original_wait_aux_status
.type csnd_original_wait_aux_status,%function
csnd_original_wait_aux_status:
    .word 0xa9bc7bfd
    b rv_native_resume_wait_aux_status
.size csnd_original_wait_aux_status, .-csnd_original_wait_aux_status
.global csnd_original_wait_finish
.hidden csnd_original_wait_finish
.type csnd_original_wait_finish,%function
csnd_original_wait_finish:
    .word 0x52800021
    b rv_native_resume_wait_finish
.size csnd_original_wait_finish, .-csnd_original_wait_finish
.global csnd_original_wait_stop_command
.hidden csnd_original_wait_stop_command
.type csnd_original_wait_stop_command,%function
csnd_original_wait_stop_command:
    .word 0xa9bd7bfd
    b rv_native_resume_wait_stop_command
.size csnd_original_wait_stop_command, .-csnd_original_wait_stop_command
.global csnd_original_wait_return_list
.hidden csnd_original_wait_return_list
.type csnd_original_wait_return_list,%function
csnd_original_wait_return_list:
    .word 0xa9be7bfd
    b rv_native_resume_wait_return_list
.size csnd_original_wait_return_list, .-csnd_original_wait_return_list
.global csnd_original_wait_return_request
.hidden csnd_original_wait_return_request
.type csnd_original_wait_return_request,%function
csnd_original_wait_return_request:
    .word 0xa9bb7bfd
    b rv_native_resume_wait_return_request
.size csnd_original_wait_return_request, .-csnd_original_wait_return_request
.global csnd_original_menu_route
.hidden csnd_original_menu_route
.type csnd_original_menu_route,%function
csnd_original_menu_route:
    .word 0xa9bc7bfd
    b rv_native_resume_menu_route
.size csnd_original_menu_route, .-csnd_original_menu_route
.global csnd_original_submenu_render
.hidden csnd_original_submenu_render
.type csnd_original_submenu_render,%function
csnd_original_submenu_render:
    .word 0xa9b87bfd
    b rv_native_resume_submenu_render
.size csnd_original_submenu_render, .-csnd_original_submenu_render
.global csnd_original_event
.hidden csnd_original_event
.type csnd_original_event,%function
csnd_original_event:
    .word 0xa9bc7bfd
    b rv_native_resume_event
.size csnd_original_event, .-csnd_original_event
