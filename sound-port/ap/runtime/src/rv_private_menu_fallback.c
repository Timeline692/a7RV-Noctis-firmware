/* These helpers belong only to the added sound metadata. No native menu
 * lookup is replaced globally. Unknown private IDs remain unavailable. */
#include <stdint.h>
extern uint32_t csnd_menu_import_blocked(uint32_t);
uint32_t csnd_original_menu_blocked(uint32_t mid){(void)mid;return 1;}
uint32_t csnd_previous_menu_blocked(uint32_t mid){return csnd_menu_import_blocked(mid);}
