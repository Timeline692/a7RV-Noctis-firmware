/* Keep the RV's original descriptor-count gate for every original item.
 * Private menu IDs use the newly expanded native caches and typed maps. */
.text
.align 2
.global csnd_rv_cache_bound_gate
.type csnd_rv_cache_bound_gate,%function
.extern csnd_rv_cache_allowed
.extern csnd_rv_cache_blocked
csnd_rv_cache_bound_gate:
 cbz x1,rv_cache_reject
 cmp w28,#1592
 b.lo rv_cache_original_compare
 cmp w28,#1599
 b.ls rv_cache_accept
rv_cache_original_compare:
 cmp w28,w0
 b.ge rv_cache_reject
rv_cache_accept:
 /* Targets stay undefined until final linking, preventing .equ folding. */
 b csnd_rv_cache_allowed
rv_cache_reject:
 b csnd_rv_cache_blocked
.size csnd_rv_cache_bound_gate,.-csnd_rv_cache_bound_gate
