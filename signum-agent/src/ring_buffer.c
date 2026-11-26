#include "smpv2.h"
#include "platform.h"
#include <string.h>

int ring_init(signum_ring_t *r) {
    memset(r, 0, sizeof(*r));
    r->entries = (ring_entry_t *)sig_alloc_locked(sizeof(ring_entry_t) * RING_CAP);
    if (!r->entries) return -1;
    memset(r->entries, 0, sizeof(ring_entry_t) * RING_CAP);
    r->next_id = 1;
    return 0;
}

void ring_destroy(signum_ring_t *r) {
    if (r->entries) {
        sig_free_locked(r->entries, sizeof(ring_entry_t) * RING_CAP);
        r->entries = NULL;
    }
}

void ring_push(signum_ring_t *r, uint16_t port, const uint8_t *data, size_t len) {
    if (!r->entries || len == 0) return;
    size_t copy_len = len > RING_MAX_REQ ? RING_MAX_REQ : len;
    ring_entry_t *slot = &r->entries[r->head];
    slot->id = r->next_id++;
    slot->target_port = port;
    slot->len = copy_len;
    memcpy(slot->data, data, copy_len);
    r->head = (r->head + 1) % RING_CAP;
    if (r->count < RING_CAP) r->count++;
}

int ring_get_by_id(const signum_ring_t *r, uint64_t id, ring_entry_t *out) {
    if (!r->entries) return -1;
    for (size_t i = 0; i < r->count; i++) {
        if (r->entries[i].id == id) {
            *out = r->entries[i];
            return 0;
        }
    }
    return -1;
}
