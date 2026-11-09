#include <assert.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
static kern_return_t fake_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);
static kern_return_t fake_read(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
#define mach_vm_region fake_region
#define mach_vm_read_overwrite fake_read
#define main scanner_main
#include "../wechat_cli/bin/find_all_keys_macos.c"
#undef main
static unsigned char memory[READ_CHUNK + 64];
#define BASE 0x10000
static kern_return_t fake_region(vm_map_t task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *count, mach_port_t *object) {
    (void)task; (void)flavor; (void)count;
    if (*address > BASE) return KERN_INVALID_ADDRESS;
    *address = BASE; *size = sizeof(memory); *object = MACH_PORT_NULL;
    ((vm_region_basic_info_t)info)->protection = VM_PROT_READ;
    return KERN_SUCCESS;
}
static kern_return_t fake_read(vm_map_t task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t output, mach_vm_size_t *actual) {
    (void)task;
    if (address < BASE || address - BASE + size > sizeof(memory)) return KERN_INVALID_ADDRESS;
    memcpy((void *)output, memory + address - BASE, size); *actual = size;
    return KERN_SUCCESS;
}
int main(void) {
    const unsigned char needle[] = "boundary-marker";
    const size_t offset = READ_CHUNK - 3;
    memcpy(memory + offset, needle, sizeof(needle) - 1);
    Pattern pattern = {needle, sizeof(needle) - 1};
    mach_vm_address_t addresses[8];
    Hits hits = {addresses, 8, 0, 0};
    ScanStats stats = {0, 0, 0};
    assert(scan_task(0, &pattern, 1, pattern.length, &hits, &stats) == KERN_SUCCESS);
    assert(stats.complete && hits.saved_count == 1 && addresses[0] == BASE + offset);
    return 0;
}
