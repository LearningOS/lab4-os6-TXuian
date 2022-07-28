//! File and filesystem-related syscalls
use crate::fs::OSInode;
use crate::fs::StatMode;
use crate::fs::get_root_inode;
use crate::mm::translated_byte_buffer;
use crate::mm::translated_str;
use crate::mm::translated_refmut;
use crate::task::current_user_token;
use crate::task::current_task;
use crate::fs::open_file;
use crate::fs::OpenFlags;
use crate::fs::Stat;
use crate::mm::UserBuffer;
use alloc::sync::Arc;
use easy_fs::DiskInodeType;

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.write(
            UserBuffer::new(translated_byte_buffer(token, buf, len))
        ) as isize
    } else {
        -1
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.read(
            UserBuffer::new(translated_byte_buffer(token, buf, len))
        ) as isize
    } else {
        -1
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(inode) = open_file(
        path.as_str(),
        OpenFlags::from_bits(flags).unwrap()
    ) {
        let mut inner = task.inner_exclusive_access();
        let fd = inner.alloc_fd();
        inner.fd_table[fd] = Some(inode.clone());
        inner.opened_file_table.insert(fd as u32, Some(inode));
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    inner.opened_file_table.remove(&(fd as u32).clone());
    inner.fd_table[fd].take();
    0
}

// YOUR JOB: 扩展 easy-fs 和内核以实现以下三个 syscall
pub fn sys_fstat(_fd: usize, _st: *mut Stat) -> isize {
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if _fd >= inner.fd_table.len() {
        return -1;
    }
    let fd_u32 = _fd as u32;
    if let Some(file) = inner.opened_file_table.get(&fd_u32) {
        let os_inode = file.clone().unwrap();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        let true_st = translated_refmut(current_user_token(), _st);
        let inode = os_inode.get_inode();
        true_st.dev = 0;
        true_st.ino = os_inode.inode_number as u64;
        true_st.nlink = inode.get_nlink();
        true_st.mode = match inode.get_file_type() {
            DiskInodeType::File => StatMode::FILE,
            DiskInodeType::Directory => StatMode::DIR,
            _ => StatMode::NULL,
        };
        0
    } else {
        -1
    }
}

pub fn sys_linkat(_old_name: *const u8, _new_name: *const u8) -> isize {
    // in this lab only has '/'
    // two different inode to one same block
    let root_inode = get_root_inode();
    let token = current_user_token();
    let (old_name, new_name) = 
        (translated_str(token, _old_name), translated_str(token, _new_name));
    // link new_name to old_name
    // get old inode
    root_inode.create_link(old_name.as_str(), new_name.as_str())
}

pub fn sys_unlinkat(_name: *const u8) -> isize {
    // in this lab only has '/'
    // two different inode to one same block
    let root_inode = get_root_inode();
    let token = current_user_token();
    let inode_name = translated_str(token, _name);
    root_inode.destory_entry(inode_name.as_str())
}
