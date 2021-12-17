//  Copyright 2020 Two Sigma Investments, LP.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

use std::{
    ptr,
    ops::{Drop, Deref, DerefMut},
};
use nix::sys::mman::{mmap, munmap, ProtFlags, MapFlags};
use core::ffi::c_void;

/// A wrapper around `T` that allocate T on a page that can be shared with a
/// child process.
pub struct SharedMem<T> {
    addr: ptr::NonNull<T>,
}

impl<T: Copy> SharedMem<T> {
    pub fn new(val: T) -> Self {
        unsafe {
            let size = std::mem::size_of::<T>();
            assert!(size > 0, "SharedMem<T> used with a zero type");
            let addr = mmap(ptr::null_mut(), size,
                            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                            MapFlags::MAP_SHARED | MapFlags::MAP_ANONYMOUS,
                            -1, 0,
                            ).expect("mmap() failed") as *mut T;
            addr.write(val);
            Self { addr: ptr::NonNull::new_unchecked(addr) }
        }
    }
}

impl<T> Deref for SharedMem<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { self.addr.as_ref() }
    }
}

impl<T> DerefMut for SharedMem<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.addr.as_mut() }
    }
}

impl<T> Drop for SharedMem<T> {
    fn drop(&mut self) {
        unsafe {
            ptr::drop_in_place(self.addr.as_mut());
            munmap(self.addr.as_ptr() as *mut c_void,
                   std::mem::size_of::<T>()
                  ).expect("munmap() failed");
        }
    }
}
