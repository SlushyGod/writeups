# HTB Distopia - PWN | Complaint Conglomerate

This challenge involved filling up the heap to get a call to malloc_consolidate and convert fast bins to unsorted bins. After that leak a libc address through the unsorted bins and use that to ROP throughout the library. To trigger the ROP chain it can be performed when the complaint was processed by AI as it memcopied more data than the buffer could hold.

Looking at checksec:
```
$ checksec complaint_conglomerate
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So when first doing an quick scan of the binary we spot a few obvious things:
- memcopy buffer overflow
- not setting freed pointers to NULL
- not checking if there is an existing complaint before overwriting the pointer

memcopy buffer overflow, the buffer is only `0xxx` size, and `0x50` bytes are being read in from a complaint stored in the heap
```

```

complaints are stored inside of the heap, however there is no check being performed if there is a complaint with an existing ID, which lets someone write multiple complaints with the same ID which causes memory leaks
```

```

Finally pointers of freed chunks are not NULLed, so these can chunks can be accessed even if they have been "deleted"
```

```

Putting these pieces together we can abuse the buffer overflow since there is no stack canary, load our payload in the heap, and then overwrite RIP using the AI function. The only issue is that since PIE is enabled, the `.text` section is randomized and we don't know where to return to. So the first step is finding a leak to any executable portion of memory.

Start targeting the heap to do this, so the first thing to do is to checkout the version of glibc that they gave us.
```
$ strings <libc_file> | grep "GNU C Library"
GNU C Library (Debian GLIBC 2.36-9+deb12u4) stable release version 2.36.
```

So we are operating with version 2.36. One technique we can use to pull libc memory addresses is using either small bins, large bins, or unsorted bins to leak out the structure that holds the doubly linked lists. The only issue is that chunks can only be allocated for `0x30` and `0x50` bytes. Both of these fall in the tcache and fastbin sizes, which are stored as a singly linked list and wouldn't contain pointers to libc when they are freed.

There is a caveat to the above though. Fastbins can be consolidated into small or unsorted bins whenever there is a call to malloc_consolidate. In glibc 2.36 there are 5 ways to get the allocator to consolidate memory.
- a large chunk is being allocated
- the heap is completely full
- if the chunk size is >= fastbin consolidation threshold
- mtrim function call
- mallopt function call

The only viable option is to fill up the heap, which fortunately for us, when allocating memory, there are no checks to prevent us from constantly creating new complaint forms for the same ID.

So using the 0x50 chunks we can calculate how many chunks we will need to create in the heap, to get close to filling up the heap.

[just gdb, show how much we have in TOP]

When performing a malloc call, the size you request isn't the same as the size that is allocated as chunks have metadata, so mallocing 0x50 will actually give you a size 0x60 chunk. TOP / 0x60 = 1390. So we need to allocate this many chunks on the heap, till it is full.

The next thing we need to do is make sure that fastbin has some chunks in it. Tcache by default holds 7 chunks, after that fastbin will start to get filled up.


HTB{f1lLiNg_tH3_he4p_t0_cOnSOlIDa73_tH3_be45t_22a22e2f6fcdc813034c2ee4a77d6cbb}