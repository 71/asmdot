#ifdef _WIN32
  #include <windows.h>
#else
  #include <sys/mman.h>
#endif

boolean createRwxBuffer(size_t maxSize, void** addr) {
  #ifdef _WIN32
    *addr = VirtualAlloc(NULL, maxSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  #else
    *addr = mmap(0, maxSize, PROT_NONE, MAP_ANON | MAP_PRIVATE);
  #endif

  return *addr != 0;
}

boolean destroyRwxBuffer(void* addr, size_t maxSize) {
  #ifdef _WIN32
    return VirtualFree(addr, maxSize, MEM_RELEASE);
  #else
    return munmap(addr, maxSize);
  #endif
}

boolean resizeRwxBuffer(void* addr, size_t newSize) {
  #ifdef _WIN32
    return VirtualAlloc(addr, newSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE) == addr;
  #else
    return mprotect(addr, newSize, PROT_READ | PROT_WRITE | PROT_EXEC);
  #endif
}
