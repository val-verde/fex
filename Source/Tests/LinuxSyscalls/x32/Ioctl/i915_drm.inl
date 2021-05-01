_BASIC_META(DRM_IOCTL_I915_INIT)
_BASIC_META(DRM_IOCTL_I915_FLUSH)
_BASIC_META(DRM_IOCTL_I915_FLIP)
_CUSTOM_META(DRM_IOCTL_I915_BATCHBUFFER, DRM_IOW(DRM_COMMAND_BASE + DRM_I915_BATCHBUFFER, FEX::HLE::x32::I915::fex_drm_i915_batchbuffer_t))
_CUSTOM_META(DRM_IOCTL_I915_IRQ_EMIT, DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_IRQ_EMIT, FEX::HLE::x32::I915::fex_drm_i915_irq_emit_t))
_BASIC_META(DRM_IOCTL_I915_IRQ_WAIT)
_CUSTOM_META(DRM_IOCTL_I915_GETPARAM, DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GETPARAM, FEX::HLE::x32::I915::fex_drm_i915_getparam_t))
_BASIC_META(DRM_IOCTL_I915_SETPARAM)
_CUSTOM_META(DRM_IOCTL_I915_ALLOC, DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_ALLOC, FEX::HLE::x32::I915::fex_drm_i915_mem_alloc_t))
_BASIC_META(DRM_IOCTL_I915_FREE)
_BASIC_META(DRM_IOCTL_I915_INIT_HEAP)
_CUSTOM_META(DRM_IOCTL_I915_CMDBUFFER, DRM_IOW( DRM_COMMAND_BASE + DRM_I915_CMDBUFFER, FEX::HLE::x32::I915::fex_drm_i915_cmdbuffer_t))
_BASIC_META(DRM_IOCTL_I915_DESTROY_HEAP)
_BASIC_META(DRM_IOCTL_I915_SET_VBLANK_PIPE)
_BASIC_META(DRM_IOCTL_I915_GET_VBLANK_PIPE)
_BASIC_META(DRM_IOCTL_I915_VBLANK_SWAP)
_BASIC_META(DRM_IOCTL_I915_HWS_ADDR)
_BASIC_META(DRM_IOCTL_I915_GEM_INIT)
_BASIC_META(DRM_IOCTL_I915_GEM_EXECBUFFER)
_BASIC_META(DRM_IOCTL_I915_GEM_EXECBUFFER2)
// DRM_IOCTL_I915_GEM_EXECBUFFER2_WR overlaps DRM_IOCTL_I915_GEM_EXECBUFFER2
_CUSTOM_META(DRM_IOCTL_I915_GEM_EXECBUFFER2_WR, DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_EXECBUFFER2_WR, struct drm_i915_gem_execbuffer2))
_BASIC_META(DRM_IOCTL_I915_GEM_PIN)
_BASIC_META(DRM_IOCTL_I915_GEM_UNPIN)
_BASIC_META(DRM_IOCTL_I915_GEM_BUSY)
_BASIC_META(DRM_IOCTL_I915_GEM_SET_CACHING)
_BASIC_META(DRM_IOCTL_I915_GEM_GET_CACHING)
_BASIC_META(DRM_IOCTL_I915_GEM_THROTTLE)
_BASIC_META(DRM_IOCTL_I915_GEM_ENTERVT)
_BASIC_META(DRM_IOCTL_I915_GEM_LEAVEVT)
_BASIC_META(DRM_IOCTL_I915_GEM_CREATE)
_BASIC_META(DRM_IOCTL_I915_GEM_PREAD)
_BASIC_META(DRM_IOCTL_I915_GEM_PWRITE)
_BASIC_META(DRM_IOCTL_I915_GEM_MMAP)
_BASIC_META(DRM_IOCTL_I915_GEM_MMAP_GTT)
// DRM_IOCTL_I915_GEM_MMAP_OFFSET overlaps DRM_IOCTL_I915_GEM_MMAP_GTT
#ifndef DRM_IOCTL_I915_GEM_MMAP_OFFSET
_CUSTOM_META(DRM_IOCTL_I915_GEM_MMAP_OFFSET, DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_MMAP_GTT, struct drm_i915_gem_mmap_offset))
#endif
_BASIC_META(DRM_IOCTL_I915_GEM_SET_DOMAIN)
_BASIC_META(DRM_IOCTL_I915_GEM_SW_FINISH)
_BASIC_META(DRM_IOCTL_I915_GEM_SET_TILING)
_BASIC_META(DRM_IOCTL_I915_GEM_GET_TILING)
_BASIC_META(DRM_IOCTL_I915_GEM_GET_APERTURE)
_BASIC_META(DRM_IOCTL_I915_GET_PIPE_FROM_CRTC_ID)
_BASIC_META(DRM_IOCTL_I915_GEM_MADVISE)
_BASIC_META(DRM_IOCTL_I915_OVERLAY_PUT_IMAGE)
_BASIC_META(DRM_IOCTL_I915_OVERLAY_ATTRS)
_BASIC_META(DRM_IOCTL_I915_SET_SPRITE_COLORKEY)
_BASIC_META(DRM_IOCTL_I915_GET_SPRITE_COLORKEY)
_BASIC_META(DRM_IOCTL_I915_GEM_WAIT)
_BASIC_META(DRM_IOCTL_I915_GEM_CONTEXT_CREATE)
// DRM_IOCTL_I915_GEM_CONTEXT_CREATE_EXT overlaps DRM_IOCTL_I915_GEM_CONTEXT_CREATE
_CUSTOM_META(DRM_IOCTL_I915_GEM_CONTEXT_CREATE_EXT, DRM_IOWR (DRM_COMMAND_BASE + DRM_I915_GEM_CONTEXT_CREATE, struct drm_i915_gem_context_create_ext))
_BASIC_META(DRM_IOCTL_I915_GEM_CONTEXT_DESTROY)
_BASIC_META(DRM_IOCTL_I915_REG_READ)
_BASIC_META(DRM_IOCTL_I915_GET_RESET_STATS)
_BASIC_META(DRM_IOCTL_I915_GEM_USERPTR)
_BASIC_META(DRM_IOCTL_I915_GEM_CONTEXT_GETPARAM)
_BASIC_META(DRM_IOCTL_I915_GEM_CONTEXT_SETPARAM)
_BASIC_META(DRM_IOCTL_I915_PERF_OPEN)
_BASIC_META(DRM_IOCTL_I915_PERF_ADD_CONFIG)
_BASIC_META(DRM_IOCTL_I915_PERF_REMOVE_CONFIG)
_BASIC_META(DRM_IOCTL_I915_QUERY)
_BASIC_META(DRM_IOCTL_I915_GEM_VM_CREATE)
_BASIC_META(DRM_IOCTL_I915_GEM_VM_DESTROY)

