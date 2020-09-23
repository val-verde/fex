#include <stdio.h>

#include <SDL2/SDL.h>
#include <SDL2/SDL_syswm.h>

#include "common/Host.h"
#include <dlfcn.h>

#include "callback_structs.inl"
#include "callback_typedefs.inl"

struct {
    #include "callback_unpacks_header.inl"
} *callback_unpacks;

#include "ldr_ptrs.inl"

struct SDL_AudioCallback_impl_userdata {
    void* fn;
    void* arg;
};

void SDL_AudioCallback_impl (void *userdata, Uint8 * stream, int len) {
    auto data = (SDL_AudioCallback_impl_userdata*)userdata;

    SDL_AudioCallbackCB_Args argsrv { data->arg, stream, len };

    call_guest(callback_unpacks->libSDL2_SDL_AudioCallbackCB, (void*) data->fn, &argsrv);
}

SDL_AudioDeviceID fexfn_impl_libSDL2_SDL_OpenAudioDevice_internal(const char* a0, int a1, const SDL_AudioSpec* a2, SDL_AudioSpec* a3, int a4) {
    
    // make a copy
    SDL_AudioSpec spec = *a2;

    // allocate our own user data -- yes we leak this
    auto data = new SDL_AudioCallback_impl_userdata();
    
    // initialize from guest
    data->fn = (void*)a2->callback;
    data->arg = a2->userdata;

    // replace host init with our values
    spec.userdata = data;
    spec.callback = &SDL_AudioCallback_impl;

    return fexldr_ptr_libSDL2_SDL_OpenAudioDevice(a0, a1, &spec, a3, a4);
}

#include "function_unpacks.inl"

static ExportEntry exports[] = {
    #include "tab_function_unpacks.inl"
    { nullptr, nullptr }
};

#include "ldr.inl"

EXPORTS(libSDL2)

