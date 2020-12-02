
#include "libFEXDebug.h"

#include "common/Guest.h"

#include <stdio.h>

#include <link.h>
#include <dlfcn.h>

static void calldladdr(dladdr_params *params) {
  params->rv = dladdr(params->addr, (Dl_info *)params->info);
}

MAKE_THUNK(fex, DebugInit)

__attribute__((constructor)) static void onLibLoad() {
  fexthunks_fex_DebugInit((void*)&calldladdr);
}