#pragma once

typedef struct
{
  const char *dli_fname;
  void *dli_fbase;
  const char *dli_sname;
  void *dli_saddr;
} dladdr_info;

typedef struct {
  int rv;
  void *addr;
  dladdr_info *info;
} dladdr_params;
