/* STCForge MCS-251 BFD architecture. SPDX-License-Identifier: GPL-3.0-or-later */
#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"

/* Address width includes the debugger's synthetic SFR window. */
const bfd_arch_info_type bfd_mcs251_arch =
{
  16, 32, 8, bfd_arch_mcs251, 0, "mcs251", "mcs251", 0, true,
  bfd_default_compatible, bfd_default_scan, bfd_arch_default_fill, NULL, 0
};
