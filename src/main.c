// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2025 wolfSSL Inc. <info@wolfssl.com>
 */

#include "version.h"
#include "device.h"
#include "noise.h"
#include "queueing.h"
#include "ratelimiter.h"
#include "netlink.h"
#include "uapi/wolfguard.h"

#include <linux/init.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>

static int __init mod_init(void)
{
	int ret;

#ifdef DEBUG
	if (!wg_allowedips_selftest() || !wg_packet_counter_selftest() ||
	    !wg_ratelimiter_selftest())
		return -ENOTRECOVERABLE;
#endif
	wg_noise_init();

	ret = wg_device_init();
	if (ret < 0)
		goto err_device;

	ret = wg_genetlink_init();
	if (ret < 0)
		goto err_netlink;

	pr_info("WolfGuard " WOLFGUARD_VERSION " loaded. See www.wolfssl.com for information.\n");
	pr_info("Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.\n");
	pr_info("Portions Copyright (C) 2020-2025 wolfSSL Inc. <info@wolfssl.com>\n");

	return 0;

err_netlink:
	wg_device_uninit();
err_device:
	return ret;
}

static void __exit mod_exit(void)
{
	wg_genetlink_uninit();
	wg_device_uninit();
        wg_noise_uninit();
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("WolfGuard secure network tunnel");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com> and Daniel Pouzzner <douzzer@wolfssl.com>");
MODULE_VERSION(WOLFGUARD_VERSION);
MODULE_ALIAS_RTNL_LINK(KBUILD_MODNAME);
MODULE_ALIAS_GENL_FAMILY(WG_GENL_NAME);
MODULE_INFO(intree, "N");

#if defined(WOLFCRYPTO_SHIM_H) && defined(MODULE_IMPORT_NS)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0))
MODULE_IMPORT_NS("WOLFSSL");
#else
MODULE_IMPORT_NS(WOLFSSL);
#endif
#endif

#include <linux/kprobes.h>
void *my_kallsyms_lookup_name(const char *name);
void *my_kallsyms_lookup_name(const char *name) {
    static typeof(kallsyms_lookup_name) *kallsyms_lookup_name_ptr = NULL;
    static struct kprobe kallsyms_lookup_name_kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    unsigned long a;

    if (! kallsyms_lookup_name_ptr) {
        int ret;
        kallsyms_lookup_name_kp.addr = NULL;
        if ((ret = register_kprobe(&kallsyms_lookup_name_kp)) != 0) {
            pr_err_once("ERROR: register_kprobe(&kallsyms_lookup_name_kp) failed: %d", ret);
            return 0;
        }
        kallsyms_lookup_name_ptr = (typeof(kallsyms_lookup_name_ptr))kallsyms_lookup_name_kp.addr;
        unregister_kprobe(&kallsyms_lookup_name_kp);
        if (! kallsyms_lookup_name_ptr) {
            pr_err_once("ERROR: kallsyms_lookup_name_kp.addr is null.");
            return 0;
        }
    }

    a = kallsyms_lookup_name_ptr(name);
    return (void *)a;
}
