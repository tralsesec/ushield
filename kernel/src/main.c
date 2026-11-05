#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("µShield Project");
MODULE_DESCRIPTION("µShield Ring 0 Sandbox & Telemetry Module");
MODULE_VERSION("0.1");

static int __init ushield_init(void) {
  pr_info("[µShield] Driver loaded into Ring 0\n");
  return 0;
}

static void __exit ushield_exit(void) {
  pr_info("[µShield] Driver unloaded from Ring 0\n");
}

module_init(ushield_init);
module_exit(ushield_exit);
