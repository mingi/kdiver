
#ifdef USE_KVM

#include <linux/ioctl.h>
#include <linux/kvm.h>
#include "compat.h"
#include "ioctls.h"
#include "utils.h"

static const struct ioctl kvm_ioctls[] = {
	IOCTL(KVM_SET_MEMORY_REGION),
	IOCTL(KVM_CREATE_VCPU),
	IOCTL(KVM_GET_DIRTY_LOG),
	IOCTL(KVM_SET_NR_MMU_PAGES),
	IOCTL(KVM_GET_NR_MMU_PAGES),
	IOCTL(KVM_SET_USER_MEMORY_REGION),
	IOCTL(KVM_SET_TSS_ADDR),
	IOCTL(KVM_SET_IDENTITY_MAP_ADDR),
	IOCTL(KVM_S390_UCAS_MAP),
	IOCTL(KVM_S390_UCAS_UNMAP),
	IOCTL(KVM_S390_VCPU_FAULT),
	IOCTL(KVM_CREATE_IRQCHIP),
	IOCTL(KVM_IRQ_LINE),
	IOCTL(KVM_GET_IRQCHIP),
	IOCTL(KVM_SET_IRQCHIP),
	IOCTL(KVM_CREATE_PIT),
	IOCTL(KVM_IRQ_LINE_STATUS),
	IOCTL(KVM_REGISTER_COALESCED_MMIO),
	IOCTL(KVM_UNREGISTER_COALESCED_MMIO),
	IOCTL(KVM_ASSIGN_PCI_DEVICE),
	IOCTL(KVM_ASSIGN_IRQ),
	IOCTL(KVM_ASSIGN_DEV_IRQ),
	IOCTL(KVM_REINJECT_CONTROL),
	IOCTL(KVM_DEASSIGN_PCI_DEVICE),
	IOCTL(KVM_ASSIGN_SET_MSIX_NR),
	IOCTL(KVM_ASSIGN_SET_MSIX_ENTRY),
	IOCTL(KVM_DEASSIGN_DEV_IRQ),
	IOCTL(KVM_IRQFD),
	IOCTL(KVM_CREATE_PIT2),
	IOCTL(KVM_SET_BOOT_CPU_ID),
	IOCTL(KVM_IOEVENTFD),
	IOCTL(KVM_SET_CLOCK),
	IOCTL(KVM_GET_CLOCK),
	IOCTL(KVM_PPC_GET_PVINFO),
	IOCTL(KVM_SET_TSC_KHZ),
	IOCTL(KVM_GET_TSC_KHZ),
	IOCTL(KVM_ASSIGN_SET_INTX_MASK),
	IOCTL(KVM_SIGNAL_MSI),
#ifdef X86
	IOCTL(KVM_SET_MEMORY_ALIAS),
	IOCTL(KVM_GET_PIT),
	IOCTL(KVM_SET_PIT),
	IOCTL(KVM_GET_PIT2),
	IOCTL(KVM_SET_PIT2),
	IOCTL(KVM_SET_GSI_ROUTING),
	IOCTL(KVM_XEN_HVM_CONFIG),
	IOCTL(KVM_GET_MSRS),
	IOCTL(KVM_SET_MSRS),
	IOCTL(KVM_SET_CPUID),
	IOCTL(KVM_GET_LAPIC),
	IOCTL(KVM_SET_LAPIC),
	IOCTL(KVM_SET_CPUID2),
	IOCTL(KVM_GET_CPUID2),
	IOCTL(KVM_X86_SET_MCE),
	IOCTL(KVM_GET_VCPU_EVENTS),
	IOCTL(KVM_SET_VCPU_EVENTS),
	IOCTL(KVM_GET_DEBUGREGS),
	IOCTL(KVM_SET_DEBUGREGS),
	IOCTL(KVM_GET_XSAVE),
	IOCTL(KVM_SET_XSAVE),
	IOCTL(KVM_GET_XCRS),
	IOCTL(KVM_SET_XCRS),
#endif
#if defined(__powerpc__)
	IOCTL(KVM_PPC_GET_SMMU_INFO),
	IOCTL(KVM_PPC_ALLOCATE_HTAB),
#if defined(KVM_CREATE_SPAPR_TCE)
	IOCTL(KVM_CREATE_SPAPR_TCE),
#endif
#if defined(KVM_ALLOCATE_RMA)
	IOCTL(KVM_ALLOCATE_RMA),
#endif
	IOCTL(KVM_PPC_GET_HTAB_FD),
#endif
#if defined(__arm__) || defined(__aarch64__)
	IOCTL(KVM_ARM_SET_DEVICE_ADDR),
	IOCTL(KVM_ARM_VCPU_INIT),
#endif
	IOCTL(KVM_RUN),
	IOCTL(KVM_GET_REGS),
	IOCTL(KVM_SET_REGS),
	IOCTL(KVM_GET_SREGS),
	IOCTL(KVM_SET_SREGS),
	IOCTL(KVM_TRANSLATE),
	IOCTL(KVM_INTERRUPT),
	IOCTL(KVM_DEBUG_GUEST),
	IOCTL(KVM_SET_SIGNAL_MASK),
	IOCTL(KVM_GET_FPU),
	IOCTL(KVM_SET_FPU),
	IOCTL(KVM_TPR_ACCESS_REPORTING),
	IOCTL(KVM_SET_VAPIC_ADDR),
#if defined(__s390__)
	IOCTL(KVM_S390_INTERRUPT),
	IOCTL(KVM_S390_STORE_STATUS),
	IOCTL(KVM_S390_SET_INITIAL_PSW),
	IOCTL(KVM_S390_INITIAL_RESET),
#endif
	IOCTL(KVM_GET_MP_STATE),
	IOCTL(KVM_SET_MP_STATE),
	IOCTL(KVM_NMI),
	IOCTL(KVM_SET_GUEST_DEBUG),
	IOCTL(KVM_X86_SETUP_MCE),
	IOCTL(KVM_X86_GET_MCE_CAP_SUPPORTED),
#if defined(KVM_IA64_VCPU_GET_STACK)
	IOCTL(KVM_IA64_VCPU_GET_STACK),
	IOCTL(KVM_IA64_VCPU_SET_STACK),
#endif
	IOCTL(KVM_ENABLE_CAP),
	IOCTL(KVM_DIRTY_TLB),
	IOCTL(KVM_GET_ONE_REG),
	IOCTL(KVM_SET_ONE_REG),
	IOCTL(KVM_KVMCLOCK_CTRL),
	IOCTL(KVM_GET_REG_LIST),
};

static const char *const kvm_devs[] = {
	"kvm",
};

static const struct ioctl_group kvm_grp = {
	.devtype = DEV_MISC,
	.devs = kvm_devs,
	.devs_cnt = ARRAY_SIZE(kvm_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = kvm_ioctls,
	.ioctls_cnt = ARRAY_SIZE(kvm_ioctls),
};

REG_IOCTL_GROUP(kvm_grp)

#endif	/* USE_KVM */