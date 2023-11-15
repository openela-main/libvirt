# -*- rpm-spec -*-

# This spec file assumes you are building on a Fedora or RHEL version
# that's still supported by the vendor. It may work on other distros
# or versions, but no effort will be made to ensure that going forward.
%define min_rhel 8
%define min_fedora 33

%define arches_qemu_kvm         %{ix86} x86_64 %{power64} %{arm} aarch64 s390x
%if 0%{?rhel}
    %if 0%{?rhel} > 8
        %define arches_qemu_kvm     x86_64 aarch64 s390x
    %else
        %define arches_qemu_kvm     x86_64 %{power64} aarch64 s390x
    %endif
%endif

%define arches_64bit            x86_64 %{power64} aarch64 s390x riscv64
%define arches_x86              %{ix86} x86_64

%define arches_systemtap_64bit  %{arches_64bit}
%define arches_dmidecode        %{arches_x86}
%define arches_xen              %{arches_x86} aarch64
%define arches_vbox             %{arches_x86}
%define arches_ceph             %{arches_64bit}
%define arches_zfs              %{arches_x86} %{power64} %{arm}
%define arches_numactl          %{arches_x86} %{power64} aarch64 s390x
%define arches_numad            %{arches_x86} %{power64} aarch64

# The hypervisor drivers that run in libvirtd
%define with_qemu          0%{!?_without_qemu:1}
%define with_lxc           0%{!?_without_lxc:1}
%define with_libxl         0%{!?_without_libxl:1}
%define with_vbox          0%{!?_without_vbox:1}

%ifarch %{arches_qemu_kvm}
    %define with_qemu_kvm      %{with_qemu}
%else
    %define with_qemu_kvm      0
%endif

%define with_qemu_tcg      %{with_qemu}

# RHEL disables TCG on all architectures
%if 0%{?rhel}
    %define with_qemu_tcg 0
%endif

%if ! %{with_qemu_tcg} && ! %{with_qemu_kvm}
    %define with_qemu 0
%endif

# Then the hypervisor drivers that run outside libvirtd, in libvirt.so
%define with_openvz        0%{!?_without_openvz:1}
%define with_vmware        0%{!?_without_vmware:1}
%define with_esx           0%{!?_without_esx:1}
%define with_hyperv        0%{!?_without_hyperv:1}

# Then the secondary host drivers, which run inside libvirtd
%define with_storage_rbd      0%{!?_without_storage_rbd:1}
%if 0%{?fedora}
    %define with_storage_sheepdog 0%{!?_without_storage_sheepdog:1}
%else
    %define with_storage_sheepdog 0
%endif

%define with_storage_gluster 0%{!?_without_storage_gluster:1}
%if 0%{?rhel}
    # Glusterfs has been dropped in RHEL-9, and before that
    # was only enabled on arches where KVM exists
    %if 0%{?rhel} > 8
        %define with_storage_gluster 0
    %else
        %ifnarch %{arches_qemu_kvm}
            %define with_storage_gluster 0
        %endif
    %endif
%endif

# Fedora has zfs-fuse
%if 0%{?fedora}
    %define with_storage_zfs      0%{!?_without_storage_zfs:1}
%else
    %define with_storage_zfs      0
%endif

%define with_storage_iscsi_direct 0%{!?_without_storage_iscsi_direct:1}
# libiscsi has been dropped in RHEL-9
%if 0%{?rhel} > 8
    %define with_storage_iscsi_direct 0
%endif

# Other optional features
%define with_numactl          0%{!?_without_numactl:1}

# A few optional bits off by default, we enable later
%define with_fuse             0
%define with_sanlock          0
%define with_numad            0
%define with_firewalld_zone   0
%define with_netcf            0
%define with_libssh2          0
%define with_wireshark        0
%define with_libssh           0
%define with_dmidecode        0

# Finally set the OS / architecture specific special cases

# Architecture-dependent features
%ifnarch %{arches_xen}
    %define with_libxl 0
%endif
%ifnarch %{arches_vbox}
    %define with_vbox 0
%endif
%ifnarch %{arches_numactl}
    %define with_numactl 0
%endif
%ifnarch %{arches_zfs}
    %define with_storage_zfs 0
%endif
%ifnarch %{arches_ceph}
    %define with_storage_rbd 0
%endif

# RHEL doesn't ship many hypervisor drivers
%if 0%{?rhel}
    %define with_openvz 0
    %define with_vbox 0
    %define with_vmware 0
    %define with_libxl 0
    %define with_hyperv 0
    %define with_vz 0
    %define with_lxc 0
%endif

%define with_firewalld_zone 0%{!?_without_firewalld_zone:1}

%if (0%{?fedora} && 0%{?fedora} < 34) || (0%{?rhel} && 0%{?rhel} < 9)
    %define with_netcf 0%{!?_without_netcf:1}
%endif


# fuse is used to provide virtualized /proc for LXC
%if %{with_lxc}
    %define with_fuse      0%{!?_without_fuse:1}
%endif

# Enable sanlock library for lock management with QEMU
# Sanlock is available only on arches where kvm is available for RHEL
%if 0%{?fedora}
    %define with_sanlock 0%{!?_without_sanlock:1}
%endif
%if 0%{?rhel}
    %ifarch %{arches_qemu_kvm}
        %define with_sanlock 0%{!?_without_sanlock:1}
    %endif
%endif

# Enable libssh2 transport for new enough distros
%if 0%{?fedora}
    %define with_libssh2 0%{!?_without_libssh2:1}
%endif

# Enable wireshark plugins for all distros
%define with_wireshark 0%{!?_without_wireshark:1}
%define wireshark_plugindir %(pkg-config --variable plugindir wireshark)/epan

# Enable libssh transport for all distros
%define with_libssh 0%{!?_without_libssh:1}

%if %{with_qemu} || %{with_lxc}
# numad is used to manage the CPU and memory placement dynamically,
# it's not available on many non-x86 architectures.
    %ifarch %{arches_numad}
        %define with_numad    0%{!?_without_numad:1}
    %endif
%endif

%ifarch %{arches_dmidecode}
    %define with_dmidecode 0%{!?_without_dmidecode:1}
%endif

%define with_modular_daemons 0
%if 0%{?fedora} >= 35 || 0%{?rhel} >= 9
    %define with_modular_daemons 1
%endif

# Force QEMU to run as non-root
%define qemu_user  qemu
%define qemu_group  qemu

# Locations for QEMU data
%define qemu_moddir %{_libdir}/qemu
%define qemu_datadir %{_datadir}/qemu


# RHEL releases provide stable tool chains and so it is safe to turn
# compiler warning into errors without being worried about frequent
# changes in reported warnings
%if 0%{?rhel}
    %define enable_werror -Dwerror=true
%else
    %define enable_werror -Dwerror=false -Dgit_werror=disabled
%endif

%define tls_priority "@LIBVIRT,SYSTEM"


Summary: Library providing a simple virtualization API
Name: libvirt
Version: 8.0.0
Release: 22%{?dist}%{?extra_release}
License: LGPLv2+
URL: https://libvirt.org/

%if %(echo %{version} | grep -q "\.0$"; echo $?) == 1
    %define mainturl stable_updates/
%endif
Source: https://libvirt.org/sources/%{?mainturl}libvirt-%{version}.tar.xz
Source1: symlinks

Patch1: libvirt-RHEL-Hack-around-changed-Broadwell-Haswell-CPUs.patch
Patch2: libvirt-RHEL-Add-rhel-machine-types-to-qemuDomainMachineNeedsFDC.patch
Patch3: libvirt-RHEL-Fix-virConnectGetMaxVcpus-output.patch
Patch4: libvirt-RHEL-qemu-Add-ability-to-set-sgio-values-for-hostdev.patch
Patch5: libvirt-RHEL-qemu-Add-check-for-unpriv-sgio-for-SCSI-generic-host-device.patch
Patch6: libvirt-RHEL-virscsi-Check-device-type-before-getting-it-s-dev-node-name.patch
Patch7: libvirt-RHEL-virscsi-Support-TAPEs-in-virSCSIDeviceGetDevName.patch
Patch8: libvirt-RHEL-virscsi-Introduce-and-use-virSCSIDeviceGetUnprivSGIOSysfsPath.patch
Patch9: libvirt-RHEL-virutil-Accept-non-block-devices-in-virGetDeviceID.patch
Patch10: libvirt-RHEL-Enable-usage-of-x-blockdev-reopen.patch
Patch11: libvirt-Revert-report-error-when-virProcessGetStatInfo-is-unable-to-parse-data.patch
Patch12: libvirt-qemu-fix-inactive-snapshot-revert.patch
Patch13: libvirt-qemuDomainSetupDisk-Initialize-targetPaths.patch
Patch14: libvirt-RHEL-Remove-glib-2.64.0-workaround-for-GSource-race.patch
Patch15: libvirt-qemu_command-Generate-memory-only-after-controllers.patch
Patch16: libvirt-qemu-Validate-domain-definition-even-on-migration.patch
Patch17: libvirt-node_device-Rework-udevKludgeStorageType.patch
Patch18: libvirt-node_device-Treat-NVMe-disks-as-regular-disks.patch
Patch19: libvirt-conf-Introduce-memory-allocation-threads.patch
Patch20: libvirt-qemu_capabilities-Detect-memory-backend-.prealloc-threads-property.patch
Patch21: libvirt-qemu_validate-Validate-prealloc-threads-against-qemuCpas.patch
Patch22: libvirt-qemu_command-Generate-prealloc-threads-property.patch
Patch23: libvirt-cpu_map-Disable-cpu64-rhel-for-host-model-and-baseline.patch
Patch24: libvirt-cputest-Drop-some-old-artificial-baseline-tests.patch
Patch25: libvirt-cputest-Give-better-names-to-baseline-tests.patch
Patch26: libvirt-cputest-Add-some-real-world-baseline-tests.patch
Patch27: libvirt-cpu_x86-Consolidate-signature-match-in-x86DecodeUseCandidate.patch
Patch28: libvirt-cpu_x86-Refactor-feature-list-comparison-in-x86DecodeUseCandidate.patch
Patch29: libvirt-cpu_x86-Penalize-disabled-features-when-computing-CPU-model.patch
Patch30: libvirt-cpu_x86-Ignore-enabled-features-for-input-models-in-x86DecodeUseCandidate.patch
Patch31: libvirt-nwfilter-fix-crash-when-counting-number-of-network-filters.patch
Patch32: libvirt-virDomainDiskDefValidate-Improve-error-messages-for-startupPolicy-checks.patch
Patch33: libvirt-domain_validate-Split-out-validation-of-disk-startup-policy.patch
Patch34: libvirt-virDomainDiskDefValidateStartupPolicy-Validate-disk-type-better.patch
Patch35: libvirt-virDomainDiskTranslateSourcePool-Fix-check-of-startupPolicy-definition.patch
Patch36: libvirt-conf-virtiofs-add-thread_pool-element.patch
Patch37: libvirt-qemu-virtiofs-format-thread-pool-size.patch
Patch38: libvirt-conf-Move-virDomainObj-originalMemlock-into-qemuDomainObjPrivate.patch
Patch39: libvirt-qemu_domain-Format-qemuDomainObjPrivate-originalMemlock.patch
Patch40: libvirt-qemu-Add-qemuDomainSetMaxMemLock-helper.patch
Patch41: libvirt-qemu_migration-Use-qemuDomainSetMaxMemLock.patch
Patch42: libvirt-qemu_migration-Restore-original-memory-locking-limit.patch
Patch43: libvirt-Add-VIR_MIGRATE_ZEROCOPY-flag.patch
Patch44: libvirt-virsh-Add-support-for-VIR_MIGRATE_ZEROCOPY-flag.patch
Patch45: libvirt-qemu_migration-Implement-VIR_MIGRATE_ZEROCOPY-flag.patch
Patch46: libvirt-security_selinux.c-Relabel-existing-mode-bind-UNIX-sockets.patch
Patch47: libvirt-RHEL-qemu_migration-Fix-restoring-memlock-limit-on-destination.patch
Patch48: libvirt-qemu_process-Don-t-require-a-hugetlbfs-mount-for-memfd.patch
Patch49: libvirt-qemu_namespace-Tolerate-missing-ACLs-when-creating-a-path-in-namespace.patch
Patch50: libvirt-qemu_namespace-Fix-a-corner-case-in-qemuDomainGetPreservedMounts.patch
Patch51: libvirt-qemu_namespace-Introduce-qemuDomainNamespaceSetupPath.patch
Patch52: libvirt-qemu_process.c-Propagate-hugetlbfs-mounts-on-reconnect.patch
Patch53: libvirt-qemuProcessReconnect-Don-t-build-memory-paths.patch
Patch54: libvirt-util-json-Split-out-array-strinlist-conversion-from-virJSONValueObjectGetStringArray.patch
Patch55: libvirt-qemuAgentGetDisks-Don-t-use-virJSONValueObjectGetStringArray-for-optional-data.patch
Patch56: libvirt-virpidfile-Add-virPidFileReadPathIfLocked-func.patch
Patch57: libvirt-qemu-tpm-Get-swtpm-pid-without-binary-validation.patch
Patch58: libvirt-qemu_tpm-Do-async-IO-when-starting-swtpm-emulator.patch
Patch59: libvirt-qemu-gpu-Get-pid-without-binary-validation.patch
Patch60: libvirt-build-Only-install-libvirt-guests-when-building-libvirtd.patch
Patch61: libvirt-tools-Fix-install_mode-for-some-scripts.patch
Patch62: libvirt-qemu-Ignore-missing-vm.unprivileged_userfaultfd-sysctl.patch
Patch63: libvirt-nodedev-fix-reported-error-msg-in-css-cap-XML-parsing.patch
Patch64: libvirt-util-refactor-virDomainDeviceCCWAddress-into-virccw.h.patch
Patch65: libvirt-util-refactor-virDomainCCWAddressAsString-into-virccw.patch
Patch66: libvirt-util-make-reuse-of-ccw-device-address-format-constant.patch
Patch67: libvirt-util-refactor-ccw-address-constants-into-virccw.patch
Patch68: libvirt-util-refactor-virDomainCCWAddressIncrement-into-virccw.patch
Patch69: libvirt-util-refactor-virDomainDeviceCCWAddressIsValid-into-virccw.patch
Patch70: libvirt-util-refactor-virDomainDeviceCCWAddressEqual-into-virccw.patch
Patch71: libvirt-conf-adjust-method-name-virDomainDeviceCCWAddressParseXML.patch
Patch72: libvirt-util-add-ccw-device-address-parsing-into-virccw.patch
Patch73: libvirt-util-add-virCCWDeviceAddressFromString-to-virccw.patch
Patch74: libvirt-nodedev-refactor-css-format-from-ccw-format-method.patch
Patch75: libvirt-nodedev-refactor-ccw-device-address-parsing-from-XML.patch
Patch76: libvirt-nodedev-refactor-css-XML-parsing-from-ccw-XML-parsing.patch
Patch77: libvirt-schemas-refactor-out-nodedev-ccw-address-schema.patch
Patch78: libvirt-nodedev-add-optional-device-address-of-channel-device-to-css-device.patch
Patch79: libvirt-nodedev-add-tests-for-optional-device-address-to-css-device.patch
Patch80: libvirt-nodedev-prevent-internal-error-on-dev_busid-parse.patch
Patch81: libvirt-rpc-Fix-memory-leak-of-fds.patch
Patch82: libvirt-qemu_namespace-Don-t-leak-memory-in-qemuDomainGetPreservedMounts.patch
Patch83: libvirt-vircpi-Add-PCIe-5.0-and-6.0-link-speeds.patch
Patch84: libvirt-conf-Make-VIR_DOMAIN_NET_TYPE_ETHERNET-not-share-host-view.patch
Patch85: libvirt-qemu-domain-Fix-logic-when-tainting-domain.patch
Patch86: libvirt-qemu-agent-Make-fetching-of-can-offline-member-from-guest-query-vcpus-optional.patch
Patch87: libvirt-qemu-monitor-Drop-old-monitor-fields-from-struct-_qemuMonitorMessage.patch
Patch88: libvirt-qemu-Make-struct-_qemuMonitorMessage-private.patch
Patch89: libvirt-qemu-monitor-Move-declaration-of-struct-_qemuMonitor-to-qemu_monitor_priv.h.patch
Patch90: libvirt-qemu-qemuBlockGetNamedNodeData-Remove-pointless-error-path.patch
Patch91: libvirt-qemu-monitor-Store-whether-query-named-block-nodes-supports-flat-parameter.patch
Patch92: libvirt-qemuMonitorJSONBlockStatsUpdateCapacityBlockdev-Use-flat-mode-of-query-named-block-nodes.patch
Patch93: libvirt-qemu-relax-shared-memory-check-for-vhostuser-daemons.patch
Patch94: libvirt-virpci-Resolve-leak-in-virPCIVirtualFunctionList-cleanup.patch
Patch95: libvirt-node_device_conf-Avoid-memleak-in-virNodeDeviceGetPCIVPDDynamicCap.patch
Patch96: libvirt-nodedev-update-transient-mdevs.patch
Patch97: libvirt-lib-Set-up-cpuset-controller-for-restrictive-numatune.patch

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-config-network = %{version}-%{release}
Requires: libvirt-daemon-config-nwfilter = %{version}-%{release}
%if %{with_libxl}
Requires: libvirt-daemon-driver-libxl = %{version}-%{release}
%endif
%if %{with_lxc}
Requires: libvirt-daemon-driver-lxc = %{version}-%{release}
%endif
%if %{with_qemu}
Requires: libvirt-daemon-driver-qemu = %{version}-%{release}
%endif
# We had UML driver, but we've removed it.
Obsoletes: libvirt-daemon-driver-uml <= 5.0.0
Obsoletes: libvirt-daemon-uml <= 5.0.0
%if %{with_vbox}
Requires: libvirt-daemon-driver-vbox = %{version}-%{release}
%endif
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}

Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-client = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

# All build-time requirements. Run-time requirements are
# listed against each sub-RPM
BuildRequires: python3-docutils
BuildRequires: gcc
BuildRequires: meson >= 0.54.0
BuildRequires: ninja-build
BuildRequires: git
BuildRequires: perl-interpreter
%if 0%{?rhel} == 8
BuildRequires: python3-devel
%else
BuildRequires: python3
%endif
%if %{with_libxl}
BuildRequires: xen-devel
%endif
BuildRequires: glib2-devel >= 2.56
BuildRequires: libxml2-devel
BuildRequires: libxslt
BuildRequires: readline-devel
BuildRequires: bash-completion >= 2.0
BuildRequires: gettext
BuildRequires: libtasn1-devel
BuildRequires: gnutls-devel
BuildRequires: libattr-devel
# For pool-build probing for existing pools
BuildRequires: libblkid-devel >= 2.17
# for augparse, optionally used in testing
BuildRequires: augeas
BuildRequires: systemd-devel >= 185
BuildRequires: libpciaccess-devel >= 0.10.9
BuildRequires: yajl-devel
%if %{with_sanlock}
BuildRequires: sanlock-devel >= 2.4
%endif
BuildRequires: libpcap-devel >= 1.5.0
BuildRequires: libnl3-devel
BuildRequires: libselinux-devel
BuildRequires: dnsmasq >= 2.41
BuildRequires: iptables
BuildRequires: ebtables
BuildRequires: module-init-tools
BuildRequires: cyrus-sasl-devel
BuildRequires: polkit >= 0.112
# For mount/umount in FS driver
BuildRequires: util-linux
%if %{with_qemu}
# For managing ACLs
BuildRequires: libacl-devel
# From QEMU RPMs
BuildRequires: /usr/bin/qemu-img
%endif
# For LVM drivers
BuildRequires: lvm2
# For pool type=iscsi
BuildRequires: iscsi-initiator-utils
%if %{with_storage_iscsi_direct}
# For pool type=iscsi-direct
BuildRequires: libiscsi-devel
%endif
# For disk driver
BuildRequires: parted-devel
# For Multipath support
BuildRequires: device-mapper-devel
%if %{with_storage_rbd}
BuildRequires: librados-devel
BuildRequires: librbd-devel
%endif
%if %{with_storage_gluster}
BuildRequires: glusterfs-api-devel >= 3.4.1
BuildRequires: glusterfs-devel >= 3.4.1
%endif
%if %{with_storage_sheepdog}
BuildRequires: sheepdog
%endif
%if %{with_numactl}
# For QEMU/LXC numa info
BuildRequires: numactl-devel
%endif
BuildRequires: libcap-ng-devel >= 0.5.0
%if %{with_fuse}
BuildRequires: fuse-devel >= 2.8.6
%endif
%if %{with_libssh2}
BuildRequires: libssh2-devel >= 1.3.0
%endif
%if %{with_netcf}
BuildRequires: netcf-devel >= 0.2.2
%endif
%if %{with_esx}
BuildRequires: libcurl-devel
%endif
%if %{with_hyperv}
BuildRequires: libwsman-devel >= 2.6.3
%endif
BuildRequires: audit-libs-devel
# we need /usr/sbin/dtrace
BuildRequires: systemtap-sdt-devel

# For mount/umount in FS driver
BuildRequires: util-linux
# For showmount in FS driver (netfs discovery)
BuildRequires: nfs-utils

# Fedora build root suckage
BuildRequires: gawk

# For storage wiping with different algorithms
BuildRequires: scrub

%if %{with_numad}
BuildRequires: numad
%endif

%if %{with_wireshark}
BuildRequires: wireshark-devel
%endif

%if %{with_libssh}
BuildRequires: libssh-devel >= 0.7.0
%endif

BuildRequires: rpcgen
BuildRequires: libtirpc-devel

# Needed for the firewalld_reload macro
%if %{with_firewalld_zone}
BuildRequires: firewalld-filesystem
%endif

%description
Libvirt is a C toolkit to interact with the virtualization capabilities
of recent versions of Linux (and other OSes). The main package includes
the libvirtd server exporting the virtualization support.

%package docs
Summary: API reference and website documentation

%description docs
Includes the API reference for the libvirt C library, and a complete
copy of the libvirt.org website documentation.

%package daemon
Summary: Server side daemon and supporting files for libvirt library

# All runtime requirements for the libvirt package (runtime requrements
# for subpackages are listed later in those subpackages)

# The client side, i.e. shared libs are in a subpackage
Requires: %{name}-libs = %{version}-%{release}

# The libvirt-guests.sh script requires virsh from libvirt-client subpackage,
# but not every deployment wants to use libvirt-guests service. Using
# Recommends here will install libvirt-client by default (if available), but
# RPM won't complain if the package is unavailable, masked, or removed later.
Recommends: %{name}-client = %{version}-%{release}

# netcat is needed on the server side so that clients that have
# libvirt < 6.9.0 can connect, but newer versions will prefer
# virt-ssh-helper. Making this a Recommends means that it gets
# installed by default, but can still be removed if compatibility
# with old clients is not required
Recommends: /usr/bin/nc

# for modprobe of pci devices
Requires: module-init-tools

# for /sbin/ip
Requires: iproute
# for /sbin/tc
Requires: iproute-tc

Requires: polkit >= 0.112
%if %{with_dmidecode}
# For virConnectGetSysinfo
Requires: dmidecode
%endif
# For service management
Requires(post): /usr/bin/systemctl
%if %{with_numad}
Requires: numad
%endif
# libvirtd depends on 'messagebus' service
Requires: dbus
# For uid creation during pre
Requires(pre): shadow-utils
# Needed by /usr/libexec/libvirt-guests.sh script.
Requires: gettext

# Ensure smooth upgrades
Obsoletes: libvirt-admin < 7.3.0
Provides: libvirt-admin = %{version}-%{release}
Obsoletes: libvirt-bash-completion < 7.3.0

%description daemon
Server side daemon required to manage the virtualization capabilities
of recent versions of Linux. Requires a hypervisor specific sub-RPM
for specific drivers.

%package daemon-config-network
Summary: Default configuration files for the libvirtd daemon

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}

%description daemon-config-network
Default configuration files for setting up NAT based networking

%package daemon-config-nwfilter
Summary: Network filter configuration files for the libvirtd daemon

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}

%description daemon-config-nwfilter
Network filter configuration files for cleaning guest traffic

%package daemon-driver-network
Summary: Network driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: dnsmasq >= 2.41
Requires: iptables

%description daemon-driver-network
The network driver plugin for the libvirtd daemon, providing
an implementation of the virtual network APIs using the Linux
bridge capabilities.


%package daemon-driver-nwfilter
Summary: Nwfilter driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: iptables
Requires: ebtables

%description daemon-driver-nwfilter
The nwfilter driver plugin for the libvirtd daemon, providing
an implementation of the firewall APIs using the ebtables,
iptables and ip6tables capabilities


%package daemon-driver-nodedev
Summary: Nodedev driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
# needed for device enumeration
Requires: systemd >= 185
# For managing persistent mediated devices
Requires: mdevctl

%description daemon-driver-nodedev
The nodedev driver plugin for the libvirtd daemon, providing
an implementation of the node device APIs using the udev
capabilities.


%package daemon-driver-interface
Summary: Interface driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
%if %{with_netcf}
Requires: netcf-libs >= 0.2.2
%endif

%description daemon-driver-interface
The interface driver plugin for the libvirtd daemon, providing
an implementation of the host network interface APIs.

%package daemon-driver-secret
Summary: Secret driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

%description daemon-driver-secret
The secret driver plugin for the libvirtd daemon, providing
an implementation of the secret key APIs.

%package daemon-driver-storage-core
Summary: Storage driver plugin including base backends for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: nfs-utils
# For mkfs
Requires: util-linux
%if %{with_qemu}
# From QEMU RPMs
Requires: /usr/bin/qemu-img
%endif
%if !%{with_storage_rbd}
Obsoletes: libvirt-daemon-driver-storage-rbd < %{version}-%{release}
%endif

%description daemon-driver-storage-core
The storage driver plugin for the libvirtd daemon, providing
an implementation of the storage APIs using files, local disks, LVM, SCSI,
iSCSI, and multipath storage.

%package daemon-driver-storage-logical
Summary: Storage driver plugin for lvm volumes
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: lvm2

%description daemon-driver-storage-logical
The storage driver backend adding implementation of the storage APIs for block
volumes using lvm.


%package daemon-driver-storage-disk
Summary: Storage driver plugin for disk
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: parted
Requires: device-mapper

%description daemon-driver-storage-disk
The storage driver backend adding implementation of the storage APIs for block
volumes using the host disks.


%package daemon-driver-storage-scsi
Summary: Storage driver plugin for local scsi devices
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

%description daemon-driver-storage-scsi
The storage driver backend adding implementation of the storage APIs for scsi
host devices.


%package daemon-driver-storage-iscsi
Summary: Storage driver plugin for iscsi
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: iscsi-initiator-utils

%description daemon-driver-storage-iscsi
The storage driver backend adding implementation of the storage APIs for iscsi
volumes using the host iscsi stack.


%if %{with_storage_iscsi_direct}
%package daemon-driver-storage-iscsi-direct
Summary: Storage driver plugin for iscsi-direct
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

%description daemon-driver-storage-iscsi-direct
The storage driver backend adding implementation of the storage APIs for iscsi
volumes using libiscsi direct connection.
%endif


%package daemon-driver-storage-mpath
Summary: Storage driver plugin for multipath volumes
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: device-mapper

%description daemon-driver-storage-mpath
The storage driver backend adding implementation of the storage APIs for
multipath storage using device mapper.


%if %{with_storage_gluster}
%package daemon-driver-storage-gluster
Summary: Storage driver plugin for gluster
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
    %if 0%{?fedora}
Requires: glusterfs-client >= 2.0.1
    %endif
    %if (0%{?fedora} || 0%{?with_storage_gluster})
Requires: /usr/sbin/gluster
    %endif

%description daemon-driver-storage-gluster
The storage driver backend adding implementation of the storage APIs for gluster
volumes using libgfapi.
%endif


%if %{with_storage_rbd}
%package daemon-driver-storage-rbd
Summary: Storage driver plugin for rbd
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

%description daemon-driver-storage-rbd
The storage driver backend adding implementation of the storage APIs for rbd
volumes using the ceph protocol.
%endif


%if %{with_storage_sheepdog}
%package daemon-driver-storage-sheepdog
Summary: Storage driver plugin for sheepdog
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: sheepdog

%description daemon-driver-storage-sheepdog
The storage driver backend adding implementation of the storage APIs for
sheepdog volumes using.
%endif


%if %{with_storage_zfs}
%package daemon-driver-storage-zfs
Summary: Storage driver plugin for ZFS
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
# Support any conforming implementation of zfs
Requires: /sbin/zfs
Requires: /sbin/zpool

%description daemon-driver-storage-zfs
The storage driver backend adding implementation of the storage APIs for
ZFS volumes.
%endif


%package daemon-driver-storage
Summary: Storage driver plugin including all backends for the libvirtd daemon
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-daemon-driver-storage-disk = %{version}-%{release}
Requires: libvirt-daemon-driver-storage-logical = %{version}-%{release}
Requires: libvirt-daemon-driver-storage-scsi = %{version}-%{release}
Requires: libvirt-daemon-driver-storage-iscsi = %{version}-%{release}
Requires: libvirt-daemon-driver-storage-mpath = %{version}-%{release}
%if %{with_storage_iscsi_direct}
Requires: libvirt-daemon-driver-storage-iscsi-direct = %{version}-%{release}
%endif
%if %{with_storage_gluster}
Requires: libvirt-daemon-driver-storage-gluster = %{version}-%{release}
%endif
%if %{with_storage_rbd}
Requires: libvirt-daemon-driver-storage-rbd = %{version}-%{release}
%endif
%if %{with_storage_sheepdog}
Requires: libvirt-daemon-driver-storage-sheepdog = %{version}-%{release}
%endif
%if %{with_storage_zfs}
Requires: libvirt-daemon-driver-storage-zfs = %{version}-%{release}
%endif

%description daemon-driver-storage
The storage driver plugin for the libvirtd daemon, providing
an implementation of the storage APIs using LVM, iSCSI,
parted and more.


%if %{with_qemu}
%package daemon-driver-qemu
Summary: QEMU driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: /usr/bin/qemu-img
# For image compression
Requires: gzip
Requires: bzip2
Requires: lzop
Requires: xz
Requires: systemd-container
Requires: swtpm-tools

%description daemon-driver-qemu
The qemu driver plugin for the libvirtd daemon, providing
an implementation of the hypervisor driver APIs using
QEMU
%endif


%if %{with_lxc}
%package daemon-driver-lxc
Summary: LXC driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
# There really is a hard cross-driver dependency here
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: systemd-container

%description daemon-driver-lxc
The LXC driver plugin for the libvirtd daemon, providing
an implementation of the hypervisor driver APIs using
the Linux kernel
%endif


%if %{with_vbox}
%package daemon-driver-vbox
Summary: VirtualBox driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

%description daemon-driver-vbox
The vbox driver plugin for the libvirtd daemon, providing
an implementation of the hypervisor driver APIs using
VirtualBox
%endif


%if %{with_libxl}
%package daemon-driver-libxl
Summary: Libxl driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Obsoletes: libvirt-daemon-driver-xen < 4.3.0

%description daemon-driver-libxl
The Libxl driver plugin for the libvirtd daemon, providing
an implementation of the hypervisor driver APIs using
Libxl
%endif



%if %{with_qemu_tcg}
%package daemon-qemu
Summary: Server side daemon & driver required to run QEMU guests

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-qemu = %{version}-%{release}
Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}
Requires: qemu

%description daemon-qemu
Server side daemon and driver required to manage the virtualization
capabilities of the QEMU TCG emulators
%endif


%if %{with_qemu_kvm}
%package daemon-kvm
Summary: Server side daemon & driver required to run KVM guests

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-qemu = %{version}-%{release}
Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}
Requires: qemu-kvm

%description daemon-kvm
Server side daemon and driver required to manage the virtualization
capabilities of the KVM hypervisor
%endif


%if %{with_lxc}
%package daemon-lxc
Summary: Server side daemon & driver required to run LXC guests

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-lxc = %{version}-%{release}
Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}

%description daemon-lxc
Server side daemon and driver required to manage the virtualization
capabilities of LXC
%endif


%if %{with_libxl}
%package daemon-xen
Summary: Server side daemon & driver required to run XEN guests

Requires: libvirt-daemon = %{version}-%{release}
    %if %{with_libxl}
Requires: libvirt-daemon-driver-libxl = %{version}-%{release}
    %endif
Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}
Requires: xen

%description daemon-xen
Server side daemon and driver required to manage the virtualization
capabilities of XEN
%endif

%if %{with_vbox}
%package daemon-vbox
Summary: Server side daemon & driver required to run VirtualBox guests

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-vbox = %{version}-%{release}
Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}

%description daemon-vbox
Server side daemon and driver required to manage the virtualization
capabilities of VirtualBox
%endif

%package client
Summary: Client side utilities of the libvirt library
Requires: %{name}-libs = %{version}-%{release}
# Needed by virt-pki-validate script.
Requires: gnutls-utils

# Ensure smooth upgrades
Obsoletes: libvirt-bash-completion < 7.3.0

%description client
The client binaries needed to access the virtualization
capabilities of recent versions of Linux (and other OSes).

%package libs
Summary: Client side libraries
# So remote clients can access libvirt over SSH tunnel
Requires: cyrus-sasl
# Needed by default sasl.conf - no onerous extra deps, since
# 100's of other things on a system already pull in krb5-libs
Requires: cyrus-sasl-gssapi

%description libs
Shared libraries for accessing the libvirt daemon.

%if %{with_wireshark}
%package wireshark
Summary: Wireshark dissector plugin for libvirt RPC transactions
Requires: wireshark
Requires: %{name}-libs = %{version}-%{release}

%description wireshark
Wireshark dissector plugin for better analysis of libvirt RPC traffic.
%endif

%if %{with_lxc}
%package login-shell
Summary: Login shell for connecting users to an LXC container
Requires: %{name}-libs = %{version}-%{release}

%description login-shell
Provides the set-uid virt-login-shell binary that is used to
connect a user to an LXC container when they login, by switching
namespaces.
%endif

%package devel
Summary: Libraries, includes, etc. to compile with the libvirt library
Requires: %{name}-libs = %{version}-%{release}
Requires: pkgconfig

%description devel
Include header files & development libraries for the libvirt C library.

%if %{with_sanlock}
%package lock-sanlock
Summary: Sanlock lock manager plugin for QEMU driver
Requires: sanlock >= 2.4
#for virt-sanlock-cleanup require augeas
Requires: augeas
Requires: %{name}-daemon = %{version}-%{release}
Requires: %{name}-libs = %{version}-%{release}

%description lock-sanlock
Includes the Sanlock lock manager plugin for the QEMU
driver
%endif

%package nss
Summary: Libvirt plugin for Name Service Switch
Requires: libvirt-daemon-driver-network = %{version}-%{release}

%description nss
Libvirt plugin for NSS for translating domain names into IP addresses.


%prep

%autosetup -S git_am -N

# "make dist" replaces all symlinks with a copy of the linked files;
# we need to replace all of them with the original symlinks
echo "Restoring symlinks"
while read lnk target; do
    if [ -e $lnk ]; then
        rm -rf $lnk
        ln -s $target $lnk
    fi
done <%{_sourcedir}/symlinks || exit 1
git add .
git commit -q -a --allow-empty --author 'rpm-build <rpm-build>' -m symlinks


git config gc.auto 0

%autopatch

%build
%if 0%{?fedora} >= %{min_fedora} || 0%{?rhel} >= %{min_rhel}
    %define supported_platform 1
%else
    %define supported_platform 0
%endif

%if ! %{supported_platform}
echo "This RPM requires either Fedora >= %{min_fedora} or RHEL >= %{min_rhel}"
exit 1
%endif

%if %{with_qemu}
    %define arg_qemu -Ddriver_qemu=enabled
%else
    %define arg_qemu -Ddriver_qemu=disabled
%endif

%if %{with_openvz}
    %define arg_openvz -Ddriver_openvz=enabled
%else
    %define arg_openvz -Ddriver_openvz=disabled
%endif

%if %{with_lxc}
    %define arg_lxc -Ddriver_lxc=enabled
    %define arg_login_shell -Dlogin_shell=enabled
%else
    %define arg_lxc -Ddriver_lxc=disabled
    %define arg_login_shell -Dlogin_shell=disabled
%endif

%if %{with_vbox}
    %define arg_vbox -Ddriver_vbox=enabled
%else
    %define arg_vbox -Ddriver_vbox=disabled
%endif

%if %{with_libxl}
    %define arg_libxl -Ddriver_libxl=enabled
%else
    %define arg_libxl -Ddriver_libxl=disabled
%endif

%if %{with_esx}
    %define arg_esx -Ddriver_esx=enabled -Dcurl=enabled
%else
    %define arg_esx -Ddriver_esx=disabled -Dcurl=disabled
%endif

%if %{with_hyperv}
    %define arg_hyperv -Ddriver_hyperv=enabled -Dopenwsman=enabled
%else
    %define arg_hyperv -Ddriver_hyperv=disabled -Dopenwsman=disabled
%endif

%if %{with_vmware}
    %define arg_vmware -Ddriver_vmware=enabled
%else
    %define arg_vmware -Ddriver_vmware=disabled
%endif

%if %{with_storage_rbd}
    %define arg_storage_rbd -Dstorage_rbd=enabled
%else
    %define arg_storage_rbd -Dstorage_rbd=disabled
%endif

%if %{with_storage_sheepdog}
    %define arg_storage_sheepdog -Dstorage_sheepdog=enabled
%else
    %define arg_storage_sheepdog -Dstorage_sheepdog=disabled
%endif

%if %{with_storage_gluster}
    %define arg_storage_gluster -Dstorage_gluster=enabled -Dglusterfs=enabled
%else
    %define arg_storage_gluster -Dstorage_gluster=disabled -Dglusterfs=disabled
%endif

%if %{with_storage_zfs}
    %define arg_storage_zfs -Dstorage_zfs=enabled
%else
    %define arg_storage_zfs -Dstorage_zfs=disabled
%endif

%if %{with_numactl}
    %define arg_numactl -Dnumactl=enabled
%else
    %define arg_numactl -Dnumactl=disabled
%endif

%if %{with_numad}
    %define arg_numad -Dnumad=enabled
%else
    %define arg_numad -Dnumad=disabled
%endif

%if %{with_fuse}
    %define arg_fuse -Dfuse=enabled
%else
    %define arg_fuse -Dfuse=disabled
%endif

%if %{with_sanlock}
    %define arg_sanlock -Dsanlock=enabled
%else
    %define arg_sanlock -Dsanlock=disabled
%endif

%if %{with_firewalld_zone}
    %define arg_firewalld_zone -Dfirewalld_zone=enabled
%else
    %define arg_firewalld_zone -Dfirewalld_zone=disabled
%endif

%if %{with_netcf}
    %define arg_netcf -Dnetcf=enabled
%else
    %define arg_netcf -Dnetcf=disabled
%endif

%if %{with_wireshark}
    %define arg_wireshark -Dwireshark_dissector=enabled
%else
    %define arg_wireshark -Dwireshark_dissector=disabled
%endif

%if %{with_storage_iscsi_direct}
    %define arg_storage_iscsi_direct -Dstorage_iscsi_direct=enabled -Dlibiscsi=enabled
%else
    %define arg_storage_iscsi_direct -Dstorage_iscsi_direct=disabled -Dlibiscsi=disabled
%endif

%if %{with_libssh}
    %define arg_libssh -Dlibssh=enabled
%else
    %define arg_libssh -Dlibssh=disabled
%endif

%if %{with_libssh2}
    %define arg_libssh2 -Dlibssh2=enabled
%else
    %define arg_libssh2 -Dlibssh2=disabled
%endif

%if %{with_modular_daemons}
    %define arg_remote_mode -Dremote_default_mode=direct
%else
    %define arg_remote_mode -Dremote_default_mode=legacy
%endif

%define when  %(date +"%%F-%%T")
%define where %(hostname)
%define who   %{?packager}%{!?packager:Unknown}
%define arg_packager -Dpackager="%{who}, %{when}, %{where}"
%define arg_packager_version -Dpackager_version="%{release}"

%define arg_selinux_mount -Dselinux_mount="/sys/fs/selinux"

# place macros above and build commands below this comment

export SOURCE_DATE_EPOCH=$(stat --printf='%Y' %{_specdir}/%{name}.spec)

%meson \
           -Drunstatedir=%{_rundir} \
           %{?arg_qemu} \
           %{?arg_openvz} \
           %{?arg_lxc} \
           %{?arg_vbox} \
           %{?arg_libxl} \
           -Dsasl=enabled \
           -Dpolkit=enabled \
           -Ddriver_libvirtd=enabled \
           -Ddriver_remote=enabled \
           -Ddriver_test=enabled \
           %{?arg_esx} \
           %{?arg_hyperv} \
           %{?arg_vmware} \
           -Ddriver_vz=disabled \
           -Ddriver_bhyve=disabled \
           -Ddriver_ch=disabled \
           %{?arg_remote_mode} \
           -Ddriver_interface=enabled \
           -Ddriver_network=enabled \
           -Dstorage_fs=enabled \
           -Dstorage_lvm=enabled \
           -Dstorage_iscsi=enabled \
           %{?arg_storage_iscsi_direct} \
           -Dstorage_scsi=enabled \
           -Dstorage_disk=enabled \
           -Dstorage_mpath=enabled \
           %{?arg_storage_rbd} \
           %{?arg_storage_sheepdog} \
           %{?arg_storage_gluster} \
           %{?arg_storage_zfs} \
           -Dstorage_vstorage=disabled \
           %{?arg_numactl} \
           %{?arg_numad} \
           -Dcapng=enabled \
           %{?arg_fuse} \
           %{?arg_netcf} \
           -Dselinux=enabled \
           %{?arg_selinux_mount} \
           -Dapparmor=disabled \
           -Dapparmor_profiles=disabled \
           -Dsecdriver_apparmor=disabled \
           -Dudev=enabled \
           -Dyajl=enabled \
           %{?arg_sanlock} \
           -Dlibpcap=enabled \
           -Dlibnl=enabled \
           -Daudit=enabled \
           -Ddtrace=enabled \
           -Dfirewalld=enabled \
           %{?arg_firewalld_zone} \
           %{?arg_wireshark} \
           %{?arg_libssh} \
           %{?arg_libssh2} \
           -Dpm_utils=disabled \
           -Dnss=enabled \
           %{arg_packager} \
           %{arg_packager_version} \
           -Dqemu_user=%{qemu_user} \
           -Dqemu_group=%{qemu_group} \
           -Dqemu_moddir=%{qemu_moddir} \
           -Dqemu_datadir=%{qemu_datadir} \
           -Dtls_priority=%{tls_priority} \
           %{?enable_werror} \
           -Dexpensive_tests=enabled \
           -Dinit_script=systemd \
           -Ddocs=enabled \
           -Dtests=enabled \
           -Drpath=disabled \
           %{?arg_login_shell}

%meson_build

%install
rm -fr %{buildroot}

export SOURCE_DATE_EPOCH=$(stat --printf='%Y' %{_specdir}/%{name}.spec)

%meson_install

rm -f $RPM_BUILD_ROOT%{_libdir}/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/lock-driver/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/lock-driver/*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/connection-driver/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/connection-driver/*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/storage-backend/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/storage-backend/*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/storage-file/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/storage-file/*.a
%if %{with_wireshark}
rm -f $RPM_BUILD_ROOT%{wireshark_plugindir}/libvirt.la
%endif

# We don't want to install /etc/libvirt/qemu/networks in the main %%files list
# because if the admin wants to delete the default network completely, we don't
# want to end up re-incarnating it on every RPM upgrade.
install -d -m 0755 $RPM_BUILD_ROOT%{_datadir}/libvirt/networks/
cp $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu/networks/default.xml \
   $RPM_BUILD_ROOT%{_datadir}/libvirt/networks/default.xml
# libvirt saves this file with mode 0600
chmod 0600 $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu/networks/default.xml

# nwfilter files are installed in /usr/share/libvirt and copied to /etc in %%post
# to avoid verification errors on changed files in /etc
install -d -m 0755 $RPM_BUILD_ROOT%{_datadir}/libvirt/nwfilter/
cp -a $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/nwfilter/*.xml \
    $RPM_BUILD_ROOT%{_datadir}/libvirt/nwfilter/
# libvirt saves these files with mode 600
chmod 600 $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/nwfilter/*.xml

%if ! %{with_qemu}
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/libvirtd_qemu.aug
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/tests/test_libvirtd_qemu.aug
%endif
%find_lang %{name}

%if ! %{with_sanlock}
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/libvirt_sanlock.aug
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/tests/test_libvirt_sanlock.aug
%endif

%if ! %{with_lxc}
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/libvirtd_lxc.aug
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/tests/test_libvirtd_lxc.aug
%endif

%if ! %{with_qemu}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu.conf
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/libvirtd.qemu
%endif
%if ! %{with_lxc}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/lxc.conf
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/libvirtd.lxc
%endif
%if ! %{with_libxl}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/libxl.conf
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/libvirtd.libxl
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/libvirtd_libxl.aug
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/tests/test_libvirtd_libxl.aug
%endif

# Copied into libvirt-docs subpackage eventually
mv $RPM_BUILD_ROOT%{_datadir}/doc/libvirt libvirt-docs

%ifarch %{arches_systemtap_64bit}
mv $RPM_BUILD_ROOT%{_datadir}/systemtap/tapset/libvirt_probes.stp \
   $RPM_BUILD_ROOT%{_datadir}/systemtap/tapset/libvirt_probes-64.stp

    %if %{with_qemu}
mv $RPM_BUILD_ROOT%{_datadir}/systemtap/tapset/libvirt_qemu_probes.stp \
   $RPM_BUILD_ROOT%{_datadir}/systemtap/tapset/libvirt_qemu_probes-64.stp
    %endif
%endif

%check
# Building on slow archs, like emulated s390x in Fedora copr, requires
# raising the test timeout
VIR_TEST_DEBUG=1 %meson_test --no-suite syntax-check --timeout-multiplier 10

%define libvirt_daemon_schedule_restart() mkdir -p %{_localstatedir}/lib/rpm-state/libvirt || : \
/bin/systemctl is-active %1.service 1>/dev/null 2>&1 && \
  touch %{_localstatedir}/lib/rpm-state/libvirt/restart-%1 || :

%define libvirt_daemon_finish_restart() rm -f %{_localstatedir}/lib/rpm-state/libvirt/restart-%1 \
rmdir %{_localstatedir}/lib/rpm-state/libvirt 2>/dev/null || :

%define libvirt_daemon_needs_restart() -f %{_localstatedir}/lib/rpm-state/libvirt/restart-%1

%define libvirt_daemon_perform_restart() if test %libvirt_daemon_needs_restart %1 \
then \
  /bin/systemctl try-restart %1.service >/dev/null 2>&1 || : \
fi \
%libvirt_daemon_finish_restart %1

# For daemons with only UNIX sockets
%define libvirt_daemon_systemd_post() %systemd_post %1.socket %1-ro.socket %1-admin.socket %1.service
%define libvirt_daemon_systemd_preun() %systemd_preun %1.service %1-ro.socket %1-admin.socket %1.socket

# For daemons with UNIX and INET sockets
%define libvirt_daemon_systemd_post_inet() %systemd_post %1.socket %1-ro.socket %1-admin.socket %1-tls.socket %1-tcp.socket %1.service
%define libvirt_daemon_systemd_preun_inet() %systemd_preun %1.service %1-ro.socket %1-admin.socket %1-tls.socket %1-tcp.socket %1.socket

# For daemons with only UNIX sockets and no unprivileged read-only access
%define libvirt_daemon_systemd_post_priv() %systemd_post %1.socket %1-admin.socket %1.service
%define libvirt_daemon_systemd_preun_priv() %systemd_preun %1.service %1-admin.socket %1.socket

%pre daemon
# 'libvirt' group is just to allow password-less polkit access to
# libvirtd. The uid number is irrelevant, so we use dynamic allocation
# described at the above link.
getent group libvirt >/dev/null || groupadd -r libvirt

exit 0

%post daemon
%libvirt_daemon_systemd_post_priv virtlogd
%libvirt_daemon_systemd_post_priv virtlockd
%if %{with_modular_daemons}
%libvirt_daemon_systemd_post_inet virtproxyd
%else
%libvirt_daemon_systemd_post_inet libvirtd
%endif

%systemd_post libvirt-guests.service

%libvirt_daemon_schedule_restart libvirtd

%preun daemon
%systemd_preun libvirt-guests.service

%libvirt_daemon_systemd_preun_inet libvirtd
%libvirt_daemon_systemd_preun_inet virtproxyd
%libvirt_daemon_systemd_preun_priv virtlogd
%libvirt_daemon_systemd_preun_priv virtlockd

%postun daemon
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then
    /bin/systemctl reload-or-try-restart virtlockd.service virtlogd.service >/dev/null 2>&1 || :
fi
%systemd_postun libvirt-guests.service

# In upgrade scenario we must explicitly enable virtlockd/virtlogd
# sockets, if libvirtd is already enabled and start them if
# libvirtd is running, otherwise you'll get failures to start
# guests
%triggerpostun daemon -- libvirt-daemon < 1.3.0
if [ $1 -ge 1 ] ; then
    /bin/systemctl is-enabled libvirtd.service 1>/dev/null 2>&1 &&
        /bin/systemctl enable virtlogd.socket virtlogd-admin.socket || :
    /bin/systemctl is-active libvirtd.service 1>/dev/null 2>&1 &&
        /bin/systemctl start virtlogd.socket virtlogd-admin.socket || :
fi

%posttrans daemon
if test %libvirt_daemon_needs_restart libvirtd
then
    # See if user has previously modified their install to
    # tell libvirtd to use --listen
    grep -E '^LIBVIRTD_ARGS=.*--listen' /etc/sysconfig/libvirtd 1>/dev/null 2>&1
    if test $? = 0
    then
        # Then lets keep honouring --listen and *not* use
        # systemd socket activation, because switching things
        # might confuse mgmt tool like puppet/ansible that
        # expect the old style libvirtd
        /bin/systemctl mask \
                libvirtd.socket \
                libvirtd-ro.socket \
                libvirtd-admin.socket \
                libvirtd-tls.socket \
                libvirtd-tcp.socket >/dev/null 2>&1 || :
    else
        # Old libvirtd owns the sockets and will delete them on
        # shutdown. Can't use a try-restart as libvirtd will simply
        # own the sockets again when it comes back up. Thus we must
        # do this particular ordering, so that we get libvirtd
        # running with socket activation in use
        /bin/systemctl is-active libvirtd.service 1>/dev/null 2>&1
        if test $? = 0
        then
            /bin/systemctl stop libvirtd.service >/dev/null 2>&1 || :

            /bin/systemctl try-restart \
                    libvirtd.socket \
                    libvirtd-ro.socket \
                    libvirtd-admin.socket >/dev/null 2>&1 || :

            /bin/systemctl start libvirtd.service >/dev/null 2>&1 || :
        fi
    fi
fi

%libvirt_daemon_finish_restart libvirtd

%post daemon-driver-network
%if %{with_firewalld_zone}
    %firewalld_reload
%endif

%if %{with_modular_daemons}
%libvirt_daemon_systemd_post virtnetworkd
%endif
%libvirt_daemon_schedule_restart virtnetworkd

%preun daemon-driver-network
%libvirt_daemon_systemd_preun virtnetworkd

%postun daemon-driver-network
%if %{with_firewalld_zone}
    %firewalld_reload
%endif

%posttrans daemon-driver-network
%libvirt_daemon_perform_restart virtnetworkd


%post daemon-driver-nwfilter
%if %{with_modular_daemons}
%libvirt_daemon_systemd_post virtnwfilterd
%endif
%libvirt_daemon_schedule_restart virtnwfilterd

%preun daemon-driver-nwfilter
%libvirt_daemon_systemd_preun virtnwfilterd

%posttrans daemon-driver-nwfilter
%libvirt_daemon_perform_restart virtnwfilterd


%post daemon-driver-nodedev
%if %{with_modular_daemons}
%libvirt_daemon_systemd_post virtnodedevd
%endif
%libvirt_daemon_schedule_restart virtnodedevd

%preun daemon-driver-nodedev
%libvirt_daemon_systemd_preun virtnodedevd

%posttrans daemon-driver-nodedev
%libvirt_daemon_perform_restart virtnodedevd


%post daemon-driver-interface
%if %{with_modular_daemons}
%libvirt_daemon_systemd_post virtinterfaced
%endif
%libvirt_daemon_schedule_restart virtinterfaced

%preun daemon-driver-interface
%libvirt_daemon_systemd_preun virtinterfaced

%posttrans daemon-driver-interface
%libvirt_daemon_perform_restart virtinterfaced


%post daemon-driver-secret
%if %{with_modular_daemons}
%libvirt_daemon_systemd_post virtsecretd
%endif
%libvirt_daemon_schedule_restart virtsecretd

%preun daemon-driver-secret
%libvirt_daemon_systemd_preun virtsecretd

%posttrans daemon-driver-secret
%libvirt_daemon_perform_restart virtsecretd


%post daemon-driver-storage
%if %{with_modular_daemons}
%libvirt_daemon_systemd_post virtstoraged
%endif
%libvirt_daemon_schedule_restart virtstoraged

%preun daemon-driver-storage
%libvirt_daemon_systemd_preun virtstoraged

%posttrans daemon-driver-storage
%libvirt_daemon_perform_restart virtstoraged


%if %{with_qemu}
%pre daemon-driver-qemu
# We want soft static allocation of well-known ids, as disk images
# are commonly shared across NFS mounts by id rather than name; see
# https://fedoraproject.org/wiki/Packaging:UsersAndGroups
getent group kvm >/dev/null || groupadd -f -g 36 -r kvm
getent group qemu >/dev/null || groupadd -f -g 107 -r qemu
if ! getent passwd qemu >/dev/null; then
  if ! getent passwd 107 >/dev/null; then
    useradd -r -u 107 -g qemu -G kvm -d / -s /sbin/nologin -c "qemu user" qemu
  else
    useradd -r -g qemu -G kvm -d / -s /sbin/nologin -c "qemu user" qemu
  fi
fi
exit 0

%post daemon-driver-qemu
    %if %{with_modular_daemons}
%libvirt_daemon_systemd_post virtqemud
    %endif
%libvirt_daemon_schedule_restart virtqemud

%preun daemon-driver-qemu
%libvirt_daemon_systemd_preun virtqemud

%posttrans daemon-driver-qemu
%libvirt_daemon_perform_restart virtqemud
%endif


%if %{with_lxc}
%post daemon-driver-lxc
    %if %{with_modular_daemons}
%libvirt_daemon_systemd_post virtlxcd
    %endif
%libvirt_daemon_schedule_restart virtlxcd

%preun daemon-driver-lxc
%libvirt_daemon_systemd_preun virtlxcd

%posttrans daemon-driver-lxc
%libvirt_daemon_perform_restart virtlxcd
%endif


%if %{with_vbox}
%post daemon-driver-vbox
    %if %{with_modular_daemons}
%libvirt_daemon_systemd_post virtvboxd
    %endif
%libvirt_daemon_schedule_restart virtvboxd

%preun daemon-driver-vbox
%libvirt_daemon_systemd_preun virtvboxd

%posttrans daemon-driver-vbox
%libvirt_daemon_perform_restart virtvboxd
%endif


%if %{with_libxl}
%post daemon-driver-libxl
    %if %{with_modular_daemons}
%libvirt_daemon_systemd_post virtxend
    %endif
%libvirt_daemon_schedule_restart virtxend

%preun daemon-driver-libxl
%libvirt_daemon_systemd_preun virtxend

%posttrans daemon-driver-libxl
%libvirt_daemon_perform_restart virtxend
%endif


%post daemon-config-network
if test $1 -eq 1 && test ! -f %{_sysconfdir}/libvirt/qemu/networks/default.xml ; then
    # see if the network used by default network creates a conflict,
    # and try to resolve it
    # NB: 192.168.122.0/24 is used in the default.xml template file;
    # do not modify any of those values here without also modifying
    # them in the template.
    orig_sub=122
    sub=${orig_sub}
    nl='
'
    routes="${nl}$(ip route show | cut -d' ' -f1)${nl}"
    case ${routes} in
      *"${nl}192.168.${orig_sub}.0/24${nl}"*)
        # there was a match, so we need to look for an unused subnet
        for new_sub in $(seq 124 254); do
          case ${routes} in
          *"${nl}192.168.${new_sub}.0/24${nl}"*)
            ;;
          *)
            sub=$new_sub
            break;
            ;;
          esac
        done
        ;;
      *)
        ;;
    esac

    sed -e "s/${orig_sub}/${sub}/g" \
         < %{_datadir}/libvirt/networks/default.xml \
         > %{_sysconfdir}/libvirt/qemu/networks/default.xml
    ln -s ../default.xml %{_sysconfdir}/libvirt/qemu/networks/autostart/default.xml
    # libvirt saves this file with mode 0600
    chmod 0600 %{_sysconfdir}/libvirt/qemu/networks/default.xml

    # Make sure libvirt picks up the new network defininiton
    %libvirt_daemon_schedule_restart libvirtd
    %libvirt_daemon_schedule_restart virtnetworkd
fi

%posttrans daemon-config-network
%libvirt_daemon_perform_restart libvirtd
%libvirt_daemon_perform_restart virtnetworkd

%post daemon-config-nwfilter
for datadir_file in %{_datadir}/libvirt/nwfilter/*.xml; do
  sysconfdir_file=%{_sysconfdir}/libvirt/nwfilter/$(basename "$datadir_file")
  if [ ! -f "$sysconfdir_file" ]; then
    # libvirt saves these files with mode 600
    install -m 0600 "$datadir_file" "$sysconfdir_file"
  fi
done
# Make sure libvirt picks up the new nwfilter defininitons
%libvirt_daemon_schedule_restart libvirtd
%libvirt_daemon_schedule_restart virtnwfilterd

%posttrans daemon-config-nwfilter
%libvirt_daemon_perform_restart libvirtd
%libvirt_daemon_perform_restart virtnwfilterd

%if %{with_lxc}
%pre login-shell
getent group virtlogin >/dev/null || groupadd -r virtlogin
exit 0
%endif

%files

%files docs
%doc AUTHORS.rst NEWS.rst README.rst
%doc libvirt-docs/*

%files daemon

%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/

%{_unitdir}/libvirtd.service
%{_unitdir}/libvirtd.socket
%{_unitdir}/libvirtd-ro.socket
%{_unitdir}/libvirtd-admin.socket
%{_unitdir}/libvirtd-tcp.socket
%{_unitdir}/libvirtd-tls.socket
%{_unitdir}/virtproxyd.service
%{_unitdir}/virtproxyd.socket
%{_unitdir}/virtproxyd-ro.socket
%{_unitdir}/virtproxyd-admin.socket
%{_unitdir}/virtproxyd-tcp.socket
%{_unitdir}/virtproxyd-tls.socket
%{_unitdir}/virt-guest-shutdown.target
%{_unitdir}/virtlogd.service
%{_unitdir}/virtlogd.socket
%{_unitdir}/virtlogd-admin.socket
%{_unitdir}/virtlockd.service
%{_unitdir}/virtlockd.socket
%{_unitdir}/virtlockd-admin.socket
%{_unitdir}/libvirt-guests.service
%config(noreplace) %{_sysconfdir}/sysconfig/libvirtd
%config(noreplace) %{_sysconfdir}/sysconfig/virtproxyd
%config(noreplace) %{_sysconfdir}/sysconfig/virtlogd
%config(noreplace) %{_sysconfdir}/sysconfig/virtlockd
%config(noreplace) %{_sysconfdir}/libvirt/libvirtd.conf
%config(noreplace) %{_sysconfdir}/libvirt/virtproxyd.conf
%config(noreplace) %{_sysconfdir}/libvirt/virtlogd.conf
%config(noreplace) %{_sysconfdir}/libvirt/virtlockd.conf
%config(noreplace) %{_sysconfdir}/sasl2/libvirt.conf
%config(noreplace) %{_sysconfdir}/sysconfig/libvirt-guests
%config(noreplace) %{_prefix}/lib/sysctl.d/60-libvirtd.conf

%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd
%dir %{_datadir}/libvirt/

%ghost %dir %{_rundir}/libvirt/

%dir %attr(0711, root, root) %{_localstatedir}/lib/libvirt/images/
%dir %attr(0711, root, root) %{_localstatedir}/lib/libvirt/filesystems/
%dir %attr(0711, root, root) %{_localstatedir}/lib/libvirt/boot/
%dir %attr(0711, root, root) %{_localstatedir}/cache/libvirt/


%dir %attr(0755, root, root) %{_libdir}/libvirt/
%dir %attr(0755, root, root) %{_libdir}/libvirt/connection-driver/
%dir %attr(0755, root, root) %{_libdir}/libvirt/lock-driver
%attr(0755, root, root) %{_libdir}/libvirt/lock-driver/lockd.so

%{_datadir}/augeas/lenses/libvirtd.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd.aug
%{_datadir}/augeas/lenses/virtlogd.aug
%{_datadir}/augeas/lenses/tests/test_virtlogd.aug
%{_datadir}/augeas/lenses/virtlockd.aug
%{_datadir}/augeas/lenses/tests/test_virtlockd.aug
%{_datadir}/augeas/lenses/virtproxyd.aug
%{_datadir}/augeas/lenses/tests/test_virtproxyd.aug
%{_datadir}/augeas/lenses/libvirt_lockd.aug
%if %{with_qemu}
%{_datadir}/augeas/lenses/tests/test_libvirt_lockd.aug
%endif

%{_datadir}/polkit-1/actions/org.libvirt.unix.policy
%{_datadir}/polkit-1/actions/org.libvirt.api.policy
%{_datadir}/polkit-1/rules.d/50-libvirt.rules

%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/

%attr(0755, root, root) %{_libexecdir}/libvirt_iohelper

%attr(0755, root, root) %{_bindir}/virt-ssh-helper

%attr(0755, root, root) %{_sbindir}/libvirtd
%attr(0755, root, root) %{_sbindir}/virtproxyd
%attr(0755, root, root) %{_sbindir}/virtlogd
%attr(0755, root, root) %{_sbindir}/virtlockd
%attr(0755, root, root) %{_libexecdir}/libvirt-guests.sh

%{_mandir}/man1/virt-admin.1*
%{_mandir}/man1/virt-host-validate.1*
%{_mandir}/man8/virt-ssh-helper.8*
%{_mandir}/man8/libvirtd.8*
%{_mandir}/man8/virtlogd.8*
%{_mandir}/man8/virtlockd.8*
%{_mandir}/man8/virtproxyd.8*
%{_mandir}/man7/virkey*.7*

%{_bindir}/virt-host-validate
%{_bindir}/virt-admin
%{_datadir}/bash-completion/completions/virt-admin

%files daemon-config-network
%dir %{_datadir}/libvirt/networks/
%{_datadir}/libvirt/networks/default.xml
%ghost %{_sysconfdir}/libvirt/qemu/networks/default.xml
%ghost %{_sysconfdir}/libvirt/qemu/networks/autostart/default.xml

%files daemon-config-nwfilter
%dir %{_datadir}/libvirt/nwfilter/
%{_datadir}/libvirt/nwfilter/*.xml
%ghost %{_sysconfdir}/libvirt/nwfilter/*.xml

%files daemon-driver-interface
%config(noreplace) %{_sysconfdir}/sysconfig/virtinterfaced
%config(noreplace) %{_sysconfdir}/libvirt/virtinterfaced.conf
%{_datadir}/augeas/lenses/virtinterfaced.aug
%{_datadir}/augeas/lenses/tests/test_virtinterfaced.aug
%{_unitdir}/virtinterfaced.service
%{_unitdir}/virtinterfaced.socket
%{_unitdir}/virtinterfaced-ro.socket
%{_unitdir}/virtinterfaced-admin.socket
%attr(0755, root, root) %{_sbindir}/virtinterfaced
%{_libdir}/%{name}/connection-driver/libvirt_driver_interface.so
%{_mandir}/man8/virtinterfaced.8*

%files daemon-driver-network
%config(noreplace) %{_sysconfdir}/sysconfig/virtnetworkd
%config(noreplace) %{_sysconfdir}/libvirt/virtnetworkd.conf
%{_datadir}/augeas/lenses/virtnetworkd.aug
%{_datadir}/augeas/lenses/tests/test_virtnetworkd.aug
%{_unitdir}/virtnetworkd.service
%{_unitdir}/virtnetworkd.socket
%{_unitdir}/virtnetworkd-ro.socket
%{_unitdir}/virtnetworkd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtnetworkd
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/networks/
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/networks/autostart
%ghost %dir %{_rundir}/libvirt/network/
%dir %attr(0700, root, root) %{_localstatedir}/lib/libvirt/network/
%dir %attr(0755, root, root) %{_localstatedir}/lib/libvirt/dnsmasq/
%attr(0755, root, root) %{_libexecdir}/libvirt_leaseshelper
%{_libdir}/%{name}/connection-driver/libvirt_driver_network.so
%{_mandir}/man8/virtnetworkd.8*

%if %{with_firewalld_zone}
%{_prefix}/lib/firewalld/zones/libvirt.xml
%endif

%files daemon-driver-nodedev
%config(noreplace) %{_sysconfdir}/sysconfig/virtnodedevd
%config(noreplace) %{_sysconfdir}/libvirt/virtnodedevd.conf
%{_datadir}/augeas/lenses/virtnodedevd.aug
%{_datadir}/augeas/lenses/tests/test_virtnodedevd.aug
%{_unitdir}/virtnodedevd.service
%{_unitdir}/virtnodedevd.socket
%{_unitdir}/virtnodedevd-ro.socket
%{_unitdir}/virtnodedevd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtnodedevd
%{_libdir}/%{name}/connection-driver/libvirt_driver_nodedev.so
%{_mandir}/man8/virtnodedevd.8*

%files daemon-driver-nwfilter
%config(noreplace) %{_sysconfdir}/sysconfig/virtnwfilterd
%config(noreplace) %{_sysconfdir}/libvirt/virtnwfilterd.conf
%{_datadir}/augeas/lenses/virtnwfilterd.aug
%{_datadir}/augeas/lenses/tests/test_virtnwfilterd.aug
%{_unitdir}/virtnwfilterd.service
%{_unitdir}/virtnwfilterd.socket
%{_unitdir}/virtnwfilterd-ro.socket
%{_unitdir}/virtnwfilterd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtnwfilterd
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/nwfilter/
%ghost %dir %{_rundir}/libvirt/network/
%{_libdir}/%{name}/connection-driver/libvirt_driver_nwfilter.so
%{_mandir}/man8/virtnwfilterd.8*

%files daemon-driver-secret
%config(noreplace) %{_sysconfdir}/sysconfig/virtsecretd
%config(noreplace) %{_sysconfdir}/libvirt/virtsecretd.conf
%{_datadir}/augeas/lenses/virtsecretd.aug
%{_datadir}/augeas/lenses/tests/test_virtsecretd.aug
%{_unitdir}/virtsecretd.service
%{_unitdir}/virtsecretd.socket
%{_unitdir}/virtsecretd-ro.socket
%{_unitdir}/virtsecretd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtsecretd
%{_libdir}/%{name}/connection-driver/libvirt_driver_secret.so
%{_mandir}/man8/virtsecretd.8*

%files daemon-driver-storage

%files daemon-driver-storage-core
%config(noreplace) %{_sysconfdir}/sysconfig/virtstoraged
%config(noreplace) %{_sysconfdir}/libvirt/virtstoraged.conf
%{_datadir}/augeas/lenses/virtstoraged.aug
%{_datadir}/augeas/lenses/tests/test_virtstoraged.aug
%{_unitdir}/virtstoraged.service
%{_unitdir}/virtstoraged.socket
%{_unitdir}/virtstoraged-ro.socket
%{_unitdir}/virtstoraged-admin.socket
%attr(0755, root, root) %{_sbindir}/virtstoraged
%attr(0755, root, root) %{_libexecdir}/libvirt_parthelper
%{_libdir}/%{name}/connection-driver/libvirt_driver_storage.so
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_fs.so
%{_libdir}/%{name}/storage-file/libvirt_storage_file_fs.so
%{_mandir}/man8/virtstoraged.8*

%files daemon-driver-storage-disk
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_disk.so

%files daemon-driver-storage-logical
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_logical.so

%files daemon-driver-storage-scsi
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_scsi.so

%files daemon-driver-storage-iscsi
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_iscsi.so

%if %{with_storage_iscsi_direct}
%files daemon-driver-storage-iscsi-direct
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_iscsi-direct.so
%endif

%files daemon-driver-storage-mpath
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_mpath.so

%if %{with_storage_gluster}
%files daemon-driver-storage-gluster
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_gluster.so
%{_libdir}/%{name}/storage-file/libvirt_storage_file_gluster.so
%endif

%if %{with_storage_rbd}
%files daemon-driver-storage-rbd
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_rbd.so
%endif

%if %{with_storage_sheepdog}
%files daemon-driver-storage-sheepdog
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_sheepdog.so
%endif

%if %{with_storage_zfs}
%files daemon-driver-storage-zfs
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_zfs.so
%endif

%if %{with_qemu}
%files daemon-driver-qemu
%config(noreplace) %{_sysconfdir}/sysconfig/virtqemud
%config(noreplace) %{_sysconfdir}/libvirt/virtqemud.conf
%config(noreplace) %{_prefix}/lib/sysctl.d/60-qemu-postcopy-migration.conf
%{_datadir}/augeas/lenses/virtqemud.aug
%{_datadir}/augeas/lenses/tests/test_virtqemud.aug
%{_unitdir}/virtqemud.service
%{_unitdir}/virtqemud.socket
%{_unitdir}/virtqemud-ro.socket
%{_unitdir}/virtqemud-admin.socket
%attr(0755, root, root) %{_sbindir}/virtqemud
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/
%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/qemu/
%config(noreplace) %{_sysconfdir}/libvirt/qemu.conf
%config(noreplace) %{_sysconfdir}/libvirt/qemu-lockd.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd.qemu
%ghost %dir %{_rundir}/libvirt/qemu/
%dir %attr(0751, %{qemu_user}, %{qemu_group}) %{_localstatedir}/lib/libvirt/qemu/
%dir %attr(0750, root, root) %{_localstatedir}/cache/libvirt/qemu/
%{_datadir}/augeas/lenses/libvirtd_qemu.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd_qemu.aug
%{_libdir}/%{name}/connection-driver/libvirt_driver_qemu.so
%dir %attr(0711, root, root) %{_localstatedir}/lib/libvirt/swtpm/
%dir %attr(0730, tss, tss) %{_localstatedir}/log/swtpm/libvirt/qemu/
%{_bindir}/virt-qemu-run
%{_mandir}/man1/virt-qemu-run.1*
%{_mandir}/man8/virtqemud.8*
%endif

%if %{with_lxc}
%files daemon-driver-lxc
%config(noreplace) %{_sysconfdir}/sysconfig/virtlxcd
%config(noreplace) %{_sysconfdir}/libvirt/virtlxcd.conf
%{_datadir}/augeas/lenses/virtlxcd.aug
%{_datadir}/augeas/lenses/tests/test_virtlxcd.aug
%{_unitdir}/virtlxcd.service
%{_unitdir}/virtlxcd.socket
%{_unitdir}/virtlxcd-ro.socket
%{_unitdir}/virtlxcd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtlxcd
%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/lxc/
%config(noreplace) %{_sysconfdir}/libvirt/lxc.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd.lxc
%ghost %dir %{_rundir}/libvirt/lxc/
%dir %attr(0700, root, root) %{_localstatedir}/lib/libvirt/lxc/
%{_datadir}/augeas/lenses/libvirtd_lxc.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd_lxc.aug
%attr(0755, root, root) %{_libexecdir}/libvirt_lxc
%{_libdir}/%{name}/connection-driver/libvirt_driver_lxc.so
%{_mandir}/man8/virtlxcd.8*
%endif

%if %{with_libxl}
%files daemon-driver-libxl
%config(noreplace) %{_sysconfdir}/sysconfig/virtxend
%config(noreplace) %{_sysconfdir}/libvirt/virtxend.conf
%{_datadir}/augeas/lenses/virtxend.aug
%{_datadir}/augeas/lenses/tests/test_virtxend.aug
%{_unitdir}/virtxend.service
%{_unitdir}/virtxend.socket
%{_unitdir}/virtxend-ro.socket
%{_unitdir}/virtxend-admin.socket
%attr(0755, root, root) %{_sbindir}/virtxend
%config(noreplace) %{_sysconfdir}/libvirt/libxl.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd.libxl
%config(noreplace) %{_sysconfdir}/libvirt/libxl-lockd.conf
%{_datadir}/augeas/lenses/libvirtd_libxl.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd_libxl.aug
%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/libxl/
%ghost %dir %{_rundir}/libvirt/libxl/
%dir %attr(0700, root, root) %{_localstatedir}/lib/libvirt/libxl/
%{_libdir}/%{name}/connection-driver/libvirt_driver_libxl.so
%{_mandir}/man8/virtxend.8*
%endif

%if %{with_vbox}
%files daemon-driver-vbox
%config(noreplace) %{_sysconfdir}/sysconfig/virtvboxd
%config(noreplace) %{_sysconfdir}/libvirt/virtvboxd.conf
%{_datadir}/augeas/lenses/virtvboxd.aug
%{_datadir}/augeas/lenses/tests/test_virtvboxd.aug
%{_unitdir}/virtvboxd.service
%{_unitdir}/virtvboxd.socket
%{_unitdir}/virtvboxd-ro.socket
%{_unitdir}/virtvboxd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtvboxd
%{_libdir}/%{name}/connection-driver/libvirt_driver_vbox.so
%{_mandir}/man8/virtvboxd.8*
%endif

%if %{with_qemu_tcg}
%files daemon-qemu
%endif

%if %{with_qemu_kvm}
%files daemon-kvm
%endif

%if %{with_lxc}
%files daemon-lxc
%endif

%if %{with_libxl}
%files daemon-xen
%endif

%if %{with_vbox}
%files daemon-vbox
%endif

%if %{with_sanlock}
%files lock-sanlock
    %if %{with_qemu}
%config(noreplace) %{_sysconfdir}/libvirt/qemu-sanlock.conf
    %endif
    %if %{with_libxl}
%config(noreplace) %{_sysconfdir}/libvirt/libxl-sanlock.conf
    %endif
%attr(0755, root, root) %{_libdir}/libvirt/lock-driver/sanlock.so
%{_datadir}/augeas/lenses/libvirt_sanlock.aug
%{_datadir}/augeas/lenses/tests/test_libvirt_sanlock.aug
%dir %attr(0770, root, sanlock) %{_localstatedir}/lib/libvirt/sanlock
%{_sbindir}/virt-sanlock-cleanup
%{_mandir}/man8/virt-sanlock-cleanup.8*
%attr(0755, root, root) %{_libexecdir}/libvirt_sanlock_helper
%endif

%files client
%{_mandir}/man1/virsh.1*
%{_mandir}/man1/virt-xml-validate.1*
%{_mandir}/man1/virt-pki-query-dn.1*
%{_mandir}/man1/virt-pki-validate.1*
%{_bindir}/virsh
%{_bindir}/virt-xml-validate
%{_bindir}/virt-pki-query-dn
%{_bindir}/virt-pki-validate

%{_datadir}/bash-completion/completions/virsh

%files libs -f %{name}.lang
%license COPYING COPYING.LESSER
%config(noreplace) %{_sysconfdir}/libvirt/libvirt.conf
%config(noreplace) %{_sysconfdir}/libvirt/libvirt-admin.conf
%{_libdir}/libvirt.so.*
%{_libdir}/libvirt-qemu.so.*
%{_libdir}/libvirt-lxc.so.*
%{_libdir}/libvirt-admin.so.*
%dir %{_datadir}/libvirt/
%dir %{_datadir}/libvirt/schemas/
%dir %attr(0755, root, root) %{_localstatedir}/lib/libvirt/

%{_datadir}/systemtap/tapset/libvirt_probes*.stp
%{_datadir}/systemtap/tapset/libvirt_functions.stp
%if %{with_qemu}
%{_datadir}/systemtap/tapset/libvirt_qemu_probes*.stp
%endif

%{_datadir}/libvirt/schemas/*.rng

%{_datadir}/libvirt/cpu_map/*.xml

%{_datadir}/libvirt/test-screenshot.png

%if %{with_wireshark}
%files wireshark
%{wireshark_plugindir}/libvirt.so
%endif

%files nss
%{_libdir}/libnss_libvirt.so.2
%{_libdir}/libnss_libvirt_guest.so.2

%if %{with_lxc}
%files login-shell
%attr(4750, root, virtlogin) %{_bindir}/virt-login-shell
%{_libexecdir}/virt-login-shell-helper
%config(noreplace) %{_sysconfdir}/libvirt/virt-login-shell.conf
%{_mandir}/man1/virt-login-shell.1*
%endif

%files devel
%{_libdir}/libvirt.so
%{_libdir}/libvirt-admin.so
%{_libdir}/libvirt-qemu.so
%{_libdir}/libvirt-lxc.so
%dir %{_includedir}/libvirt
%{_includedir}/libvirt/virterror.h
%{_includedir}/libvirt/libvirt.h
%{_includedir}/libvirt/libvirt-admin.h
%{_includedir}/libvirt/libvirt-common.h
%{_includedir}/libvirt/libvirt-domain.h
%{_includedir}/libvirt/libvirt-domain-checkpoint.h
%{_includedir}/libvirt/libvirt-domain-snapshot.h
%{_includedir}/libvirt/libvirt-event.h
%{_includedir}/libvirt/libvirt-host.h
%{_includedir}/libvirt/libvirt-interface.h
%{_includedir}/libvirt/libvirt-network.h
%{_includedir}/libvirt/libvirt-nodedev.h
%{_includedir}/libvirt/libvirt-nwfilter.h
%{_includedir}/libvirt/libvirt-secret.h
%{_includedir}/libvirt/libvirt-storage.h
%{_includedir}/libvirt/libvirt-stream.h
%{_includedir}/libvirt/libvirt-qemu.h
%{_includedir}/libvirt/libvirt-lxc.h
%{_libdir}/pkgconfig/libvirt.pc
%{_libdir}/pkgconfig/libvirt-admin.pc
%{_libdir}/pkgconfig/libvirt-qemu.pc
%{_libdir}/pkgconfig/libvirt-lxc.pc

%dir %{_datadir}/libvirt/api/
%{_datadir}/libvirt/api/libvirt-api.xml
%{_datadir}/libvirt/api/libvirt-admin-api.xml
%{_datadir}/libvirt/api/libvirt-qemu-api.xml
%{_datadir}/libvirt/api/libvirt-lxc-api.xml


%changelog
* Mon Jul 31 2023 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-22
- lib: Set up cpuset controller for restrictive numatune (rhbz#2223464)

* Thu Jun 22 2023 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-21
- nodedev: update transient mdevs (rhbz#2143160)

* Fri May 19 2023 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-20
- qemu: monitor: Drop old monitor fields from 'struct _qemuMonitorMessage' (rhbz#2170472)
- qemu: Make 'struct _qemuMonitorMessage' private (rhbz#2170472)
- qemu: monitor: Move declaration of struct _qemuMonitor to qemu_monitor_priv.h (rhbz#2170472)
- qemu: qemuBlockGetNamedNodeData: Remove pointless error path (rhbz#2170472)
- qemu: monitor: Store whether 'query-named-block-nodes' supports 'flat' parameter (rhbz#2170472)
- qemuMonitorJSONBlockStatsUpdateCapacityBlockdev: Use 'flat' mode of query-named-block-nodes (rhbz#2170472)
- qemu: relax shared memory check for vhostuser daemons (rhbz#2177701)
- virpci: Resolve leak in virPCIVirtualFunctionList cleanup (CVE-2023-2700)
- node_device_conf: Avoid memleak in virNodeDeviceGetPCIVPDDynamicCap() (CVE-2023-2700)

* Tue Mar 14 2023 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-19
- qemu: domain: Fix logic when tainting domain (rhbz#2174447)
- qemu: agent: Make fetching of 'can-offline' member from 'guest-query-vcpus' optional (rhbz#2174447)

* Wed Mar  1 2023 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-18
- conf: Make VIR_DOMAIN_NET_TYPE_ETHERNET not share 'host view' (rhbz#2172578)

* Thu Feb  9 2023 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-17
- vircpi: Add PCIe 5.0 and 6.0 link speeds (rhbz#2168116)

* Wed Feb  8 2023 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-16
- qemu_namespace: Don't leak memory in qemuDomainGetPreservedMounts() (rhbz#2166573)

* Tue Jan 31 2023 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-15
- nodedev: fix reported error msg in css cap XML parsing (rhbz#2165011)
- util: refactor virDomainDeviceCCWAddress into virccw.h (rhbz#2165011)
- util: refactor virDomainCCWAddressAsString into virccw (rhbz#2165011)
- util: make reuse of ccw device address format constant (rhbz#2165011)
- util: refactor ccw address constants into virccw (rhbz#2165011)
- util: refactor virDomainCCWAddressIncrement into virccw (rhbz#2165011)
- util: refactor virDomainDeviceCCWAddressIsValid into virccw (rhbz#2165011)
- util: refactor virDomainDeviceCCWAddressEqual into virccw (rhbz#2165011)
- conf: adjust method name virDomainDeviceCCWAddressParseXML (rhbz#2165011)
- util: add ccw device address parsing into virccw (rhbz#2165011)
- util: add virCCWDeviceAddressFromString to virccw (rhbz#2165011)
- nodedev: refactor css format from ccw format method (rhbz#2165011)
- nodedev: refactor ccw device address parsing from XML (rhbz#2165011)
- nodedev: refactor css XML parsing from ccw XML parsing (rhbz#2165011)
- schemas: refactor out nodedev ccw address schema (rhbz#2165011)
- nodedev: add optional device address of channel device to css device (rhbz#2165011)
- nodedev: add tests for optional device address to css device (rhbz#2165011)
- nodedev: prevent internal error on dev_busid parse (rhbz#2165011)
- rpc: Fix memory leak of fds (rhbz#2165428)

* Wed Jan 11 2023 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-14
- qemu: Ignore missing vm.unprivileged_userfaultfd sysctl (rhbz#2148578)

* Wed Jan  4 2023 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-13
- build: Only install libvirt-guests when building libvirtd (rhbz#2153688)
- tools: Fix install_mode for some scripts (rhbz#2153688)

* Tue Dec 13 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-12
- util: json: Split out array->strinlist conversion from virJSONValueObjectGetStringArray (rhbz#2149752)
- qemuAgentGetDisks: Don't use virJSONValueObjectGetStringArray for optional data (rhbz#2149752)
- virpidfile: Add virPidFileReadPathIfLocked func (rhbz#2152188)
- qemu: tpm: Get swtpm pid without binary validation (rhbz#2152188)
- qemu_tpm: Do async IO when starting swtpm emulator (rhbz#2152188)
- qemu: gpu: Get pid without binary validation (rhbz#2152188)
- spec: libvirt-daemon: Add optional dependency on *-client (rhbz#2136591)

* Fri Oct  7 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-11
- qemu_process: Don't require a hugetlbfs mount for memfd (rhbz#2123196)
- qemu_namespace: Tolerate missing ACLs when creating a path in namespace (rhbz#2123196)
- qemu_namespace: Fix a corner case in qemuDomainGetPreservedMounts() (rhbz#2123196)
- qemu_namespace: Introduce qemuDomainNamespaceSetupPath() (rhbz#2123196)
- qemu_process.c: Propagate hugetlbfs mounts on reconnect (rhbz#2123196)
- qemuProcessReconnect: Don't build memory paths (rhbz#2123196)

* Mon Jul 25 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-10
- security_selinux.c: Relabel existing mode="bind" UNIX sockets (rhbz#2101575)
- RHEL: qemu_migration: Fix restoring memlock limit on destination (rhbz#2107954)

* Thu Jun 30 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-9
- conf: virtiofs: add thread_pool element (rhbz#2079582)
- qemu: virtiofs: format --thread-pool-size (rhbz#2079582)
- conf: Move virDomainObj::originalMemlock into qemuDomainObjPrivate (rhbz#2089433)
- qemu_domain: Format qemuDomainObjPrivate::originalMemlock (rhbz#2089433)
- qemu: Add qemuDomainSetMaxMemLock helper (rhbz#2089433)
- qemu_migration: Use qemuDomainSetMaxMemLock (rhbz#2089433)
- qemu_migration: Restore original memory locking limit (rhbz#2089433)
- Add VIR_MIGRATE_ZEROCOPY flag (rhbz#2089433)
- virsh: Add support for VIR_MIGRATE_ZEROCOPY flag (rhbz#2089433)
- qemu_migration: Implement VIR_MIGRATE_ZEROCOPY flag (rhbz#2089433)

* Wed Jun 15 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-8
- nwfilter: fix crash when counting number of network filters (CVE-2022-0897, rhbz#2063902)
- virDomainDiskDefValidate: Improve error messages for 'startupPolicy' checks (rhbz#2095758)
- domain_validate: Split out validation of disk startup policy (rhbz#2095758)
- virDomainDiskDefValidateStartupPolicy: Validate disk type better (rhbz#2095758)
- virDomainDiskTranslateSourcePool: Fix check of 'startupPolicy' definition (rhbz#2095758)

* Tue May 17 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-7
- cpu_map: Disable cpu64-rhel* for host-model and baseline (rhbz#1851227)
- cputest: Drop some old artificial baseline tests (rhbz#1851227)
- cputest: Give better names to baseline tests (rhbz#1851227)
- cputest: Add some real world baseline tests (rhbz#1851227)
- cpu_x86: Consolidate signature match in x86DecodeUseCandidate (rhbz#1851227)
- cpu_x86: Refactor feature list comparison in x86DecodeUseCandidate (rhbz#1851227)
- cpu_x86: Penalize disabled features when computing CPU model (rhbz#1851227)
- cpu_x86: Ignore enabled features for input models in x86DecodeUseCandidate (rhbz#1851227)

* Wed Apr 27 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-6
- conf: Introduce memory allocation threads (rhbz#2067126)
- qemu_capabilities: Detect memory-backend-*.prealloc-threads property (rhbz#2067126)
- qemu_validate: Validate prealloc threads against qemuCpas (rhbz#2067126)
- qemu_command: Generate prealloc-threads property (rhbz#2067126)

* Fri Feb 25 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-5
- node_device: Rework udevKludgeStorageType() (rhbz#2056673)
- node_device: Treat NVMe disks as regular disks (rhbz#2056673)

* Thu Feb 10 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-4
- qemu_command: Generate memory only after controllers (rhbz#2050697)
- qemu: Validate domain definition even on migration (rhbz#2050702)

* Wed Feb  2 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-3
- qemuDomainSetupDisk: Initialize 'targetPaths' (rhbz#2046172)
- RHEL: Remove <glib-2.64.0 workaround for GSource race (rhbz#2045879)

* Wed Jan 26 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-2
- Revert "report error when virProcessGetStatInfo() is unable to parse data" (rhbz#2041610)
- qemu: fix inactive snapshot revert (rhbz#2043584)

* Fri Jan 14 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-1
- Rebased to libvirt-8.0.0 (rhbz#2012802)

* Thu Jan 13 2022 Jiri Denemark <jdenemar@redhat.com> - 8.0.0-0rc1.1
- Rebased to libvirt-8.0.0-rc1 (rhbz#2012802)
- The rebase also fixes the following bugs:
    rhbz#1689202, rhbz#2014369, rhbz#2030119, rhbz#2029380, rhbz#2035237
    rhbz#2035714, rhbz#2034180

* Wed Dec  1 2021 Jiri Denemark <jdenemar@redhat.com> - 7.10.0-1
- Rebased to libvirt-7.10.0 (rhbz#2012802)
- The rebase also fixes the following bugs:
    rhbz#1845468, rhbz#2017928, rhbz#2024419, rhbz#1953389, rhbz#1510237

* Wed Nov  3 2021 Jiri Denemark <jdenemar@redhat.com> - 7.9.0-1
- Rebased to libvirt-7.9.0 (rhbz#2012802)
- The rebase also fixes the following bugs:
    rhbz#2011731, rhbz#2012385, rhbz#2013539

* Fri Oct 15 2021 Jiri Denemark <jdenemar@redhat.com> - 7.8.0-1
- Rebased to libvirt-7.8.0 (rhbz#2012802)
- The rebase also fixes the following bugs:
    rhbz#1839070, rhbz#1942275, rhbz#1995865, rhbz#1806857, rhbz#1924616
    rhbz#1978574, rhbz#1989457, rhbz#1965589, rhbz#1677608, rhbz#1926508
    rhbz#1810863, rhbz#1845468, rhbz#1738392, rhbz#1965140

* Thu Sep 2 2021 Danilo C. L. de Paula <ddepaula@redhat.com> - 7.6.0-2.fc34
- Resolves: bz#2000225
  (Rebase virt:rhel module:stream based on AV-8.6)

* Fri Aug  6 2021 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-37
- security: fix SELinux label generation logic (CVE-2021-3631)
- storage_driver: Unlock object on ACL fail in storagePoolLookupByTargetPath (CVE-2021-3667)

* Tue Jun  1 2021 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-36
- network: make it safe to call networkSetupPrivateChains() multiple times (rhbz#1942805)
- network: force re-creation of iptables private chains on firewalld restart (rhbz#1942805)
- hostdev: Update mdev pointer reference after checking device type (rhbz#1940449)
- hostdev: mdev: Lookup mdevs by sysfs path rather than mdev struct (rhbz#1940449)
- qemu_firmware: don't error out for unknown firmware features (rhbz#1961562)
- docs: improve description of secure attribute for loader element (rhbz#1929357)
- conf: introduce virDomainDefParseBootInitOptions (rhbz#1929357)
- conf: introduce virDomainDefParseBootKernelOptions (rhbz#1929357)
- conf: introduce virDomainDefParseBootFirmwareOptions (rhbz#1929357)
- conf: introduce virDomainDefParseBootLoaderOptions (rhbz#1929357)
- conf: introduce virDomainDefParseBootAcpiOptions (rhbz#1929357)
- conf: use switch in virDomainDefParseBootOptions (rhbz#1929357)
- conf: introduce support for firmware auto-selection feature filtering (rhbz#1929357)
- qemu: implement support for firmware auto-selection feature filtering (rhbz#1929357)
- domain_conf: Don't leak def->os.firmwareFeatures (rhbz#1929357)
- conf: remove duplicated firmware type attribute (rhbz#1929357)

* Thu Mar  4 2021 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-35
- vircgroupv2: properly detect placement of running VM (rhbz#1798463)
- virsystemd: export virSystemdHasMachined (rhbz#1798463)
- virsystemd: introduce virSystemdGetMachineByPID (rhbz#1798463)
- virsystemd: introduce virSystemdGetMachineUnitByPID (rhbz#1798463)
- vircgroup: use DBus call to systemd for some APIs (rhbz#1798463)
- vircgroupv1: refactor virCgroupV1DetectPlacement (rhbz#1798463)
- vircgroupv2: move task into cgroup before enabling controllers (rhbz#1798463)
- vircgroup: introduce virCgroupV1Exists and virCgroupV2Exists (rhbz#1798463)
- vircgroup: introduce nested cgroup to properly work with systemd (rhbz#1798463)
- tests: add cgroup nested tests (rhbz#1798463)
- vircgroup: correctly free nested virCgroupPtr (rhbz#1798463)
- qemu: Add virtio related options to vsock (rhbz#1931548)
- domain_validate: use defines for cpu period and quota limits (rhbz#1798463)
- docs: use proper cpu quota value in our documentation (rhbz#1798463)
- vircgroup: enforce range limit for cpu.shares (rhbz#1798463)
- cgroup: use virCgroupSetCpuShares instead of virCgroupSetupCpuShares (rhbz#1798463)
- cpumap: Add support for ibrs CPU feature (rhbz#1926864)
- cpumap: Add support for svme-addr-check CPU feature (rhbz#1926864)
- cpu_map: Add EPYC-Milan x86 CPU model (rhbz#1926864)
- cpu_map: Install x86_EPYC-Milan.xml (rhbz#1926864)
- cpu_map: Fix spelling of svme-addr-chk feature (rhbz#1926864)

* Mon Feb  1 2021 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-34
- qemu: move cgroup cpu period and quota defines to vircgroup.h (rhbz#1915733)
- vircgroupv1: use defines for cpu period and quota limits (rhbz#1915733)
- vircgroupv2: use defines for cpu period and quota limits (rhbz#1915733)
- vircgroup: fix cpu quota maximum limit (rhbz#1915733)
- util: add virNetDevGetPhysPortName (rhbz#1918708)
- util: avoid manual VIR_FREE of a g_autofree pointer in virPCIGetName() (rhbz#1918708)
- util: Add phys_port_name support on virPCIGetNetName (rhbz#1918708)

* Thu Jan 21 2021 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-33
- cpu_map: Fix Icelake Server model number (rhbz#1537734)
- cputestdata: Add test data for Snowridge (rhbz#1537734)
- cpu_map: Add support for fsrm CPU feature (rhbz#1537734)
- cpu_map: Add support for core-capability CPU feature (rhbz#1537734)
- cpu_map: Add support for split-lock-detect CPU feature (rhbz#1537734)
- cpu_map: Define and enable Snowridge model (rhbz#1537734)
- util: fix typo in VIR_MOCK_WRAP_RET_ARGS() (rhbz#1607929)
- util/tests: enable locking on iptables/ebtables commandlines in unit tests (rhbz#1607929)
- util/tests: enable locking on iptables/ebtables commandlines by default (rhbz#1607929)
- tests: fix iptables test case commandline options in virfirewalltest.c (rhbz#1607929)
- network: be more verbose about the reason for a firewall reload (rhbz#1607929)
- util: always check for ebtables/iptables binaries, even when using firewalld (rhbz#1607929)
- util: synchronize with firewalld before we start calling iptables directly (rhbz#1607929)
- util: call iptables directly rather than via firewalld (rhbz#1607929)
- util: virhostcpu: Fail when fetching CPU Stats for invalid cpu (rhbz#1915183)

* Tue Dec 15 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-32
- util: replace macvtap name reservation bitmap with a simple counter (rhbz#1874304)
- util: assign tap device names using a monotonically increasing integer (rhbz#1874304)
- util: virNetDevTapCreate: initialize fd to -1 (rhbz#1874304)

* Thu Dec 10 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-31
- conf: properly clear out autogenerated macvtap names when formatting/parsing (rhbz#1872610)
- qemu: format 'ramfb' attribute for mediated devices (rhbz#1876297)

* Mon Nov  9 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-30
- cpu_map: Add missing x86 features in 0x7 CPUID leaf (rhbz#1861506)
- cpu_map: Add missing x86 features in 0x80000008 CPUID leaf (rhbz#1861506)
- cpu_map: Add missing AMD SVM features (rhbz#1861506)
- Add testdata for AMD EPYC 7502 (rhbz#1861506)
- cpu_map: Defined and enable EPYC-Rome model (rhbz#1861506)
- cpu_map: Remove monitor feature from EPYC-Rome (rhbz#1861506)
- tests: qemuxml2argv: Use existing machine type for 'numatune-distances' case (rhbz#1749518)
- qemuxml2xmltest: Add "numatune-distance" test case (rhbz#1749518)
- conf: Move and rename virDomainParseScaledValue() (rhbz#1749518)
- numa_conf: Drop CPU from name of two functions (rhbz#1749518)
- qemu_command: Rename qemuBuildNumaArgStr() (rhbz#1749518)
- qemuBuildMachineCommandLine: Drop needless check (rhbz#1749518)
- numa_conf: Make virDomainNumaSetNodeCpumask() return void (rhbz#1749518)
- Allow NUMA nodes without vCPUs (rhbz#1749518)
- conf: Parse and format HMAT (rhbz#1749518)
- conf: Validate NUMA HMAT configuration (rhbz#1749518)
- numa: expose HMAT APIs (rhbz#1749518)
- qemu: Introduce QEMU_CAPS_NUMA_HMAT capability (rhbz#1749518)
- qemu: Build HMAT command line (rhbz#1749518)
- qemuBuildNumaCommandLine: Fix @masterInitiator check (rhbz#1749518)
- numa_conf: Properly check for caches in virDomainNumaDefValidate() (rhbz#1749518)
- RNG: Allow interleaving of /domain/cpu/numa/cell children (rhbz#1749518)

* Fri Oct  9 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-29
- qemu: substitute missing model name for host-passthrough (rhbz#1850680)
- rpc: gendispatch: handle empty flags (CVE-2020-25637)
- rpc: add support for filtering @acls by uint params (CVE-2020-25637)
- rpc: require write acl for guest agent in virDomainInterfaceAddresses (CVE-2020-25637)
- qemu: agent: set ifname to NULL after freeing (CVE-2020-25637)
- qemu: Fix domfsinfo for non-PCI device information from guest agent (rhbz#1858771)
- virDomainNetFindIdx: add support for CCW addresses (rhbz#1837495)
- check for NULL before calling g_regex_unref (rhbz#1861176)
- virhostcpu.c: fix 'die_id' parsing for Power hosts (rhbz#1876742)
- qemuFirmwareFillDomain: Fill NVRAM template on migration too (rhbz#1880418)
- node_device: refactor udevProcessCCW (rhbz#1853289, rhbz#1865932)
- node_device: detect CSS devices (rhbz#1853289, rhbz#1865932)
- virsh: nodedev: ability to filter CSS capabilities (rhbz#1853289, rhbz#1865932)
- node_device: detect DASD devices (rhbz#1853289, rhbz#1865932)
- udevProcessCSS: Check if def->driver is non-NULL (rhbz#1853289, rhbz#1865932)

* Wed Aug 26 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-28
- virdevmapper: Don't cache device-mapper major (rhbz#1860421)
- virdevmapper: Handle kernel without device-mapper support (rhbz#1860421)
- virdevmapper: Ignore all errors when opening /dev/mapper/control (rhbz#1860421)

* Fri Aug  7 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-27
- src: assume sys/sysmacros.h always exists on Linux (rhbz#1860421)
- virdevmapper.c: Join two WITH_DEVMAPPER sections together (rhbz#1860421)
- virDevMapperGetTargetsImpl: Use VIR_AUTOSTRINGLIST (rhbz#1860421)
- virdevmapper: Don't use libdevmapper to obtain dependencies (CVE-2020-14339, rhbz#1860421)
- virDevMapperGetTargets: Don't ignore EBADF (rhbz#1860421)

* Fri Jul 24 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-26
- qemu: blockjob: Don't base bitmap handling of active-layer block commit on QEMU_CAPS_BLOCKDEV_REOPEN (rhbz#1857779)
- qemu: blockjob: Actually delete temporary bitmap on failed active commit (rhbz#1857779)
- qemu: block: Remove 'active-write' bitmap even if there are no bitmaps to merge (rhbz#1857779)
- qemuDomainBlockPivot: Rename 'actions' to 'bitmapactions' (rhbz#1857779)
- qemuDomainBlockPivot: Ignore failures of creating active layer bitmap (rhbz#1857779)

* Wed Jun 24 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-25
- Upgrade components in virt:rhel module:stream for RHEL-8.3 release (rhbz#1828317)
- conf: Don't format http cookies unless VIR_DOMAIN_DEF_FORMAT_SECURE is used (CVE-2020-14301)
- util: Introduce a parser for kernel cmdline arguments (rhbz#1848997)
- qemu: Check if s390 secure guest support is enabled (rhbz#1848997)
- qemu: Check if AMD secure guest support is enabled (rhbz#1848997)
- tools: Secure guest check on s390 in virt-host-validate (rhbz#1848997)
- tools: Secure guest check for AMD in virt-host-validate (rhbz#1848997)
- docs: Update AMD launch secure description (rhbz#1848997)
- docs: Describe protected virtualization guest setup (rhbz#1848997)

* Fri Jun 19 2020 Danilo C. L. de Paula <ddepaula@redhat.com> - 6.0.0
- Resolves: bz#1828317
(Upgrade components in virt:rhel module:stream for RHEL-8.3 release)

* Tue Jun 09 2020 Danilo C. L. de Paula <ddepaula@redhat.com> - 6.0.0
- Resolves: bz#1810193
(Upgrade components in virt:rhel module:stream for RHEL-8.3 release)

* Fri Jun 05 2020 Danilo C. L. de Paula <ddepaula@redhat.com> - 6.0.0
- Resolves: bz#1810193
(Upgrade components in virt:rhel module:stream for RHEL-8.3 release)

* Mon Apr 27 2020 Danilo C. L. de Paula <ddepaula@redhat.com> - 6.0.0
- Resolves: bz#1810193
  (Upgrade components in virt:rhel module:stream for RHEL-8.3 release)

* Mon Mar 16 2020 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-42
- RHEL: virscsi: Check device type before getting it's /dev node name (rhbz#1808388)
- RHEL: virscsi: Support TAPEs in virSCSIDeviceGetDevName() (rhbz#1808388)
- RHEL: virscsi: Introduce and use virSCSIDeviceGetUnprivSGIOSysfsPath() (rhbz#1808388)
- RHEL: virutil: Accept non-block devices in virGetDeviceID() (rhbz#1808388)
- RHEL: qemuSetUnprivSGIO: Actually use calculated @sysfs_path to set unpriv_sgio (rhbz#1808388)
- RHEL: qemuCheckUnprivSGIO: use @sysfs_path to get unpriv_sgio (rhbz#1808399)

* Wed Mar  4 2020 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-41
- qemu: Translate features in virQEMUCapsGetCPUFeatures (rhbz#1804224)

* Mon Feb 17 2020 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-40
- process: wait longer on kill per assigned Hostdev (rhbz#1785338)
- process: wait longer 5->30s on hard shutdown (rhbz#1785338)

* Mon Feb 10 2020 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-39
- selinux: Do not report an error when not returning -1 (rhbz#1788096)
- qemu: Fix hyperv features with QEMU 4.1 (rhbz#1794868)
- qemu: Prefer dashes for hyperv features (rhbz#1794868)
- cpu: Drop KVM_ from hyperv feature macros (rhbz#1794868)
- cpu: Drop unused KVM features (rhbz#1794868)
- qemu: Fix KVM features with QEMU 4.1 (rhbz#1794868)
- cpu: Drop CPUID definition for hv-spinlocks (rhbz#1794868)

* Tue Jan 14 2020 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-38
- cpu_map/x86: Add support for BFLOAT16 data type (rhbz#1749516)

* Fri Dec 13 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-37
- cpu_map: Add TAA_NO bit for IA32_ARCH_CAPABILITIES MSR (CVE-2019-11135)
- cpu_map: Add TSX_CTRL bit for IA32_ARCH_CAPABILITIES MSR (CVE-2019-11135)

* Thu Nov 21 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-36
- cpu_conf: Pass policy to CPU feature filtering callbacks (rhbz#1749672, rhbz#1756156, rhbz#1721608)
- qemuxml2*test: Add tests for Icelake-Server, -pconfig (rhbz#1749672, rhbz#1756156, rhbz#1721608)
- qemu: Drop disabled CPU features unknown to QEMU (rhbz#1749672, rhbz#1756156, rhbz#1721608)
- cputest: Add data for Ice Lake Server CPU (rhbz#1749672, rhbz#1756156, rhbz#1721608)
- cpu_map: Drop pconfig from Icelake-Server CPU model (rhbz#1749672, rhbz#1756156, rhbz#1721608)
- qemu: Fix NULL ptr dereference caused by qemuDomainDefFormatBufInternal (rhbz#1749672, rhbz#1756156, rhbz#1721608)

* Mon Sep 16 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-35
- vircgroupv2: fix setting cpu.max period (rhbz#1749227)

* Wed Sep  4 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-34
- vircgroupv2: fix abort in VIR_AUTOFREE (rhbz#1747440)

* Mon Aug 26 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-33
- vircgroupv2: fix parsing multiple values in single file (rhbz#1741825)
- vircgroupv2: fix virCgroupV2GetCpuCfsQuota for "max" value (rhbz#1741837)

* Mon Aug 19 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-32
- virDomainObjListAddLocked: Produce better error message than 'Duplicate key' (rhbz#1737790)
- virdbus: Grab a ref as long as the while loop is executed (rhbz#1741900)

* Tue Jul 30 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-31
- virDomainObjListAddLocked: fix double free (rhbz#1728530)
- docs: schemas: Decouple the virtio options from each other (rhbz#1729675)
- util: command: use VIR_AUTOFREE instead of VIR_FREE for scalar types (rhbz#1721434)
- util: command: define cleanup function using VIR_DEFINE_AUTOPTR_FUNC (rhbz#1721434)
- util: netdevopenvswitch: use VIR_AUTOFREE instead of VIR_FREE for scalar types (rhbz#1721434)
- util: virnetdevopenvswitch: Drop an unused variable @ovs_timeout (rhbz#1721434)
- util: netdevopenvswitch: use VIR_AUTOPTR for aggregate types (rhbz#1721434)
- util: suppress unimportant ovs-vsctl errors when getting interface stats (rhbz#1721434)
- virNetDevOpenvswitchInterfaceStats: Optimize for speed (rhbz#1721434)
- test: Introduce virnetdevopenvswitchtest (rhbz#1721434)
- vircommand: Separate mass FD closing into a function (rhbz#1721434)
- virCommand: use procfs to learn opened FDs (rhbz#1721434)
- util: command: Ignore bitmap errors when enumerating file descriptors to close (rhbz#1721434)
- util: Avoid possible error in virCommandMassClose (rhbz#1721434)
- vircgroup: fix cgroups v2 controllers detection (rhbz#1689297)
- vircgroupv2: store enabled controllers (rhbz#1689297)

* Wed Jul  3 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-30
- virWaitForDevices: Drop confusing part of comment (rhbz#1710575)
- lib: Drop UDEVSETTLE (rhbz#1710575)
- m4: Provide default value fore UDEVADM (rhbz#1710575)
- m4: Drop needless string checks (rhbz#1710575)
- util: vircgroup: introduce virCgroup(Get|Set)ValueRaw (rhbz#1658890)
- util: vircgroup: move virCgroupGetValueStr out of virCgroupGetValueForBlkDev (rhbz#1658890)
- util: vircgroupv1: add support for BFQ blkio files (rhbz#1658890)
- util: vircgroupv2: add support for BFQ files (rhbz#1658890)
- Handle copying bitmaps to larger data buffers (rhbz#1703160)

* Tue Jul  2 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-29
- cpu: allow include files for CPU definition (rhbz#1686895)
- cpu: fix cleanup when signature parsing fails (rhbz#1686895)
- cpu: push more parsing logic into common code (rhbz#1686895)
- cpu: simplify failure cleanup paths (rhbz#1686895)
- cpu_map: Add support for arch-capabilities feature (rhbz#1693433)
- cputest: Add data for Intel(R) Xeon(R) CPU E5-2630 v4 (rhbz#1686895)
- cputest: Add data for Intel(R) Core(TM) i7-7600U (rhbz#1686895)
- cputest: Add data for Intel(R) Xeon(R) CPU E7540 (rhbz#1686895)
- cputest: Add data for Intel(R) Xeon(R) CPU E5-2650 (rhbz#1686895)
- cputest: Add data for Intel(R) Core(TM) i7-8700 (rhbz#1686895)
- cpu_x86: Separate ancestor model parsing from x86ModelParse (rhbz#1686895)
- cpu_x86: Separate signature parsing from x86ModelParse (rhbz#1686895)
- cpu_x86: Separate vendor parsing from x86ModelParse (rhbz#1686895)
- cpu_x86: Separate feature list parsing from x86ModelParse (rhbz#1686895)
- cpu_x86: Make sure CPU model names are unique in cpu_map (rhbz#1686895)
- cpu_x86: Add x86ModelCopySignatures helper (rhbz#1686895)
- cpu_x86: Store CPU signature in an array (rhbz#1686895)
- cpu_x86: Allow multiple signatures for a CPU model (rhbz#1686895)
- cpu_x86: Log decoded CPU model and signatures (rhbz#1686895)
- qemu_capabilities: Inroduce virQEMUCapsGetCPUModelX86Data (rhbz#1686895)
- qemu_capabilities: Introduce virQEMUCapsGetCPUModelInfo (rhbz#1686895)
- qemu_capabilities: Use virQEMUCapsGetCPUModelInfo (rhbz#1686895)
- cpu_x86: Add virCPUx86DataGetSignature for tests (rhbz#1686895)
- cpu_map: Add hex representation of signatures (rhbz#1686895)
- cputest: Test CPU signatures (rhbz#1686895)
- cpu_map: Add more signatures for Conroe CPU model (rhbz#1686895)
- cpu_map: Add more signatures for Penryn CPU model (rhbz#1686895)
- cpu_map: Add more signatures for Nehalem CPU models (rhbz#1686895)
- cpu_map: Add more signatures for Westmere CPU model (rhbz#1686895)
- cpu_map: Add more signatures for SandyBridge CPU models (rhbz#1686895)
- cpu_map: Add more signatures for IvyBridge CPU models (rhbz#1686895)
- cpu_map: Add more signatures for Haswell CPU models (rhbz#1686895)
- cpu_map: Add more signatures for Broadwell CPU models (rhbz#1686895)
- cpu_map: Add more signatures for Skylake-Client CPU models (rhbz#1686895)
- cpu: Don't access invalid memory in virCPUx86Translate (rhbz#1686895)
- cpu_x86: Require <cpuid> within <feature> in CPU map (rhbz#1697627)
- cputest: Add data for Intel(R) Xeon(R) Platinum 8268 CPU (rhbz#1693433)
- cpu_map: Add Cascadelake-Server CPU model (rhbz#1693433)
- cpu_x86: Introduce virCPUx86DataItem container struct (rhbz#1697627)
- cpu_x86: Rename virCPUx86Vendor.cpuid (rhbz#1697627)
- cpu_x86: Rename virCPUx86DataItem variables (rhbz#1697627)
- cpu_x86: Rename x86DataCpuidNext function (rhbz#1697627)
- cpu_x86: Rename x86DataCpuid (rhbz#1697627)
- cpu_x86: Rename virCPUx86CPUIDSorter (rhbz#1697627)
- cpu_x86: Rename virCPUx86DataAddCPUIDInt (rhbz#1697627)
- cpu_x86: Rename virCPUx86DataAddCPUID (rhbz#1697627)
- cpu_x86: Rename virCPUx86VendorToCPUID (rhbz#1697627)
- cpu_x86: Simplify x86DataAdd (rhbz#1697627)
- cpu_x86: Introduce virCPUx86DataCmp (rhbz#1697627)
- cpu_x86: Make x86cpuidSetBits more general (rhbz#1697627)
- cpu_x86: Make x86cpuidClearBits more general (rhbz#1697627)
- cpu_x86: Make x86cpuidAndBits more general (rhbz#1697627)
- cpu_x86: Make x86cpuidMatchMasked more general (rhbz#1697627)
- cpu_x86: Make x86cpuidMatch more general (rhbz#1697627)
- cpu_x86: Store virCPUx86DataItem content in union (rhbz#1697627)
- cpu_x86: Add support for storing MSR features in CPU map (rhbz#1697627)
- cpu_x86: Move *CheckFeature functions (rhbz#1697627)
- cputest: Add support for MSR features to cpu-parse.sh (rhbz#1697627)
- util: file: introduce VIR_AUTOCLOSE macro to close fd of the file automatically (rhbz#1697627)
- vircpuhost: Add support for reading MSRs (rhbz#1697627)
- virhostcpu: Make virHostCPUGetMSR() work only on x86 (rhbz#1697627)
- cpu_x86: Fix placement of *CheckFeature functions (rhbz#1697627)
- cpu_conf: Introduce virCPUDefFilterFeatures (rhbz#1697627)
- qemu_command: Use consistent syntax for CPU features (rhbz#1697627)
- tests: Add QEMU caps data for future 4.1.0 (rhbz#1697627)
- tests: Add domain capabilities case for QEMU 4.1.0 (rhbz#1697627)
- qemuxml2argvtest: Add test for CPU features translation (rhbz#1697627)
- qemu: Add APIs for translating CPU features (rhbz#1697627)
- qemu: Probe for max-x86_64-cpu type (rhbz#1697627)
- qemu: Probe for "unavailable-features" CPU property (rhbz#1697627)
- qemu: Probe host CPU after capabilities (rhbz#1697627)
- qemu_command: Use canonical names of CPU features (rhbz#1697627)
- qemu: Translate feature names from query-cpu-model-expansion (rhbz#1697627)
- qemu: Don't use full CPU model expansion (rhbz#1697627)
- qemu: Make qemuMonitorGetGuestCPU usable on x86 only (rhbz#1697627)
- cpu: Introduce virCPUDataAddFeature (rhbz#1697627)
- qemu: Add type filter to qemuMonitorJSONParsePropsList (rhbz#1697627)
- util: string: Introduce macro for automatic string lists (rhbz#1697627)
- util: json: define cleanup function using VIR_DEFINE_AUTOPTR_FUNC (rhbz#1697627)
- qemu: Introduce generic qemuMonitorGetGuestCPU (rhbz#1697627)
- qemu_process: Prefer generic qemuMonitorGetGuestCPU (rhbz#1697627)
- util: Rework virStringListAdd (rhbz#1697627)
- conf: Introduce virCPUDefCheckFeatures (rhbz#1697627)
- cpu_x86: Turn virCPUx86DataIteratorInit into a function (rhbz#1697627)
- cpu_x86: Introduce virCPUx86FeatureFilter*MSR (rhbz#1697627)
- cpu_x86: Read CPU features from IA32_ARCH_CAPABILITIES MSR (rhbz#1697627)
- cpu_map: Introduce IA32_ARCH_CAPABILITIES MSR features (rhbz#1697627)
- qemu: Forbid MSR features with old QEMU (rhbz#1697627)
- qemu: Drop MSR features from host-model with old QEMU (rhbz#1697627)
- cpu_x86: Fix memory leak - virCPUx86GetHost (rhbz#1697627)
- qemu: Use @tmpChr in qemuDomainDetachChrDevice to build device string (rhbz#1624204)
- qemu: Drop "user-" prefix for guestfwd netdev (rhbz#1624204)
- qemu_hotplug: Attach guestfwd using netdev_add (rhbz#1624204)
- qemu_hotplug: Detach guestfwd using netdev_del (rhbz#1624204)
- qemuhotplugtest: Test guestfwd attach and detach (rhbz#1624204)
- daemon: Register secret driver before storage driver (rhbz#1685151)
- bhyve: Move autostarting of domains into bhyveStateInitialize (rhbz#1685151)
- Revert "virStateDriver - Separate AutoStart from Initialize" (rhbz#1685151)
- Revert "Separate out StateAutoStart from StateInitialize" (rhbz#1685151)
- util: moving 'type' argument to avoid issues with mount() syscall. (rhbz#1689297)
- util: cgroup: use VIR_AUTOFREE instead of VIR_FREE for scalar types (rhbz#1689297)
- vircgroup: Rename structs to start with underscore (rhbz#1689297)
- vircgroup: Introduce standard set of typedefs and use them (rhbz#1689297)
- vircgroup: Extract file link resolving into separate function (rhbz#1689297)
- vircgroup: Remove unused function virCgroupKill() (rhbz#1689297)
- vircgroup: Unexport unused function virCgroupAddTaskController() (rhbz#1689297)
- vircgroup: Unexport unused function virCgroupRemoveRecursively (rhbz#1689297)
- vircgroup: Move function used in tests into vircgrouppriv.h (rhbz#1689297)
- vircgroup: Remove pointless bool parameter (rhbz#1689297)
- vircgroup: Extract mount options matching into function (rhbz#1689297)
- vircgroup: Use virCgroupMountOptsMatchController in virCgroupDetectPlacement (rhbz#1689297)
- vircgroup: Introduce virCgroupEnableMissingControllers (rhbz#1689297)
- vircgroup: machinename will never be NULL (rhbz#1689297)
- vircgroup: Remove virCgroupAddTaskController (rhbz#1689297)
- vircgroup: Introduce virCgroupGetMemoryStat (rhbz#1689297)
- lxc: Use virCgroupGetMemoryStat (rhbz#1689297)
- vircgroup: fix MinGW build (rhbz#1689297)
- vircgroup: Duplicate string before modifying (rhbz#1689297)
- vircgroup: Extract controller detection into function (rhbz#1689297)
- vircgroup: Extract placement validation into function (rhbz#1689297)
- vircgroup: Split virCgroupPathOfController into two functions (rhbz#1689297)
- vircgroup: Call virCgroupRemove inside virCgroupMakeGroup (rhbz#1689297)
- vircgroup: Simplify if conditions in virCgroupMakeGroup (rhbz#1689297)
- vircgroup: Remove obsolete sa_assert (rhbz#1689297)
- tests: Resolve possible overrun (rhbz#1689297)
- vircgroup: cleanup controllers not managed by systemd on error (rhbz#1689297)
- vircgroup: fix bug in virCgroupEnableMissingControllers (rhbz#1689297)
- vircgroup: rename virCgroupAdd.*Task to virCgroupAdd.*Process (rhbz#1689297)
- vircgroup: introduce virCgroupTaskFlags (rhbz#1689297)
- vircgroup: introduce virCgroupAddThread (rhbz#1689297)
- vircgroupmock: cleanup unused cgroup files (rhbz#1689297)
- vircgroupmock: rewrite cgroup fopen mocking (rhbz#1689297)
- vircgrouptest: call virCgroupDetectMounts directly (rhbz#1689297)
- vircgrouptest: call virCgroupNewSelf instead virCgroupDetectMounts (rhbz#1689297)
- util: introduce vircgroupbackend files (rhbz#1689297)
- vircgroup: introduce cgroup v1 backend files (rhbz#1689297)
- vircgroup: extract virCgroupV1Available (rhbz#1689297)
- vircgroup: detect available backend for cgroup (rhbz#1689297)
- vircgroup: extract virCgroupV1ValidateMachineGroup (rhbz#1689297)
- vircgroup: extract virCgroupV1CopyMounts (rhbz#1689297)
- vircgroup: extract v1 detect functions (rhbz#1689297)
- vircgroup: extract virCgroupV1CopyPlacement (rhbz#1689297)
- vircgroup: extract virCgroupV1ValidatePlacement (rhbz#1689297)
- vircgroup: extract virCgroupV1StealPlacement (rhbz#1689297)
- vircgroup: extract virCgroupV1DetectControllers (rhbz#1689297)
- vircgroup: extract virCgroupV1HasController (rhbz#1689297)
- vircgroup: extract virCgroupV1GetAnyController (rhbz#1689297)
- vircgroup: extract virCgroupV1PathOfController (rhbz#1689297)
- vircgroup: extract virCgroupV1MakeGroup (rhbz#1689297)
- vircgroup: extract virCgroupV1Remove (rhbz#1689297)
- vircgroup: extract virCgroupV1AddTask (rhbz#1689297)
- vircgroup: extract virCgroupV1HasEmptyTasks (rhbz#1689297)
- vircgroup: extract virCgroupV1BindMount (rhbz#1689297)
- vircgroup: extract virCgroupV1SetOwner (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioWeight (rhbz#1689297)
- vircgroup: extract virCgroupV1GetBlkioIoServiced (rhbz#1689297)
- vircgroup: extract virCgroupV1GetBlkioIoDeviceServiced (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioDeviceWeight (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioDeviceReadIops (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioDeviceWriteIops (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioDeviceReadBps (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioDeviceWriteBps (rhbz#1689297)
- vircgroup: extract virCgroupV1SetMemory (rhbz#1689297)
- vircgroup: extract virCgroupV1GetMemoryStat (rhbz#1689297)
- vircgroup: extract virCgroupV1GetMemoryUsage (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)Memory*Limit (rhbz#1689297)
- vircgroup: extract virCgroupV1GetMemSwapUsage (rhbz#1689297)
- vircgroup: extract virCgroupV1(Allow|Deny)Device (rhbz#1689297)
- vircgroup: extract virCgroupV1(Allow|Deny)AllDevices (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpuShares (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpuCfsPeriod (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpuCfsQuota (rhbz#1689297)
- vircgroup: extract virCgroupV1SupportsCpuBW (rhbz#1689297)
- vircgroup: extract virCgroupV1GetCpuacct*Usage (rhbz#1689297)
- vircgroup: extract virCgroupV1GetCpuacctStat (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)FreezerState (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpusetMems (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpusetMemoryMigrate (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpusetCpus (rhbz#1689297)
- vircgroup: rename virCgroupController into virCgroupV1Controller (rhbz#1689297)
- vircgroup: rename controllers to legacy (rhbz#1689297)
- vircgroup: remove VIR_CGROUP_SUPPORTED (rhbz#1689297)
- vircgroup: include system headers only on linux (rhbz#1689297)
- vircgroupv1: fix build on non-linux OSes (rhbz#1689297)
- Revert "vircgroup: cleanup controllers not managed by systemd on error" (rhbz#1689297)
- util: introduce cgroup v2 files (rhbz#1689297)
- vircgroup: introduce virCgroupV2Available (rhbz#1689297)
- vircgroup: introduce virCgroupV2ValidateMachineGroup (rhbz#1689297)
- vircgroup: introduce virCgroupV2CopyMounts (rhbz#1689297)
- vircgroup: introduce virCgroupV2CopyPlacement (rhbz#1689297)
- vircgroup: introduce virCgroupV2DetectMounts (rhbz#1689297)
- vircgroup: introduce virCgroupV2DetectPlacement (rhbz#1689297)
- vircgroup: introduce virCgroupV2ValidatePlacement (rhbz#1689297)
- vircgroup: introduce virCgroupV2StealPlacement (rhbz#1689297)
- vircgroup: introduce virCgroupV2DetectControllers (rhbz#1689297)
- vircgroup: introduce virCgroupV2HasController (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetAnyController (rhbz#1689297)
- vircgroup: introduce virCgroupV2PathOfController (rhbz#1689297)
- vircgroup: introduce virCgroupV2MakeGroup (rhbz#1689297)
- vircgroup: introduce virCgroupV2Remove (rhbz#1689297)
- vircgroup: introduce virCgroupV2AddTask (rhbz#1689297)
- vircgroup: introduce virCgroupV2HasEmptyTasks (rhbz#1689297)
- vircgroup: introduce virCgroupV2BindMount (rhbz#1689297)
- vircgroup: introduce virCgroupV2SetOwner (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioWeight (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetBlkioIoServiced (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetBlkioIoDeviceServiced (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioDeviceWeight (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioDeviceReadIops (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioDeviceWriteIops (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioDeviceReadBps (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioDeviceWriteBps (rhbz#1689297)
- vircgroup: introduce virCgroupV2SetMemory (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetMemoryStat (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetMemoryUsage (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)MemoryHardLimit (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)MemorySoftLimit (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)MemSwapHardLimit (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetMemSwapUsage (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)CpuShares (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)CpuCfsPeriod (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)CpuCfsQuota (rhbz#1689297)
- vircgroup: introduce virCgroupV2SupportsCpuBW (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetCpuacctUsage (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetCpuacctStat (rhbz#1689297)
- vircgroup: register cgroup v2 backend (rhbz#1689297)
- vircgroup: add support for hybrid configuration (rhbz#1689297)
- vircgroupmock: change cgroup prefix (rhbz#1689297)
- vircgroupmock: add support to test cgroup v2 (rhbz#1689297)
- vircgrouptest: introduce initFakeFS and cleanupFakeFS helpers (rhbz#1689297)
- vircgrouptest: prepare testCgroupDetectMounts for cgroup v2 (rhbz#1689297)
- vircgrouptest: add detect mounts test for cgroup v2 (rhbz#1689297)
- vircgrouptest: add detect mounts test for hybrid cgroups (rhbz#1689297)
- vircgrouptest: prepare validateCgroup for cgroupv2 (rhbz#1689297)
- vircgrouptest: add cgroup v2 tests (rhbz#1689297)
- vircgrouptest: add hybrid tests (rhbz#1689297)
- virt-host-validate: rewrite cgroup detection to use util/vircgroup (rhbz#1689297)
- virt-host-validate: require freezer for LXC (rhbz#1689297)
- virt-host-validate: Fix build on non-Linux (rhbz#1689297)
- tests: Use correct function name in error path (rhbz#1689297)
- util: Fix virCgroupGetMemoryStat (rhbz#1689297)
- tests: Augment vcgrouptest to add virCgroupGetMemoryStat (rhbz#1689297)
- vircgroup: introduce virCgroupKillRecursiveCB (rhbz#1689297)
- vircgroupv2: fix virCgroupV2ValidateMachineGroup (rhbz#1689297)
- util: implement virCgroupV2(Set|Get)CpusetMems (rhbz#1689297)
- util: implement virCgroupV2(Set|Get)CpusetMemoryMigrate (rhbz#1689297)
- util: implement virCgroupV2(Set|Get)CpusetCpus (rhbz#1689297)
- util: enable cgroups v2 cpuset controller for threads (rhbz#1689297)
- util: vircgroup: pass parent cgroup into virCgroupDetectControllersCB (rhbz#1689297)
- internal: introduce a family of NULLSTR macros (rhbz#1689297)
- util: vircgroup: improve controller detection (rhbz#1689297)
- util: vircgroupv2: use any controller to create thread directory (rhbz#1689297)
- util: vircgroupv2: enable CPU controller only if it's available (rhbz#1689297)
- util: vircgroupv2: separate return values of virCgroupV2EnableController (rhbz#1689297)
- util: vircgroupv2: don't error out if enabling controller fails (rhbz#1689297)
- util: vircgroupv2: mark only requested controllers as available (rhbz#1689297)
- Revert "util: vircgroup: pass parent cgroup into virCgroupDetectControllersCB" (rhbz#1689297)
- util: vircgroupv2: stop enabling missing controllers with systemd (rhbz#1689297)

* Fri Jun 28 2019 Danilo de Paula <ddepaula@redhat.com> - 4.5.0-28
- Rebuild all virt packages to fix RHEL's upgrade path
- Resolves: rhbz#1695587
  (Ensure modular RPM upgrade path)

* Fri Jun 21 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-27
- RHEL: spec: Disable gluster on i686 (rhbz#1722668)
- rpc: virnetlibsshsession: update deprecated functions (rhbz#1722735)

* Thu Jun 20 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-26
- api: disallow virDomainSaveImageGetXMLDesc on read-only connections (CVE-2019-10161)
- api: disallow virDomainManagedSaveDefineXML on read-only connections (CVE-2019-10166)
- api: disallow virConnectGetDomainCapabilities on read-only connections (CVE-2019-10167)
- api: disallow virConnect*HypervisorCPU on read-only connections (CVE-2019-10168)

* Fri Jun 14 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-25
- admin: reject clients unless their UID matches the current UID (CVE-2019-10132)
- locking: restrict sockets to mode 0600 (CVE-2019-10132)
- logging: restrict sockets to mode 0600 (CVE-2019-10132)
- util: skip RDMA detection for non-PCI network devices (rhbz#1693299)
- virfile: Detect ceph as shared FS (rhbz#1698133)
- virfile: added GPFS as shared fs (rhbz#1698133)
- util: bitmap: define cleanup function using VIR_DEFINE_AUTOPTR_FUNC (rhbz#1716943)
- qemu: Rework setting process affinity (rhbz#1716943)
- qemu: Set up EMULATOR thread and cpuset.mems before exec()-ing qemu (rhbz#1716943)
- conf: Add definitions for 'uid' and 'fid' PCI address attributes (rhbz#1508149)
- qemu: Introduce zPCI capability (rhbz#1508149)
- qemu: Enable PCI multi bus for S390 guests (rhbz#1508149)
- conf: Introduce extension flag and zPCI member for PCI address (rhbz#1508149)
- conf: Introduce address caching for PCI extensions (rhbz#1508149)
- qemu: Auto add pci-root for s390/s390x guests (rhbz#1508149)
- conf: use virXMLFormatElement() in virDomainDeviceInfoFormat() (rhbz#1508149)
- conf: Introduce parser, formatter for uid and fid (rhbz#1508149)
- qemu: Add zPCI address definition check (rhbz#1508149)
- conf: Allocate/release 'uid' and 'fid' in PCI address (rhbz#1508149)
- qemu: Generate and use zPCI device in QEMU command line (rhbz#1508149)
- qemu: Add hotpluging support for PCI devices on S390 guests (rhbz#1508149)
- qemuDomainRemoveRNGDevice: Remove associated chardev too (rhbz#1508149)
- qemu_hotplug: remove erroneous call to qemuDomainDetachExtensionDevice() (rhbz#1508149)
- qemu_hotplug: remove another erroneous qemuDomainDetachExtensionDevice() call (rhbz#1508149)
- util: Propagate numad failures correctly (rhbz#1716907)
- util: Introduce virBitmapUnion() (rhbz#1716908)
- util: Introduce virNumaNodesetToCPUset() (rhbz#1716908)
- qemu: Fix qemuProcessInitCpuAffinity() (rhbz#1716908)
- qemu: Fix leak in qemuProcessInitCpuAffinity() (rhbz#1716908)
- qemu: Drop cleanup label from qemuProcessInitCpuAffinity() (rhbz#1716908)
- qemu: Fix NULL pointer access in qemuProcessInitCpuAffinity() (rhbz#1716908)
- qemuBuildMemoryBackendProps: Pass @priv instead of its individual members (rhbz#1624223)
- qemu: Don't use -mem-prealloc among with .prealloc=yes (rhbz#1624223)
- nwfilter: fix adding std MAC and IP values to filter binding (rhbz#1691356)
- qemuProcessBuildDestroyMemoryPathsImpl: Don't overwrite error (rhbz#1658112)
- qemu_security: Fully implement qemuSecurityDomainSetPathLabel (rhbz#1658112)
- qemu: process: SEV: Assume libDir to be the directory to create files in (rhbz#1658112)
- qemu: process: SEV: Relabel guest owner's SEV files created before start (rhbz#1658112)

* Tue May 14 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-24
- tests: qemuxml2argv: add CAPS_ARCH_LATEST macro (rhbz#1698855)
- qemu: Add ccw support for vhost-vsock (rhbz#1698855)
- qemu: Allow creating ppc64 guests with graphics and no USB mouse (rhbz#1683681)
- conf: Expose virDomainSCSIDriveAddressIsUsed (rhbz#1692354)
- qemuhotplugtest: Don't plug a SCSI disk at unit 7 (rhbz#1692354)
- qemu_hotplug: Check for duplicate drive addresses (rhbz#1692354)
- cpu_map: Add support for cldemote CPU feature (rhbz#1537731)
- util: alloc: add macros for implementing automatic cleanup functionality (rhbz#1505998)
- qemu: domain: Simplify non-VFIO memLockLimit calculation for PPC64 (rhbz#1505998)
- qemu_domain: add a PPC64 memLockLimit helper (rhbz#1505998)
- qemu_domain: NVLink2 bridge detection function for PPC64 (rhbz#1505998)
- PPC64 support for NVIDIA V100 GPU with NVLink2 passthrough (rhbz#1505998)
- cpu_x86: Do not cache microcode version (CVE-2018-12127, CVE-2019-11091, CVE-2018-12126, CVE-2018-12130)
- qemu: Don't cache microcode version (CVE-2018-12127, CVE-2019-11091, CVE-2018-12126, CVE-2018-12130)
- cputest: Add data for Intel(R) Xeon(R) CPU E3-1225 v5 (CVE-2018-12127, CVE-2019-11091, CVE-2018-12126, CVE-2018-12130)
- cpu_map: Define md-clear CPUID bit (CVE-2018-12127, CVE-2019-11091, CVE-2018-12126, CVE-2018-12130)

* Fri Feb 15 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-23
- network: explicitly allow icmp/icmpv6 in libvirt zonefile (rhbz#1650320)

* Fri Feb 15 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-22
- util: fix memory leak in virFirewallDInterfaceSetZone() (rhbz#1650320)

* Fri Feb  8 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-21
- docs: Drop /dev/net/tun from the list of shared devices (rhbz#1665400)
- qemu: conf: Remove /dev/sev from the default cgroup device acl list (rhbz#1665400)
- qemu: cgroup: Expose /dev/sev/ only to domains that require SEV (rhbz#1665400)
- qemu: domain: Add /dev/sev into the domain mount namespace selectively (rhbz#1665400)
- security: dac: Relabel /dev/sev in the namespace (rhbz#1665400)
- qemu: caps: Use CAP_DAC_OVERRIDE for probing to avoid permission issues (rhbz#1665400)
- qemu: caps: Don't try to ask for CAP_DAC_OVERRIDE if non-root (rhbz#1665400)
- Revert "RHEL: Require firewalld-filesystem for firewalld rpm macros" (rhbz#1650320)
- Revert "RHEL: network: regain guest network connectivity after firewalld switch to nftables" (rhbz#1650320)
- configure: change HAVE_FIREWALLD to WITH_FIREWALLD (rhbz#1650320)
- util: move all firewalld-specific stuff into its own files (rhbz#1650320)
- util: new virFirewallD APIs + docs (rhbz#1650320)
- configure: selectively install a firewalld 'libvirt' zone (rhbz#1650320)
- network: set firewalld zone of bridges to "libvirt" zone when appropriate (rhbz#1650320)
- network: allow configuring firewalld zone for virtual network bridge device (rhbz#1650320)
- util: remove test code accidentally committed to virFirewallDZoneExists (rhbz#1650320)
- qemu: command: Don't skip 'readonly' and throttling info for empty drive (rhbz#1670337)

* Mon Jan 28 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-20
- RHEL: qemu: Fix crash trying to use iSCSI hostdev (rhbz#1669424)

* Thu Jan 24 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-19
- qemu: Fix logic error in qemuSetUnprivSGIO (rhbz#1666605)
- tests: qemuxml2argv: Add test case for empty CDROM with cache mode (rhbz#1553255)
- qemu: command: Don't format image properties for empty -drive (rhbz#1553255)

* Mon Jan 14 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-18
- conf: correct false boot order error during domain parse (rhbz#1630393)
- qemu: Remove duplicated qemuAgentCheckError (rhbz#1665000)
- qemu: require reply from guest agent in qemuAgentGetInterfaces (rhbz#1665000)
- qemu: Filter non SCSI hostdevs in qemuHostdevPrepareSCSIDevices (rhbz#1665244)
- util: remove const specifier from nlmsghdr arg to virNetlinkDumpCallback() (rhbz#1583131)
- util: add a function to insert new interfaces to IPv6CheckForwarding list (rhbz#1583131)
- util: use nlmsg_find_attr() instead of an open-coded loop (rhbz#1583131)
- util: check accept_ra for all nexthop interfaces of multipath routes (rhbz#1583131)
- util: make forgotten changes suggested during review of commit d40b820c (rhbz#1583131)

* Mon Jan  7 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-17
- virsh: Strip XML declaration when extracting CPU XMLs (rhbz#1659048)
- RHEL: qemu: Add ability to set sgio values for hostdev (rhbz#1582424)
- RHEL: qemu: Add check for unpriv sgio for SCSI generic host device (rhbz#1582424)
- qemu: Alter @val usage in qemuSetUnprivSGIO (rhbz#1656362)
- qemu: Alter qemuSetUnprivSGIO hostdev shareable logic (rhbz#1656362)

* Mon Dec 17 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-16
- util: Don't overflow in virRandomBits (rhbz#1655586)
- virrandom: Avoid undefined behaviour in virRandomBits (rhbz#1655586)
- spec: remove libcgroup and cgconfig (rhbz#1602407)
- qemu: Drop duplicated code from qemuDomainDefValidateFeatures() (rhbz#1647822)
- tests: Add capabilities data for QEMU 3.1.0 on ppc64 (rhbz#1647822)
- qemu: Introduce QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV (rhbz#1647822)
- conf: Parse and format nested-hv feature (rhbz#1647822)
- qemu: Format nested-hv feature on the command line (rhbz#1647822)
- qemu: Add check for whether KVM nesting is enabled (rhbz#1645139)
- secret: Add check/validation for correct usage when LookupByUUID (rhbz#1656255)
- cpu: Add support for "stibp" x86_64 feature (rhbz#1655032)

* Mon Dec  3 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-15
- virfile: Take symlink into account in virFileIsSharedFixFUSE (rhbz#1634782)
- qemu: Ignore nwfilter binding instantiation issues during reconnect (rhbz#1648544)
- qemu: Set identity for the reconnect all thread (rhbz#1648546)
- Revert "access: Modify the VIR_ERR_ACCESS_DENIED to include driverName" (rhbz#1631608)
- access: Modify the VIR_ERR_ACCESS_DENIED to include driverName (rhbz#1631608)
- qemu: add vfio-ap capability (rhbz#1508146)
- qemu: vfio-ap device support (rhbz#1508146)
- qemu: Extract MDEV VFIO PCI validation code into a separate helper (rhbz#1508146)
- conf: Move VFIO AP validation from post parse to QEMU validation code (rhbz#1508146)
- qemu: Fix post-copy migration on the source (rhbz#1649169)

* Fri Nov  9 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-14
- storage: Remove secretPath from _virStorageBackendQemuImgInfo (rhbz#1645459)
- storage: Allow for inputvol to have any format for encryption (rhbz#1645459)
- storage: Allow inputvol to be encrypted (rhbz#1645459)
- access: Modify the VIR_ERR_ACCESS_DENIED to include driverName (rhbz#1631608)
- docs: Enhance polkit documentation to describe secondary connection (rhbz#1631608)
- qemu: Don't ignore resume events (rhbz#1634758, rhbz#1643338)

* Thu Nov  1 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-13
- Revert "spec: Temporarily drop gluster support" (rhbz#1599339)

* Wed Oct 17 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-12
- RHEL: Require firewalld-filesystem for firewalld rpm macros (rhbz#1639932)

* Tue Oct 16 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-11
- virfile: fix cast-align error (rhbz#1634782)
- virfiletest: Fix test name prefix for virFileInData test (rhbz#1634782)
- virfiletst: Test virFileIsSharedFS (rhbz#1634782)
- virFileIsSharedFSType: Detect direct mount points (rhbz#1634782)
- virfile: Rework virFileIsSharedFixFUSE (rhbz#1634782)
- RHEL: network: regain guest network connectivity after firewalld switch to nftables (rhbz#1638864)

* Mon Oct  8 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-10
- conf: Fix check for chardev source path (rhbz#1609723)
- tests: Reuse qemucapabilities data for qemucaps2xml (rhbz#1629862)
- tests: Add more tests to qemucaps2xml (rhbz#1629862)
- qemu: Drop QEMU_CAPS_ENABLE_KVM (rhbz#1629862)
- qemu: Avoid probing non-native binaries all the time (rhbz#1629862)
- qemu: Clarify QEMU_CAPS_KVM (rhbz#1629862)
- qemu: Don't check for /dev/kvm presence (rhbz#1629862)
- tests: Follow up on qemucaps2xmldata rename (rhbz#1629862)
- security: dac: also label listen UNIX sockets (rhbz#1634775)
- spec: Set correct TLS priority (rhbz#1632269)
- spec: Build ceph and gluster support everywhere (rhbz#1599546)
- virsh: Require explicit --domain for domxml-to-native (rhbz#1634769)
- virFileIsSharedFSType: Check for fuse.glusterfs too (rhbz#1634782)
- qemu: fix up permissions for pre-created UNIX sockets (rhbz#1634775)
- cpu_map: Add features for Icelake CPUs (rhbz#1527657, rhbz#1526625)
- cpu_map: Add Icelake CPU models (rhbz#1526625)
- qemu: Properly report VIR_DOMAIN_EVENT_RESUMED_FROM_SNAPSHOT (rhbz#1634758)
- qemu: Report more appropriate running reasons (rhbz#1634758)
- qemu: Pass running reason to RESUME event handler (rhbz#1634758)
- qemu: Map running reason to resume event detail (rhbz#1634758)
- qemu: Avoid duplicate resume events and state changes (rhbz#1634758)
- conf: qemu: add support for Hyper-V frequency MSRs (rhbz#1589702)
- conf: qemu: add support for Hyper-V reenlightenment notifications (rhbz#1589702)
- conf: qemu: add support for Hyper-V PV TLB flush (rhbz#1589702)

* Wed Sep  5 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-9
- RHEL: Fix virConnectGetMaxVcpus output (rhbz#1582222)
- storage: Add --shrink to qemu-img command when shrinking vol (rhbz#1622534)
- access: Fix nwfilter-binding ACL access API name generation (rhbz#1622540)
- conf: Add validation of input devices (rhbz#1591240)
- tests: qemu: Remove disk from graphics-vnc-tls (rhbz#1598167)
- tests: qemu: test more versions for graphics-vnc-tls (rhbz#1598167)
- qemu: vnc: switch to tls-creds-x509 (rhbz#1598167)
- qemu: mdev: Use vfio-pci 'display' property only with vfio-pci mdevs (rhbz#1624740)
- virDomainDefCompatibleDevice: Relax alias change check (rhbz#1603133)
- virDomainDetachDeviceFlags: Clarify update semantics (rhbz#1603133)
- virDomainNetDefCheckABIStability: Check for MTU change too (rhbz#1623158)
- RHEL: spec: Require python3-devel on RHEL-8 (rhbz#1518446)
- qemu: monitor: Remove qemuMonitorJSONExtractCPUArchInfo wrapper (rhbz#1598829)
- qemu: monitor: Use 'target' instead of 'arch' in reply of 'query-cpus-fast' (rhbz#1598829)

* Tue Aug 21 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-8
- tests: Add missing thread_siblings_list files (rhbz#1608479)
- util: Rewrite virHostCPUCountThreadSiblings() (rhbz#1608479)
- utils: Remove arbitrary limit on socket_id/core_id (rhbz#1608479)
- tests: Add linux-high-ids test (rhbz#1608479)
- qemu: hotplug: Fix asynchronous unplug of 'shmem' (rhbz#1618680)
- tests: rename hugepages to hugepages-default (rhbz#1615461)
- tests: extract hugepages-numa-default-dimm out of hugepages-numa (rhbz#1615461)
- tests: rename hugepages-numa into hugepages-numa-default (rhbz#1615461)
- tests: remove unnecessary XML elements from hugepages-numa-default (rhbz#1615461)
- tests: extract pages-discard out of hugepages-pages (rhbz#1615461)
- tests: rename hugepages-pages into hugepages-numa-nodeset (rhbz#1615461)
- tests: rename hugepages-pages2 into hugepages-numa-default-2M (rhbz#1615461)
- tests: extract pages-discard-hugepages out of hugepages-pages3 (rhbz#1615461)
- tests: rename hugepages-pages3 into hugepages-numa-nodeset-part (rhbz#1615461)
- tests: rename hugepages-pages4 into hugepages-numa-nodeset-nonexist (rhbz#1615461)
- tests: rename hugepages-pages5 into hugepages-default-2M (rhbz#1615461)
- tests: rename hugepages-pages6 into hugepages-default-system-size (rhbz#1615461)
- tests: rename hugepages-pages7 into pages-dimm-discard (rhbz#1615461)
- tests: rename hugepages-pages8 into hugepages-nodeset-nonexist (rhbz#1615461)
- tests: introduce hugepages-default-1G-nodeset-2M (rhbz#1615461)
- tests: introduce hugepages-nodeset (rhbz#1615461)
- conf: Move hugepage XML validation check out of qemu_command (rhbz#1615461)
- conf: Move hugepages validation out of XML parser (rhbz#1615461)
- conf: Introduce virDomainDefPostParseMemtune (rhbz#1615461)
- tests: sev: Test launch-security with specific QEMU version (rhbz#1619150)
- qemu: Fix probing of AMD SEV support (rhbz#1619150)
- qemu: caps: Format SEV platform data into qemuCaps cache (rhbz#1619150)
- conf: Parse guestfwd channel device info again (rhbz#1610072)

* Thu Aug 16 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-7
- qemu_migration: Avoid writing to freed memory (rhbz#1615854)

* Thu Aug  2 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-6
- qemu: Exempt video model 'none' from getting a PCI address on Q35
- conf: Fix a error msg typo in virDomainVideoDefValidate

* Tue Jul 31 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-5
- esx storage: Fix typo lsilogic -> lsiLogic
- networkGetDHCPLeases: Don't always report error if unable to read leases file
- nwfilter: Resolve SEGV for NWFilter Snoop processing
- qemu: Remove unused bypassSecurityDriver from qemuOpenFileAs
- qemuDomainSaveMemory: Don't enforce dynamicOwnership
- domain_nwfilter: Return early if net has no name in virDomainConfNWFilterTeardownImpl
- examples: Add clean-traffic-gateway into nwfilters

* Mon Jul 23 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-4
- qemu: hotplug: don't overwrite error message in qemuDomainAttachNetDevice
- qemu: hotplug: report error when changing rom enabled attr for net iface
- qemu: Fix setting global_period cputune element
- tests: qemucaps: Add test data for upcoming qemu 3.0.0
- qemu: capabilities: Add capability for werror/rerror for 'usb-device' frontend
- qemu: command: Move graphics iteration to its own function
- qemu: address: Handle all the video devices within a single loop
- conf: Introduce virDomainVideoDefClear helper
- conf: Introduce virDomainDefPostParseVideo helper
- qemu: validate: Enforce compile time switch type checking for videos
- tests: Add capabilities data for QEMU 2.11 x86_64
- tests: Update capabilities data for QEMU 3.0.0 x86_64
- qemu: qemuBuildHostdevCommandLine: Use a helper variable mdevsrc
- qemu: caps: Introduce a capability for egl-headless
- qemu: Introduce a new graphics display type 'headless'
- qemu: caps: Add vfio-pci.display capability
- conf: Introduce virDomainGraphicsDefHasOpenGL helper
- conf: Replace 'error' with 'cleanup' in virDomainHostdevDefParseXMLSubsys
- conf: Introduce new <hostdev> attribute 'display'
- qemu: command: Enable formatting vfio-pci.display option onto cmdline
- docs: Rephrase the mediated devices hostdev section a bit
- conf: Introduce new video type 'none'
- virt-xml-validate: Add schema for nwfilterbinding
- tools: Fix typo generating adapter_wwpn field
- src: Fix memory leak in virNWFilterBindingDispose

* Mon Jul 23 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-3
- qemu: hotplug: Do not try to add secret object for TLS if it does not exist
- qemu: monitor: Make qemuMonitorAddObject more robust against programming errors
- spec: Explicitly require matching libvirt-libs
- virDomainConfNWFilterInstantiate: initialize @xml to avoid random crash
- qemuProcessStartPRDaemonHook: Try to set NS iff domain was started with one
- qemuDomainValidateStorageSource: Relax PR validation
- virStoragePRDefFormat: Suppress path formatting for migratable XML
- qemu: Wire up PR_MANAGER_STATUS_CHANGED event
- qemu_monitor: Introduce qemuMonitorJSONGetPRManagerInfo
- qemu: Fetch pr-helper process info on reconnect
- qemu: Fix ATTRIBUTE_NONNULL for qemuMonitorAddObject
- virsh.pod: Fix a command name typo in nwfilter-binding-undefine
- docs: schema: Add missing <alias> to vsock device
- virnetdevtap: Don't crash on !ifname in virNetDevTapInterfaceStats
- tests: fix TLS handshake failure with TLS 1.3

* Mon Jul  9 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-2
- qemu: Add capability for the HTM pSeries feature
- conf: Parse and format the HTM pSeries feature
- qemu: Format the HTM pSeries feature
- qemu: hotplug: Don't access srcPriv when it's not allocated
- qemuDomainNestedJobAllowed: Allow QEMU_JOB_NONE
- src: Mention DEVICE_REMOVAL_FAILED event in virDomainDetachDeviceAlias docs
- virsh.pod: Drop --persistent for detach-device-alias
- qemu: don't use chardev FD passing with standalone args
- qemu: remove chardevStdioLogd param from vhostuser code path
- qemu: consolidate parameters of qemuBuildChrChardevStr into flags
- qemu: don't use chardev FD passing for vhostuser backend
- qemu: fix UNIX socket chardevs operating in client mode
- qemuDomainDeviceDefValidateNetwork: Check for range only if IP prefix set
- spec: Temporarily drop gluster support

* Tue Jul  3 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-1
- Rebased to libvirt-4.5.0

* Fri May 25 2018 Jiri Denemark <jdenemar@redhat.com> - 4.3.0-1
- Rebased to libvirt-4.3.0

* Wed Mar 21 2018 Daniel P. Berrangé <berrange@redhat.com> - 4.1.0-2
- Fix systemd macro argument with line continuations (rhbz#1558648)

* Mon Mar  5 2018 Daniel Berrange <berrange@redhat.com> - 4.1.0-1
- Rebase to version 4.1.0

* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 4.0.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Fri Jan 19 2018 Daniel P. Berrange <berrange@redhat.com> - 4.0.0-1
- Rebase to version 4.0.0

* Wed Dec 20 2017 Cole Robinson <crobinso@redhat.com> - 3.10.0-2
- Rebuild for xen 4.10

* Tue Dec  5 2017 Daniel P. Berrange <berrange@redhat.com> - 3.10.0-1
- Rebase to version 3.10.0

* Fri Nov  3 2017 Daniel P. Berrange <berrange@redhat.com> - 3.9.0-1
- Rebase to version 3.9.0

* Wed Oct  4 2017 Daniel P. Berrange <berrange@redhat.com> - 3.8.0-1
- Rebase to version 3.8.0

* Mon Sep  4 2017 Daniel P. Berrange <berrange@redhat.com> - 3.7.0-1
- Rebase to version 3.7.0

* Wed Aug  2 2017 Daniel P. Berrange <berrange@redhat.com> - 3.6.0-1
- Rebase to version 3.6.0

* Sun Jul 30 2017 Florian Weimer <fweimer@redhat.com> - 3.5.0-4
- Rebuild with binutils fix for ppc64le (#1475636)

* Tue Jul 25 2017 Daniel P. Berrange <berrange@redhat.com> - 3.5.0-3
- Disabled RBD on i386, arm, ppc64 (rhbz #1474743)

* Mon Jul 17 2017 Cole Robinson <crobinso@redhat.com> - 3.5.0-2
- Rebuild for xen 4.9

* Thu Jul  6 2017 Daniel P. Berrange <berrange@redhat.com> - 3.5.0-1
- Rebase to version 3.5.0

* Fri Jun  2 2017 Daniel P. Berrange <berrange@redhat.com> - 3.4.0-1
- Rebase to version 3.4.0

* Mon May  8 2017 Daniel P. Berrange <berrange@redhat.com> - 3.3.0-1
- Rebase to version 3.3.0

* Mon Apr  3 2017 Daniel P. Berrange <berrange@redhat.com> - 3.2.0-1
- Rebase to version 3.2.0

* Fri Mar  3 2017 Daniel P. Berrange <berrange@redhat.com> - 3.1.0-1
- Rebase to version 3.1.0

* Fri Feb 10 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Thu Jan 19 2017 Daniel P. Berrange <berrange@redhat.com> - 3.0.0-1
- Rebase to version 3.0.0
