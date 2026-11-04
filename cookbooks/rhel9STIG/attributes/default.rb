default['rhel9STIG']['XCCDF_result']['Manage'] = true

# R-257779 RHEL-09-211020
default['rhel9STIG']['stigrule_257779']['Manage'] = true
default['rhel9STIG']['stigrule_257779']['Title'] = "RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a command line user logon."
default['rhel9STIG']['stigrule_257779']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257779']['Setting']['_etc_issue_Path'] = '/etc/issue'
default['rhel9STIG']['stigrule_257779']['Setting']['_etc_issue_Content'] = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
'

# R-257783 RHEL-09-211040
default['rhel9STIG']['stigrule_257783']['Manage'] = true
default['rhel9STIG']['stigrule_257783']['Title'] = "RHEL 9 systemd-journald service must be enabled."
default['rhel9STIG']['stigrule_257783']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257783']['Setting']['systemd_journald_enable_ServiceName'] = 'systemd-journald'
default['rhel9STIG']['stigrule_257783']['Setting']['systemd_journald_enable_Action'] = :enable

default['rhel9STIG']['stigrule_257783']['Setting']['systemd_journald_start_ServiceName'] = 'systemd-journald'
default['rhel9STIG']['stigrule_257783']['Setting']['systemd_journald_start_Action'] = :start

# R-257784 RHEL-09-211045
default['rhel9STIG']['stigrule_257784']['Manage'] = true
default['rhel9STIG']['stigrule_257784']['Title'] = "The systemd Ctrl-Alt-Delete burst key sequence in RHEL 9 must be disabled."
default['rhel9STIG']['stigrule_257784']['Severity'] = 'high'
default['rhel9STIG']['stigrule_257784']['Setting']['_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Path'] = '/etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction.conf'
default['rhel9STIG']['stigrule_257784']['Setting']['_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Section'] = 'Manager'
default['rhel9STIG']['stigrule_257784']['Setting']['_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Option'] = 'CtrlAltDelBurstAction'
default['rhel9STIG']['stigrule_257784']['Setting']['_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Value'] = "none"
default['rhel9STIG']['stigrule_257784']['Setting']['_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Only_if'] = "rpm -q dconf"

# R-257785 RHEL-09-211050
default['rhel9STIG']['stigrule_257785']['Manage'] = true
default['rhel9STIG']['stigrule_257785']['Title'] = "The x86 Ctrl-Alt-Delete key sequence must be disabled on RHEL 9."
default['rhel9STIG']['stigrule_257785']['Severity'] = 'high'
default['rhel9STIG']['stigrule_257785']['Setting']['ctrl_alt_del_target_disable_UnitName'] = 'ctrl-alt-del.target'
default['rhel9STIG']['stigrule_257785']['Setting']['ctrl_alt_del_target_disable_Action'] = :disable

default['rhel9STIG']['stigrule_257785']['Setting']['ctrl_alt_del_target_mask_UnitName'] = 'ctrl-alt-del.target'
default['rhel9STIG']['stigrule_257785']['Setting']['ctrl_alt_del_target_mask_Action'] = [:mask, :stop]

# R-257786 RHEL-09-211055
default['rhel9STIG']['stigrule_257786']['Manage'] = true
default['rhel9STIG']['stigrule_257786']['Title'] = "RHEL 9 debug-shell systemd service must be disabled."
default['rhel9STIG']['stigrule_257786']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257786']['Setting']['debug_shell_service_disable_UnitName'] = 'debug-shell.service'
default['rhel9STIG']['stigrule_257786']['Setting']['debug_shell_service_disable_Action'] = :disable

default['rhel9STIG']['stigrule_257786']['Setting']['debug_shell_service_mask_UnitName'] = 'debug-shell.service'
default['rhel9STIG']['stigrule_257786']['Setting']['debug_shell_service_mask_Action'] = [:mask, :stop]

# R-257790 RHEL-09-212025
default['rhel9STIG']['stigrule_257790']['Manage'] = true
default['rhel9STIG']['stigrule_257790']['Title'] = "RHEL 9 /boot/grub2/grub.cfg file must be group-owned by root."
default['rhel9STIG']['stigrule_257790']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257790']['Setting']['_boot_grub2_grub_cfg_group_owner_Path'] = '/boot/grub2/grub.cfg'
default['rhel9STIG']['stigrule_257790']['Setting']['_boot_grub2_grub_cfg_group_owner_Group'] = 'root'

# R-257791 RHEL-09-212030
default['rhel9STIG']['stigrule_257791']['Manage'] = true
default['rhel9STIG']['stigrule_257791']['Title'] = "RHEL 9 /boot/grub2/grub.cfg file must be owned by root."
default['rhel9STIG']['stigrule_257791']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257791']['Setting']['_boot_grub2_grub_cfg_owner_Path'] = '/boot/grub2/grub.cfg'
default['rhel9STIG']['stigrule_257791']['Setting']['_boot_grub2_grub_cfg_owner_Owner'] = 'root'

# R-257797 RHEL-09-213010
default['rhel9STIG']['stigrule_257797']['Manage'] = true
default['rhel9STIG']['stigrule_257797']['Title'] = "RHEL 9 must restrict access to the kernel message buffer."
default['rhel9STIG']['stigrule_257797']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257797']['Setting']['kernel_dmesg_restrict_Key'] = 'kernel.dmesg_restrict'
default['rhel9STIG']['stigrule_257797']['Setting']['kernel_dmesg_restrict_Value'] = 1

# R-257798 RHEL-09-213015
default['rhel9STIG']['stigrule_257798']['Manage'] = true
default['rhel9STIG']['stigrule_257798']['Title'] = "RHEL 9 must prevent kernel profiling by nonprivileged users."
default['rhel9STIG']['stigrule_257798']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257798']['Setting']['kernel_perf_event_paranoid_Key'] = 'kernel.perf_event_paranoid'
default['rhel9STIG']['stigrule_257798']['Setting']['kernel_perf_event_paranoid_Value'] = 2

# R-257799 RHEL-09-213020
default['rhel9STIG']['stigrule_257799']['Manage'] = true
default['rhel9STIG']['stigrule_257799']['Title'] = "RHEL 9 must prevent the loading of a new kernel for later execution."
default['rhel9STIG']['stigrule_257799']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257799']['Setting']['kernel_kexec_load_disabled_Key'] = 'kernel.kexec_load_disabled'
default['rhel9STIG']['stigrule_257799']['Setting']['kernel_kexec_load_disabled_Value'] = 1

# R-257800 RHEL-09-213025
default['rhel9STIG']['stigrule_257800']['Manage'] = true
default['rhel9STIG']['stigrule_257800']['Title'] = "RHEL 9 must restrict exposed kernel pointer addresses access."
default['rhel9STIG']['stigrule_257800']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257800']['Setting']['kernel_kptr_restrict_Key'] = 'kernel.kptr_restrict'
default['rhel9STIG']['stigrule_257800']['Setting']['kernel_kptr_restrict_Value'] = 1

# R-257801 RHEL-09-213030
default['rhel9STIG']['stigrule_257801']['Manage'] = true
default['rhel9STIG']['stigrule_257801']['Title'] = "RHEL 9 must enable kernel parameters to enforce discretionary access control (DAC) on hardlinks."
default['rhel9STIG']['stigrule_257801']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257801']['Setting']['fs_protected_hardlinks_Key'] = 'fs.protected_hardlinks'
default['rhel9STIG']['stigrule_257801']['Setting']['fs_protected_hardlinks_Value'] = 1

# R-257802 RHEL-09-213035
default['rhel9STIG']['stigrule_257802']['Manage'] = true
default['rhel9STIG']['stigrule_257802']['Title'] = "RHEL 9 must enable kernel parameters to enforce discretionary access (DAC) control on symlinks."
default['rhel9STIG']['stigrule_257802']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257802']['Setting']['fs_protected_symlinks_Key'] = 'fs.protected_symlinks'
default['rhel9STIG']['stigrule_257802']['Setting']['fs_protected_symlinks_Value'] = 1

# R-257803 RHEL-09-213040
default['rhel9STIG']['stigrule_257803']['Manage'] = true
default['rhel9STIG']['stigrule_257803']['Title'] = "RHEL 9 must disable the kernel.core_pattern."
default['rhel9STIG']['stigrule_257803']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257803']['Setting']['kernel_core_pattern_Key'] = 'kernel.core_pattern'
default['rhel9STIG']['stigrule_257803']['Setting']['kernel_core_pattern_Value'] = '|/bin/false'

# R-257804 RHEL-09-213045
default['rhel9STIG']['stigrule_257804']['Manage'] = true
default['rhel9STIG']['stigrule_257804']['Title'] = "RHEL 9 must be configured to disable the Asynchronous Transfer Mode kernel module."
default['rhel9STIG']['stigrule_257804']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257804']['Setting']['_etc_modprobe_d_atm_conf_install_atm__bin_false_Path'] = '/etc/modprobe.d/atm.conf'
default['rhel9STIG']['stigrule_257804']['Setting']['_etc_modprobe_d_atm_conf_install_atm__bin_false_Line'] = 'install atm /bin/false'

default['rhel9STIG']['stigrule_257804']['Setting']['_etc_modprobe_d_atm_conf_blacklist_atm_Path'] = '/etc/modprobe.d/atm.conf'
default['rhel9STIG']['stigrule_257804']['Setting']['_etc_modprobe_d_atm_conf_blacklist_atm_Line'] = 'blacklist atm'

# R-257805 RHEL-09-213050
default['rhel9STIG']['stigrule_257805']['Manage'] = true
default['rhel9STIG']['stigrule_257805']['Title'] = "RHEL 9 must be configured to disable the Controller Area Network kernel module."
default['rhel9STIG']['stigrule_257805']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257805']['Setting']['_etc_modprobe_d_can_conf_install_can__bin_false_Path'] = '/etc/modprobe.d/can.conf'
default['rhel9STIG']['stigrule_257805']['Setting']['_etc_modprobe_d_can_conf_install_can__bin_false_Line'] = 'install can /bin/false'

default['rhel9STIG']['stigrule_257805']['Setting']['_etc_modprobe_d_can_conf_blacklist_can_Path'] = '/etc/modprobe.d/can.conf'
default['rhel9STIG']['stigrule_257805']['Setting']['_etc_modprobe_d_can_conf_blacklist_can_Line'] = 'blacklist can'

# R-257806 RHEL-09-213055
default['rhel9STIG']['stigrule_257806']['Manage'] = true
default['rhel9STIG']['stigrule_257806']['Title'] = "RHEL 9 must be configured to disable the FireWire kernel module."
default['rhel9STIG']['stigrule_257806']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257806']['Setting']['_etc_modprobe_d_firewire_core_conf_install_firewire_core__bin_false_Path'] = '/etc/modprobe.d/firewire-core.conf'
default['rhel9STIG']['stigrule_257806']['Setting']['_etc_modprobe_d_firewire_core_conf_install_firewire_core__bin_false_Line'] = 'install firewire-core /bin/false'

default['rhel9STIG']['stigrule_257806']['Setting']['_etc_modprobe_d_firewire_core_conf_blacklist_firewire_core_Path'] = '/etc/modprobe.d/firewire-core.conf'
default['rhel9STIG']['stigrule_257806']['Setting']['_etc_modprobe_d_firewire_core_conf_blacklist_firewire_core_Line'] = 'blacklist firewire-core'

# R-257807 RHEL-09-213060
default['rhel9STIG']['stigrule_257807']['Manage'] = true
default['rhel9STIG']['stigrule_257807']['Title'] = "RHEL 9 must disable the Stream Control Transmission Protocol (SCTP) kernel module."
default['rhel9STIG']['stigrule_257807']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257807']['Setting']['_etc_modprobe_d_sctp_conf_install_sctp__bin_false_Path'] = '/etc/modprobe.d/sctp.conf'
default['rhel9STIG']['stigrule_257807']['Setting']['_etc_modprobe_d_sctp_conf_install_sctp__bin_false_Line'] = 'install sctp /bin/false'

default['rhel9STIG']['stigrule_257807']['Setting']['_etc_modprobe_d_sctp_conf_blacklist_sctp_Path'] = '/etc/modprobe.d/sctp.conf'
default['rhel9STIG']['stigrule_257807']['Setting']['_etc_modprobe_d_sctp_conf_blacklist_sctp_Line'] = 'blacklist sctp'

# R-257808 RHEL-09-213065
default['rhel9STIG']['stigrule_257808']['Manage'] = true
default['rhel9STIG']['stigrule_257808']['Title'] = "RHEL 9 must disable the Transparent Inter Process Communication (TIPC) kernel module."
default['rhel9STIG']['stigrule_257808']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257808']['Setting']['_etc_modprobe_d_tipc_conf_install_tipc__bin_false_Path'] = '/etc/modprobe.d/tipc.conf'
default['rhel9STIG']['stigrule_257808']['Setting']['_etc_modprobe_d_tipc_conf_install_tipc__bin_false_Line'] = 'install tipc /bin/false'

default['rhel9STIG']['stigrule_257808']['Setting']['_etc_modprobe_d_tipc_conf_blacklist_tipc_Path'] = '/etc/modprobe.d/tipc.conf'
default['rhel9STIG']['stigrule_257808']['Setting']['_etc_modprobe_d_tipc_conf_blacklist_tipc_Line'] = 'blacklist tipc'

# R-257809 RHEL-09-213070
default['rhel9STIG']['stigrule_257809']['Manage'] = true
default['rhel9STIG']['stigrule_257809']['Title'] = "RHEL 9 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution."
default['rhel9STIG']['stigrule_257809']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257809']['Setting']['kernel_randomize_va_space_Key'] = 'kernel.randomize_va_space'
default['rhel9STIG']['stigrule_257809']['Setting']['kernel_randomize_va_space_Value'] = 2

# R-257810 RHEL-09-213075
default['rhel9STIG']['stigrule_257810']['Manage'] = true
default['rhel9STIG']['stigrule_257810']['Title'] = "RHEL 9 must disable access to network bpf system call from nonprivileged processes."
default['rhel9STIG']['stigrule_257810']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257810']['Setting']['kernel_unprivileged_bpf_disabled_Key'] = 'kernel.unprivileged_bpf_disabled'
default['rhel9STIG']['stigrule_257810']['Setting']['kernel_unprivileged_bpf_disabled_Value'] = 1

# R-257811 RHEL-09-213080
default['rhel9STIG']['stigrule_257811']['Manage'] = true
default['rhel9STIG']['stigrule_257811']['Title'] = "RHEL 9 must restrict usage of ptrace to descendant processes."
default['rhel9STIG']['stigrule_257811']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257811']['Setting']['kernel_yama_ptrace_scope_Key'] = 'kernel.yama.ptrace_scope'
default['rhel9STIG']['stigrule_257811']['Setting']['kernel_yama_ptrace_scope_Value'] = 1

# R-257812 RHEL-09-213085
default['rhel9STIG']['stigrule_257812']['Manage'] = true
default['rhel9STIG']['stigrule_257812']['Title'] = "RHEL 9 must disable core dump backtraces."
default['rhel9STIG']['stigrule_257812']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257812']['Setting']['_etc_systemd_coredump_conf_Path'] = '/etc/systemd/coredump.conf'
default['rhel9STIG']['stigrule_257812']['Setting']['_etc_systemd_coredump_conf_Regexp'] = '^\s*ProcessSizeMax\s*='
default['rhel9STIG']['stigrule_257812']['Setting']['_etc_systemd_coredump_conf_Line'] = 'ProcessSizeMax=0'

# R-257813 RHEL-09-213090
default['rhel9STIG']['stigrule_257813']['Manage'] = true
default['rhel9STIG']['stigrule_257813']['Title'] = "RHEL 9 must disable storing core dumps."
default['rhel9STIG']['stigrule_257813']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257813']['Setting']['_etc_systemd_coredump_conf_Path'] = '/etc/systemd/coredump.conf'
default['rhel9STIG']['stigrule_257813']['Setting']['_etc_systemd_coredump_conf_Regexp'] = '^\s*Storage\s*='
default['rhel9STIG']['stigrule_257813']['Setting']['_etc_systemd_coredump_conf_Line'] = 'Storage=none'

# R-257814 RHEL-09-213095
default['rhel9STIG']['stigrule_257814']['Manage'] = true
default['rhel9STIG']['stigrule_257814']['Title'] = "RHEL 9 must disable core dumps for all users."
default['rhel9STIG']['stigrule_257814']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257814']['Setting']['_etc_security_limits_conf_Path'] = '/etc/security/limits.conf'
default['rhel9STIG']['stigrule_257814']['Setting']['_etc_security_limits_conf_Regexp'] = '^\s*\*\s+hard\s+core\b'
default['rhel9STIG']['stigrule_257814']['Setting']['_etc_security_limits_conf_Line'] = '* hard core 0'

# R-257815 RHEL-09-213100
default['rhel9STIG']['stigrule_257815']['Manage'] = true
default['rhel9STIG']['stigrule_257815']['Title'] = "RHEL 9 must disable acquiring, saving, and processing core dumps."
default['rhel9STIG']['stigrule_257815']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257815']['Setting']['systemd_coredump_socket_disable_UnitName'] = 'systemd-coredump.socket'
default['rhel9STIG']['stigrule_257815']['Setting']['systemd_coredump_socket_disable_Action'] = :disable

default['rhel9STIG']['stigrule_257815']['Setting']['systemd_coredump_socket_mask_UnitName'] = 'systemd-coredump.socket'
default['rhel9STIG']['stigrule_257815']['Setting']['systemd_coredump_socket_mask_Action'] = [:mask, :stop]

# R-257816 RHEL-09-213105
default['rhel9STIG']['stigrule_257816']['Manage'] = true
default['rhel9STIG']['stigrule_257816']['Title'] = "RHEL 9 must disable the use of user namespaces."
default['rhel9STIG']['stigrule_257816']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257816']['Setting']['user_max_user_namespaces_Key'] = 'user.max_user_namespaces'
default['rhel9STIG']['stigrule_257816']['Setting']['user_max_user_namespaces_Value'] = 0

# R-257818 RHEL-09-213115
default['rhel9STIG']['stigrule_257818']['Manage'] = true
default['rhel9STIG']['stigrule_257818']['Title'] = "The kdump service on RHEL 9 must be disabled."
default['rhel9STIG']['stigrule_257818']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257818']['Setting']['kdump_disable_UnitName'] = 'kdump'
default['rhel9STIG']['stigrule_257818']['Setting']['kdump_disable_Action'] = :disable

default['rhel9STIG']['stigrule_257818']['Setting']['kdump_mask_UnitName'] = 'kdump'
default['rhel9STIG']['stigrule_257818']['Setting']['kdump_mask_Action'] = [:mask, :stop]

# R-257820 RHEL-09-214015
default['rhel9STIG']['stigrule_257820']['Manage'] = true
default['rhel9STIG']['stigrule_257820']['Title'] = "RHEL 9 must check the GPG signature of software packages originating from external software repositories before installation."
default['rhel9STIG']['stigrule_257820']['Severity'] = 'high'
default['rhel9STIG']['stigrule_257820']['Setting']['_etc_dnf_dnf_conf_Path'] = '/etc/dnf/dnf.conf'
default['rhel9STIG']['stigrule_257820']['Setting']['_etc_dnf_dnf_conf_Section'] = 'main'
default['rhel9STIG']['stigrule_257820']['Setting']['_etc_dnf_dnf_conf_Option'] = 'gpgcheck'
default['rhel9STIG']['stigrule_257820']['Setting']['_etc_dnf_dnf_conf_Value'] = "1"

# R-257821 RHEL-09-214020
default['rhel9STIG']['stigrule_257821']['Manage'] = true
default['rhel9STIG']['stigrule_257821']['Title'] = "RHEL 9 must check the GPG signature of locally installed software packages before installation."
default['rhel9STIG']['stigrule_257821']['Severity'] = 'high'
default['rhel9STIG']['stigrule_257821']['Setting']['_etc_dnf_dnf_conf_Path'] = '/etc/dnf/dnf.conf'
default['rhel9STIG']['stigrule_257821']['Setting']['_etc_dnf_dnf_conf_Section'] = 'main'
default['rhel9STIG']['stigrule_257821']['Setting']['_etc_dnf_dnf_conf_Option'] = 'localpkg_gpgcheck'
default['rhel9STIG']['stigrule_257821']['Setting']['_etc_dnf_dnf_conf_Value'] = "1"

# R-257824 RHEL-09-214035
default['rhel9STIG']['stigrule_257824']['Manage'] = true
default['rhel9STIG']['stigrule_257824']['Title'] = "RHEL 9 must remove all software components after updated versions have been installed."
default['rhel9STIG']['stigrule_257824']['Severity'] = 'low'
default['rhel9STIG']['stigrule_257824']['Setting']['_etc_dnf_dnf_conf_Path'] = '/etc/dnf/dnf.conf'
default['rhel9STIG']['stigrule_257824']['Setting']['_etc_dnf_dnf_conf_Section'] = 'main'
default['rhel9STIG']['stigrule_257824']['Setting']['_etc_dnf_dnf_conf_Option'] = 'clean_requirements_on_remove'
default['rhel9STIG']['stigrule_257824']['Setting']['_etc_dnf_dnf_conf_Value'] = "1"

# R-257825 RHEL-09-215010
default['rhel9STIG']['stigrule_257825']['Manage'] = true
default['rhel9STIG']['stigrule_257825']['Title'] = "RHEL 9 subscription-manager package must be installed."
default['rhel9STIG']['stigrule_257825']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257825']['Setting']['subscription_manager_PackageName'] = 'subscription-manager'
default['rhel9STIG']['stigrule_257825']['Setting']['subscription_manager_Action'] = :install

# R-257827 RHEL-09-215020
default['rhel9STIG']['stigrule_257827']['Manage'] = true
default['rhel9STIG']['stigrule_257827']['Title'] = "RHEL 9 must not have the sendmail package installed."
default['rhel9STIG']['stigrule_257827']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257827']['Setting']['sendmail_PackageName'] = 'sendmail'
default['rhel9STIG']['stigrule_257827']['Setting']['sendmail_Action'] = :remove

# R-257828 RHEL-09-215025
default['rhel9STIG']['stigrule_257828']['Manage'] = true
default['rhel9STIG']['stigrule_257828']['Title'] = "RHEL 9 must not have the nfs-utils package installed."
default['rhel9STIG']['stigrule_257828']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257828']['Setting']['nfs_utils_PackageName'] = 'nfs-utils'
default['rhel9STIG']['stigrule_257828']['Setting']['nfs_utils_Action'] = :remove

# R-257830 RHEL-09-215035
default['rhel9STIG']['stigrule_257830']['Manage'] = true
default['rhel9STIG']['stigrule_257830']['Title'] = "RHEL 9 must not install packages from the Extra Packages for Enterprise Linux (EPEL) repository."
default['rhel9STIG']['stigrule_257830']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257830']['Setting']['epel_release_PackageName'] = 'epel-release'
default['rhel9STIG']['stigrule_257830']['Setting']['epel_release_Action'] = :remove

# R-257831 RHEL-09-215040
default['rhel9STIG']['stigrule_257831']['Manage'] = true
default['rhel9STIG']['stigrule_257831']['Title'] = "RHEL 9 must not have the telnet-server package installed."
default['rhel9STIG']['stigrule_257831']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257831']['Setting']['telnet_server_PackageName'] = 'telnet-server'
default['rhel9STIG']['stigrule_257831']['Setting']['telnet_server_Action'] = :remove

# R-257832 RHEL-09-215045
default['rhel9STIG']['stigrule_257832']['Manage'] = true
default['rhel9STIG']['stigrule_257832']['Title'] = "RHEL 9 must not have the gssproxy package installed."
default['rhel9STIG']['stigrule_257832']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257832']['Setting']['gssproxy_PackageName'] = 'gssproxy'
default['rhel9STIG']['stigrule_257832']['Setting']['gssproxy_Action'] = :remove

# R-257833 RHEL-09-215050
default['rhel9STIG']['stigrule_257833']['Manage'] = true
default['rhel9STIG']['stigrule_257833']['Title'] = "RHEL 9 must not have the iprutils package installed."
default['rhel9STIG']['stigrule_257833']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257833']['Setting']['iprutils_PackageName'] = 'iprutils'
default['rhel9STIG']['stigrule_257833']['Setting']['iprutils_Action'] = :remove

# R-257834 RHEL-09-215055
default['rhel9STIG']['stigrule_257834']['Manage'] = true
default['rhel9STIG']['stigrule_257834']['Title'] = "RHEL 9 must not have the tuned package installed."
default['rhel9STIG']['stigrule_257834']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257834']['Setting']['tuned_PackageName'] = 'tuned'
default['rhel9STIG']['stigrule_257834']['Setting']['tuned_Action'] = :remove

# R-257838 RHEL-09-215075
default['rhel9STIG']['stigrule_257838']['Manage'] = true
default['rhel9STIG']['stigrule_257838']['Title'] = "RHEL 9 must have the openssl-pkcs11 package installed."
default['rhel9STIG']['stigrule_257838']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257838']['Setting']['openssl_pkcs11_PackageName'] = 'openssl-pkcs11'
default['rhel9STIG']['stigrule_257838']['Setting']['openssl_pkcs11_Action'] = :install

# R-257839 RHEL-09-215080
default['rhel9STIG']['stigrule_257839']['Manage'] = true
default['rhel9STIG']['stigrule_257839']['Title'] = "RHEL 9 must have the gnutls-utils package installed."
default['rhel9STIG']['stigrule_257839']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257839']['Setting']['gnutls_utils_PackageName'] = 'gnutls-utils'
default['rhel9STIG']['stigrule_257839']['Setting']['gnutls_utils_Action'] = :install

# R-257840 RHEL-09-215085
default['rhel9STIG']['stigrule_257840']['Manage'] = true
default['rhel9STIG']['stigrule_257840']['Title'] = "RHEL 9 must have the nss-tools package installed."
default['rhel9STIG']['stigrule_257840']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257840']['Setting']['nss_tools_PackageName'] = 'nss-tools'
default['rhel9STIG']['stigrule_257840']['Setting']['nss_tools_Action'] = :install

# R-257841 RHEL-09-215090
default['rhel9STIG']['stigrule_257841']['Manage'] = true
default['rhel9STIG']['stigrule_257841']['Title'] = "RHEL 9 must have the rng-tools package installed."
default['rhel9STIG']['stigrule_257841']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257841']['Setting']['rng_tools_PackageName'] = 'rng-tools'
default['rhel9STIG']['stigrule_257841']['Setting']['rng_tools_Action'] = :install

# R-257842 RHEL-09-215095
default['rhel9STIG']['stigrule_257842']['Manage'] = true
default['rhel9STIG']['stigrule_257842']['Title'] = "RHEL 9 must have the s-nail package installed."
default['rhel9STIG']['stigrule_257842']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257842']['Setting']['s_nail_PackageName'] = 's-nail'
default['rhel9STIG']['stigrule_257842']['Setting']['s_nail_Action'] = :install

# R-257849 RHEL-09-231040
default['rhel9STIG']['stigrule_257849']['Manage'] = true
default['rhel9STIG']['stigrule_257849']['Title'] = "RHEL 9 file system automount function must be disabled unless required."
default['rhel9STIG']['stigrule_257849']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257849']['Setting']['autofs_service_disable_UnitName'] = 'autofs.service'
default['rhel9STIG']['stigrule_257849']['Setting']['autofs_service_disable_Action'] = :disable

default['rhel9STIG']['stigrule_257849']['Setting']['autofs_service_mask_UnitName'] = 'autofs.service'
default['rhel9STIG']['stigrule_257849']['Setting']['autofs_service_mask_Action'] = [:mask, :stop]

# R-257880 RHEL-09-231195
default['rhel9STIG']['stigrule_257880']['Manage'] = true
default['rhel9STIG']['stigrule_257880']['Title'] = "RHEL 9 must disable mounting of cramfs."
default['rhel9STIG']['stigrule_257880']['Severity'] = 'low'
default['rhel9STIG']['stigrule_257880']['Setting']['_etc_modprobe_d_cramfs_conf_install_cramfs__bin_false_Path'] = '/etc/modprobe.d/cramfs.conf'
default['rhel9STIG']['stigrule_257880']['Setting']['_etc_modprobe_d_cramfs_conf_install_cramfs__bin_false_Line'] = 'install cramfs /bin/false'

default['rhel9STIG']['stigrule_257880']['Setting']['_etc_modprobe_d_cramfs_conf_blacklist_cramfs_Path'] = '/etc/modprobe.d/cramfs.conf'
default['rhel9STIG']['stigrule_257880']['Setting']['_etc_modprobe_d_cramfs_conf_blacklist_cramfs_Line'] = 'blacklist cramfs'

# R-257885 RHEL-09-232025
default['rhel9STIG']['stigrule_257885']['Manage'] = true
default['rhel9STIG']['stigrule_257885']['Title'] = "RHEL 9 /var/log directory must have mode 0755 or less permissive."
default['rhel9STIG']['stigrule_257885']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257885']['Setting']['_var_log_mode_Path'] = '/var/log'
default['rhel9STIG']['stigrule_257885']['Setting']['_var_log_mode_Mode'] = '0755'

# R-257886 RHEL-09-232030
default['rhel9STIG']['stigrule_257886']['Manage'] = true
default['rhel9STIG']['stigrule_257886']['Title'] = "RHEL 9 /var/log/messages file must have mode 0640 or less permissive."
default['rhel9STIG']['stigrule_257886']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257886']['Setting']['_var_log_messages_mode_Path'] = '/var/log/messages'
default['rhel9STIG']['stigrule_257886']['Setting']['_var_log_messages_mode_Mode'] = '0640'

# R-257891 RHEL-09-232055
default['rhel9STIG']['stigrule_257891']['Manage'] = true
default['rhel9STIG']['stigrule_257891']['Title'] = "RHEL 9 /etc/group file must have mode 0644 or less permissive to prevent unauthorized access."
default['rhel9STIG']['stigrule_257891']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257891']['Setting']['_etc_group_mode_Path'] = '/etc/group'
default['rhel9STIG']['stigrule_257891']['Setting']['_etc_group_mode_Mode'] = '0644'

# R-257892 RHEL-09-232060
default['rhel9STIG']['stigrule_257892']['Manage'] = true
default['rhel9STIG']['stigrule_257892']['Title'] = "RHEL 9 /etc/group- file must have mode 0644 or less permissive to prevent unauthorized access."
default['rhel9STIG']['stigrule_257892']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257892']['Setting']['_etc_group__mode_Path'] = '/etc/group-'
default['rhel9STIG']['stigrule_257892']['Setting']['_etc_group__mode_Mode'] = '0644'

# R-257893 RHEL-09-232065
default['rhel9STIG']['stigrule_257893']['Manage'] = true
default['rhel9STIG']['stigrule_257893']['Title'] = "RHEL 9 /etc/gshadow file must have mode 0000 or less permissive to prevent unauthorized access."
default['rhel9STIG']['stigrule_257893']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257893']['Setting']['_etc_gshadow_mode_Path'] = '/etc/gshadow'
default['rhel9STIG']['stigrule_257893']['Setting']['_etc_gshadow_mode_Mode'] = '0000'

# R-257894 RHEL-09-232070
default['rhel9STIG']['stigrule_257894']['Manage'] = true
default['rhel9STIG']['stigrule_257894']['Title'] = "RHEL 9 /etc/gshadow- file must have mode 0000 or less permissive to prevent unauthorized access."
default['rhel9STIG']['stigrule_257894']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257894']['Setting']['_etc_gshadow__mode_Path'] = '/etc/gshadow-'
default['rhel9STIG']['stigrule_257894']['Setting']['_etc_gshadow__mode_Mode'] = '0000'

# R-257895 RHEL-09-232075
default['rhel9STIG']['stigrule_257895']['Manage'] = true
default['rhel9STIG']['stigrule_257895']['Title'] = "RHEL 9 /etc/passwd file must have mode 0644 or less permissive to prevent unauthorized access."
default['rhel9STIG']['stigrule_257895']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257895']['Setting']['_etc_passwd_mode_Path'] = '/etc/passwd'
default['rhel9STIG']['stigrule_257895']['Setting']['_etc_passwd_mode_Mode'] = '0644'

# R-257896 RHEL-09-232080
default['rhel9STIG']['stigrule_257896']['Manage'] = true
default['rhel9STIG']['stigrule_257896']['Title'] = "RHEL 9 /etc/passwd- file must have mode 0644 or less permissive to prevent unauthorized access."
default['rhel9STIG']['stigrule_257896']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257896']['Setting']['_etc_passwd__mode_Path'] = '/etc/passwd-'
default['rhel9STIG']['stigrule_257896']['Setting']['_etc_passwd__mode_Mode'] = '0644'

# R-257897 RHEL-09-232085
default['rhel9STIG']['stigrule_257897']['Manage'] = true
default['rhel9STIG']['stigrule_257897']['Title'] = "RHEL 9 /etc/shadow- file must have mode 0000 or less permissive to prevent unauthorized access."
default['rhel9STIG']['stigrule_257897']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257897']['Setting']['_etc_shadow__mode_Path'] = '/etc/shadow-'
default['rhel9STIG']['stigrule_257897']['Setting']['_etc_shadow__mode_Mode'] = '0000'

# R-257898 RHEL-09-232090
default['rhel9STIG']['stigrule_257898']['Manage'] = true
default['rhel9STIG']['stigrule_257898']['Title'] = "RHEL 9 /etc/group file must be owned by root."
default['rhel9STIG']['stigrule_257898']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257898']['Setting']['_etc_group_owner_Path'] = '/etc/group'
default['rhel9STIG']['stigrule_257898']['Setting']['_etc_group_owner_Owner'] = 'root'

# R-257899 RHEL-09-232095
default['rhel9STIG']['stigrule_257899']['Manage'] = true
default['rhel9STIG']['stigrule_257899']['Title'] = "RHEL 9 /etc/group file must be group-owned by root."
default['rhel9STIG']['stigrule_257899']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257899']['Setting']['_etc_group_group_owner_Path'] = '/etc/group'
default['rhel9STIG']['stigrule_257899']['Setting']['_etc_group_group_owner_Group'] = 'root'

# R-257900 RHEL-09-232100
default['rhel9STIG']['stigrule_257900']['Manage'] = true
default['rhel9STIG']['stigrule_257900']['Title'] = "RHEL 9 /etc/group- file must be owned by root."
default['rhel9STIG']['stigrule_257900']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257900']['Setting']['_etc_group__owner_Path'] = '/etc/group-'
default['rhel9STIG']['stigrule_257900']['Setting']['_etc_group__owner_Owner'] = 'root'

# R-257901 RHEL-09-232105
default['rhel9STIG']['stigrule_257901']['Manage'] = true
default['rhel9STIG']['stigrule_257901']['Title'] = "RHEL 9 /etc/group- file must be group-owned by root."
default['rhel9STIG']['stigrule_257901']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257901']['Setting']['_etc_group__group_owner_Path'] = '/etc/group-'
default['rhel9STIG']['stigrule_257901']['Setting']['_etc_group__group_owner_Group'] = 'root'

# R-257902 RHEL-09-232110
default['rhel9STIG']['stigrule_257902']['Manage'] = true
default['rhel9STIG']['stigrule_257902']['Title'] = "RHEL 9 /etc/gshadow file must be owned by root."
default['rhel9STIG']['stigrule_257902']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257902']['Setting']['_etc_gshadow_owner_Path'] = '/etc/gshadow'
default['rhel9STIG']['stigrule_257902']['Setting']['_etc_gshadow_owner_Owner'] = 'root'

# R-257903 RHEL-09-232115
default['rhel9STIG']['stigrule_257903']['Manage'] = true
default['rhel9STIG']['stigrule_257903']['Title'] = "RHEL 9 /etc/gshadow file must be group-owned by root."
default['rhel9STIG']['stigrule_257903']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257903']['Setting']['_etc_gshadow_group_owner_Path'] = '/etc/gshadow'
default['rhel9STIG']['stigrule_257903']['Setting']['_etc_gshadow_group_owner_Group'] = 'root'

# R-257904 RHEL-09-232120
default['rhel9STIG']['stigrule_257904']['Manage'] = true
default['rhel9STIG']['stigrule_257904']['Title'] = "RHEL 9 /etc/gshadow- file must be owned by root."
default['rhel9STIG']['stigrule_257904']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257904']['Setting']['_etc_gshadow__owner_Path'] = '/etc/gshadow-'
default['rhel9STIG']['stigrule_257904']['Setting']['_etc_gshadow__owner_Owner'] = 'root'

# R-257905 RHEL-09-232125
default['rhel9STIG']['stigrule_257905']['Manage'] = true
default['rhel9STIG']['stigrule_257905']['Title'] = "RHEL 9 /etc/gshadow- file must be group-owned by root."
default['rhel9STIG']['stigrule_257905']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257905']['Setting']['_etc_gshadow__group_owner_Path'] = '/etc/gshadow-'
default['rhel9STIG']['stigrule_257905']['Setting']['_etc_gshadow__group_owner_Group'] = 'root'

# R-257906 RHEL-09-232130
default['rhel9STIG']['stigrule_257906']['Manage'] = true
default['rhel9STIG']['stigrule_257906']['Title'] = "RHEL 9 /etc/passwd file must be owned by root."
default['rhel9STIG']['stigrule_257906']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257906']['Setting']['_etc_passwd_owner_Path'] = '/etc/passwd'
default['rhel9STIG']['stigrule_257906']['Setting']['_etc_passwd_owner_Owner'] = 'root'

# R-257907 RHEL-09-232135
default['rhel9STIG']['stigrule_257907']['Manage'] = true
default['rhel9STIG']['stigrule_257907']['Title'] = "RHEL 9 /etc/passwd file must be group-owned by root."
default['rhel9STIG']['stigrule_257907']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257907']['Setting']['_etc_passwd_group_owner_Path'] = '/etc/passwd'
default['rhel9STIG']['stigrule_257907']['Setting']['_etc_passwd_group_owner_Group'] = 'root'

# R-257908 RHEL-09-232140
default['rhel9STIG']['stigrule_257908']['Manage'] = true
default['rhel9STIG']['stigrule_257908']['Title'] = "RHEL 9 /etc/passwd- file must be owned by root."
default['rhel9STIG']['stigrule_257908']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257908']['Setting']['_etc_passwd__owner_Path'] = '/etc/passwd-'
default['rhel9STIG']['stigrule_257908']['Setting']['_etc_passwd__owner_Owner'] = 'root'

# R-257909 RHEL-09-232145
default['rhel9STIG']['stigrule_257909']['Manage'] = true
default['rhel9STIG']['stigrule_257909']['Title'] = "RHEL 9 /etc/passwd- file must be group-owned by root."
default['rhel9STIG']['stigrule_257909']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257909']['Setting']['_etc_passwd__group_owner_Path'] = '/etc/passwd-'
default['rhel9STIG']['stigrule_257909']['Setting']['_etc_passwd__group_owner_Group'] = 'root'

# R-257910 RHEL-09-232150
default['rhel9STIG']['stigrule_257910']['Manage'] = true
default['rhel9STIG']['stigrule_257910']['Title'] = "RHEL 9 /etc/shadow file must be owned by root."
default['rhel9STIG']['stigrule_257910']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257910']['Setting']['_etc_shadow_owner_Path'] = '/etc/shadow'
default['rhel9STIG']['stigrule_257910']['Setting']['_etc_shadow_owner_Owner'] = 'root'

# R-257911 RHEL-09-232155
default['rhel9STIG']['stigrule_257911']['Manage'] = true
default['rhel9STIG']['stigrule_257911']['Title'] = "RHEL 9 /etc/shadow file must be group-owned by root."
default['rhel9STIG']['stigrule_257911']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257911']['Setting']['_etc_shadow_group_owner_Path'] = '/etc/shadow'
default['rhel9STIG']['stigrule_257911']['Setting']['_etc_shadow_group_owner_Group'] = 'root'

# R-257912 RHEL-09-232160
default['rhel9STIG']['stigrule_257912']['Manage'] = true
default['rhel9STIG']['stigrule_257912']['Title'] = "RHEL 9 /etc/shadow- file must be owned by root."
default['rhel9STIG']['stigrule_257912']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257912']['Setting']['_etc_shadow__owner_Path'] = '/etc/shadow-'
default['rhel9STIG']['stigrule_257912']['Setting']['_etc_shadow__owner_Owner'] = 'root'

# R-257913 RHEL-09-232165
default['rhel9STIG']['stigrule_257913']['Manage'] = true
default['rhel9STIG']['stigrule_257913']['Title'] = "RHEL 9 /etc/shadow- file must be group-owned by root."
default['rhel9STIG']['stigrule_257913']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257913']['Setting']['_etc_shadow__group_owner_Path'] = '/etc/shadow-'
default['rhel9STIG']['stigrule_257913']['Setting']['_etc_shadow__group_owner_Group'] = 'root'

# R-257914 RHEL-09-232170
default['rhel9STIG']['stigrule_257914']['Manage'] = true
default['rhel9STIG']['stigrule_257914']['Title'] = "RHEL 9 /var/log directory must be owned by root."
default['rhel9STIG']['stigrule_257914']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257914']['Setting']['_var_log_owner_Path'] = '/var/log'
default['rhel9STIG']['stigrule_257914']['Setting']['_var_log_owner_Owner'] = 'root'

# R-257915 RHEL-09-232175
default['rhel9STIG']['stigrule_257915']['Manage'] = true
default['rhel9STIG']['stigrule_257915']['Title'] = "RHEL 9 /var/log directory must be group-owned by root."
default['rhel9STIG']['stigrule_257915']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257915']['Setting']['_var_log_group_owner_Path'] = '/var/log'
default['rhel9STIG']['stigrule_257915']['Setting']['_var_log_group_owner_Group'] = 'root'

# R-257916 RHEL-09-232180
default['rhel9STIG']['stigrule_257916']['Manage'] = true
default['rhel9STIG']['stigrule_257916']['Title'] = "RHEL 9 /var/log/messages file must be owned by root."
default['rhel9STIG']['stigrule_257916']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257916']['Setting']['_var_log_messages_owner_Path'] = '/var/log/messages'
default['rhel9STIG']['stigrule_257916']['Setting']['_var_log_messages_owner_Owner'] = 'root'

# R-257917 RHEL-09-232185
default['rhel9STIG']['stigrule_257917']['Manage'] = true
default['rhel9STIG']['stigrule_257917']['Title'] = "RHEL 9 /var/log/messages file must be group-owned by root."
default['rhel9STIG']['stigrule_257917']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257917']['Setting']['_var_log_messages_group_owner_Path'] = '/var/log/messages'
default['rhel9STIG']['stigrule_257917']['Setting']['_var_log_messages_group_owner_Group'] = 'root'

# R-257934 RHEL-09-232270
default['rhel9STIG']['stigrule_257934']['Manage'] = true
default['rhel9STIG']['stigrule_257934']['Title'] = "RHEL 9 /etc/shadow file must have mode 0000 to prevent unauthorized access."
default['rhel9STIG']['stigrule_257934']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257934']['Setting']['_etc_shadow_mode_Path'] = '/etc/shadow'
default['rhel9STIG']['stigrule_257934']['Setting']['_etc_shadow_mode_Mode'] = '0000'

# R-257935 RHEL-09-251010
default['rhel9STIG']['stigrule_257935']['Manage'] = true
default['rhel9STIG']['stigrule_257935']['Title'] = "RHEL 9 must have the firewalld package installed."
default['rhel9STIG']['stigrule_257935']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257935']['Setting']['firewalld_PackageName'] = 'firewalld'
default['rhel9STIG']['stigrule_257935']['Setting']['firewalld_Action'] = :install

# R-257936 RHEL-09-251015
default['rhel9STIG']['stigrule_257936']['Manage'] = true
default['rhel9STIG']['stigrule_257936']['Title'] = "The firewalld service on RHEL 9 must be active."
default['rhel9STIG']['stigrule_257936']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257936']['Setting']['firewalld_enable_ServiceName'] = 'firewalld'
default['rhel9STIG']['stigrule_257936']['Setting']['firewalld_enable_Action'] = :enable

default['rhel9STIG']['stigrule_257936']['Setting']['firewalld_start_ServiceName'] = 'firewalld'
default['rhel9STIG']['stigrule_257936']['Setting']['firewalld_start_Action'] = :start

# R-257939 RHEL-09-251030
default['rhel9STIG']['stigrule_257939']['Manage'] = true
default['rhel9STIG']['stigrule_257939']['Title'] = "RHEL 9 must protect against or limit the effects of denial-of-service (DoS) attacks by ensuring rate-limiting measures on impacted network interfaces are implemented."
default['rhel9STIG']['stigrule_257939']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257939']['Setting']['_etc_firewalld_firewalld_conf_Path'] = '/etc/firewalld/firewalld.conf'
default['rhel9STIG']['stigrule_257939']['Setting']['_etc_firewalld_firewalld_conf_Regexp'] = '^\s*FirewallBackend\s*='
default['rhel9STIG']['stigrule_257939']['Setting']['_etc_firewalld_firewalld_conf_Line'] = 'FirewallBackend=nftables'

# R-257942 RHEL-09-251045
default['rhel9STIG']['stigrule_257942']['Manage'] = true
default['rhel9STIG']['stigrule_257942']['Title'] = "RHEL 9 must enable hardening for the Berkeley Packet Filter just-in-time compiler."
default['rhel9STIG']['stigrule_257942']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257942']['Setting']['net_core_bpf_jit_harden_Key'] = 'net.core.bpf_jit_harden'
default['rhel9STIG']['stigrule_257942']['Setting']['net_core_bpf_jit_harden_Value'] = 2

# R-257943 RHEL-09-252010
default['rhel9STIG']['stigrule_257943']['Manage'] = true
default['rhel9STIG']['stigrule_257943']['Title'] = "RHEL 9 must have the chrony package installed."
default['rhel9STIG']['stigrule_257943']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257943']['Setting']['chrony_PackageName'] = 'chrony'
default['rhel9STIG']['stigrule_257943']['Setting']['chrony_Action'] = :install

# R-257944 RHEL-09-252015
default['rhel9STIG']['stigrule_257944']['Manage'] = true
default['rhel9STIG']['stigrule_257944']['Title'] = "RHEL 9 chronyd service must be enabled."
default['rhel9STIG']['stigrule_257944']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257944']['Setting']['chronyd_enable_ServiceName'] = 'chronyd'
default['rhel9STIG']['stigrule_257944']['Setting']['chronyd_enable_Action'] = :enable

default['rhel9STIG']['stigrule_257944']['Setting']['chronyd_start_ServiceName'] = 'chronyd'
default['rhel9STIG']['stigrule_257944']['Setting']['chronyd_start_Action'] = :start

# R-257946 RHEL-09-252025
default['rhel9STIG']['stigrule_257946']['Manage'] = true
default['rhel9STIG']['stigrule_257946']['Title'] = "RHEL 9 must disable the chrony daemon from acting as a server."
default['rhel9STIG']['stigrule_257946']['Severity'] = 'low'
default['rhel9STIG']['stigrule_257946']['Setting']['_etc_chrony_conf_Path'] = '/etc/chrony.conf'
default['rhel9STIG']['stigrule_257946']['Setting']['_etc_chrony_conf_Regexp'] = '^\s*port\s+\d+'
default['rhel9STIG']['stigrule_257946']['Setting']['_etc_chrony_conf_Line'] = 'port 0'

# R-257947 RHEL-09-252030
default['rhel9STIG']['stigrule_257947']['Manage'] = true
default['rhel9STIG']['stigrule_257947']['Title'] = "RHEL 9 must disable network management of the chrony daemon."
default['rhel9STIG']['stigrule_257947']['Severity'] = 'low'
default['rhel9STIG']['stigrule_257947']['Setting']['_etc_chrony_conf_Path'] = '/etc/chrony.conf'
default['rhel9STIG']['stigrule_257947']['Setting']['_etc_chrony_conf_Regexp'] = '^\s*cmdport\s+\d+'
default['rhel9STIG']['stigrule_257947']['Setting']['_etc_chrony_conf_Line'] = 'cmdport 0'

# R-257949 RHEL-09-252040
default['rhel9STIG']['stigrule_257949']['Manage'] = true
default['rhel9STIG']['stigrule_257949']['Title'] = "RHEL 9 must configure a DNS processing mode in Network Manager."
default['rhel9STIG']['stigrule_257949']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257949']['Setting']['_etc_NetworkManager_NetworkManager_conf_Path'] = '/etc/NetworkManager/NetworkManager.conf'
default['rhel9STIG']['stigrule_257949']['Setting']['_etc_NetworkManager_NetworkManager_conf_Section'] = 'main'
default['rhel9STIG']['stigrule_257949']['Setting']['_etc_NetworkManager_NetworkManager_conf_Option'] = 'dns'
default['rhel9STIG']['stigrule_257949']['Setting']['_etc_NetworkManager_NetworkManager_conf_Value'] = "none"

# R-257954 RHEL-09-252065
default['rhel9STIG']['stigrule_257954']['Manage'] = true
default['rhel9STIG']['stigrule_257954']['Title'] = "RHEL 9 libreswan package must be installed."
default['rhel9STIG']['stigrule_257954']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257954']['Setting']['libreswan_PackageName'] = 'libreswan'
default['rhel9STIG']['stigrule_257954']['Setting']['libreswan_Action'] = :install

# R-257957 RHEL-09-253010
default['rhel9STIG']['stigrule_257957']['Manage'] = true
default['rhel9STIG']['stigrule_257957']['Title'] = "RHEL 9 must be configured to use TCP syncookies."
default['rhel9STIG']['stigrule_257957']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257957']['Setting']['net_ipv4_tcp_syncookies_Key'] = 'net.ipv4.tcp_syncookies'
default['rhel9STIG']['stigrule_257957']['Setting']['net_ipv4_tcp_syncookies_Value'] = 1

# R-257958 RHEL-09-253015
default['rhel9STIG']['stigrule_257958']['Manage'] = true
default['rhel9STIG']['stigrule_257958']['Title'] = "RHEL 9 must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages."
default['rhel9STIG']['stigrule_257958']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257958']['Setting']['net_ipv4_conf_all_accept_redirects_Key'] = 'net.ipv4.conf.all.accept_redirects'
default['rhel9STIG']['stigrule_257958']['Setting']['net_ipv4_conf_all_accept_redirects_Value'] = 0

# R-257959 RHEL-09-253020
default['rhel9STIG']['stigrule_257959']['Manage'] = true
default['rhel9STIG']['stigrule_257959']['Title'] = "RHEL 9 must not forward Internet Protocol version 4 (IPv4) source-routed packets."
default['rhel9STIG']['stigrule_257959']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257959']['Setting']['net_ipv4_conf_all_accept_source_route_Key'] = 'net.ipv4.conf.all.accept_source_route'
default['rhel9STIG']['stigrule_257959']['Setting']['net_ipv4_conf_all_accept_source_route_Value'] = 0

# R-257960 RHEL-09-253025
default['rhel9STIG']['stigrule_257960']['Manage'] = true
default['rhel9STIG']['stigrule_257960']['Title'] = "RHEL 9 must log IPv4 packets with impossible addresses."
default['rhel9STIG']['stigrule_257960']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257960']['Setting']['net_ipv4_conf_all_log_martians_Key'] = 'net.ipv4.conf.all.log_martians'
default['rhel9STIG']['stigrule_257960']['Setting']['net_ipv4_conf_all_log_martians_Value'] = 1

# R-257961 RHEL-09-253030
default['rhel9STIG']['stigrule_257961']['Manage'] = true
default['rhel9STIG']['stigrule_257961']['Title'] = "RHEL 9 must log IPv4 packets with impossible addresses by default."
default['rhel9STIG']['stigrule_257961']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257961']['Setting']['net_ipv4_conf_default_log_martians_Key'] = 'net.ipv4.conf.default.log_martians'
default['rhel9STIG']['stigrule_257961']['Setting']['net_ipv4_conf_default_log_martians_Value'] = 1

# R-257962 RHEL-09-253035
default['rhel9STIG']['stigrule_257962']['Manage'] = true
default['rhel9STIG']['stigrule_257962']['Title'] = "RHEL 9 must use reverse path filtering on all IPv4 interfaces."
default['rhel9STIG']['stigrule_257962']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257962']['Setting']['net_ipv4_conf_all_rp_filter_Key'] = 'net.ipv4.conf.all.rp_filter'
default['rhel9STIG']['stigrule_257962']['Setting']['net_ipv4_conf_all_rp_filter_Value'] = 1

# R-257963 RHEL-09-253040
default['rhel9STIG']['stigrule_257963']['Manage'] = true
default['rhel9STIG']['stigrule_257963']['Title'] = "RHEL 9 must prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted."
default['rhel9STIG']['stigrule_257963']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257963']['Setting']['net_ipv4_conf_default_accept_redirects_Key'] = 'net.ipv4.conf.default.accept_redirects'
default['rhel9STIG']['stigrule_257963']['Setting']['net_ipv4_conf_default_accept_redirects_Value'] = 0

# R-257964 RHEL-09-253045
default['rhel9STIG']['stigrule_257964']['Manage'] = true
default['rhel9STIG']['stigrule_257964']['Title'] = "RHEL 9 must not forward IPv4 source-routed packets by default."
default['rhel9STIG']['stigrule_257964']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257964']['Setting']['net_ipv4_conf_default_accept_source_route_Key'] = 'net.ipv4.conf.default.accept_source_route'
default['rhel9STIG']['stigrule_257964']['Setting']['net_ipv4_conf_default_accept_source_route_Value'] = 0

# R-257965 RHEL-09-253050
default['rhel9STIG']['stigrule_257965']['Manage'] = true
default['rhel9STIG']['stigrule_257965']['Title'] = "RHEL 9 must use a reverse-path filter for IPv4 network traffic when possible by default."
default['rhel9STIG']['stigrule_257965']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257965']['Setting']['net_ipv4_conf_default_rp_filter_Key'] = 'net.ipv4.conf.default.rp_filter'
default['rhel9STIG']['stigrule_257965']['Setting']['net_ipv4_conf_default_rp_filter_Value'] = 1

# R-257966 RHEL-09-253055
default['rhel9STIG']['stigrule_257966']['Manage'] = true
default['rhel9STIG']['stigrule_257966']['Title'] = "RHEL 9 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address."
default['rhel9STIG']['stigrule_257966']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257966']['Setting']['net_ipv4_icmp_echo_ignore_broadcasts_Key'] = 'net.ipv4.icmp_echo_ignore_broadcasts'
default['rhel9STIG']['stigrule_257966']['Setting']['net_ipv4_icmp_echo_ignore_broadcasts_Value'] = 1

# R-257967 RHEL-09-253060
default['rhel9STIG']['stigrule_257967']['Manage'] = true
default['rhel9STIG']['stigrule_257967']['Title'] = "RHEL 9 must limit the number of bogus Internet Control Message Protocol (ICMP) response errors logs."
default['rhel9STIG']['stigrule_257967']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257967']['Setting']['net_ipv4_icmp_ignore_bogus_error_responses_Key'] = 'net.ipv4.icmp_ignore_bogus_error_responses'
default['rhel9STIG']['stigrule_257967']['Setting']['net_ipv4_icmp_ignore_bogus_error_responses_Value'] = 1

# R-257968 RHEL-09-253065
default['rhel9STIG']['stigrule_257968']['Manage'] = true
default['rhel9STIG']['stigrule_257968']['Title'] = "RHEL 9 must not send Internet Control Message Protocol (ICMP) redirects."
default['rhel9STIG']['stigrule_257968']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257968']['Setting']['net_ipv4_conf_all_send_redirects_Key'] = 'net.ipv4.conf.all.send_redirects'
default['rhel9STIG']['stigrule_257968']['Setting']['net_ipv4_conf_all_send_redirects_Value'] = 0

# R-257969 RHEL-09-253070
default['rhel9STIG']['stigrule_257969']['Manage'] = true
default['rhel9STIG']['stigrule_257969']['Title'] = "RHEL 9 must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default."
default['rhel9STIG']['stigrule_257969']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257969']['Setting']['net_ipv4_conf_default_send_redirects_Key'] = 'net.ipv4.conf.default.send_redirects'
default['rhel9STIG']['stigrule_257969']['Setting']['net_ipv4_conf_default_send_redirects_Value'] = 0

# R-257970 RHEL-09-253075
default['rhel9STIG']['stigrule_257970']['Manage'] = true
default['rhel9STIG']['stigrule_257970']['Title'] = "RHEL 9 must not enable IPv4 packet forwarding unless the system is a router."
default['rhel9STIG']['stigrule_257970']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257970']['Setting']['net_ipv4_conf_all_forwarding_Key'] = 'net.ipv4.conf.all.forwarding'
default['rhel9STIG']['stigrule_257970']['Setting']['net_ipv4_conf_all_forwarding_Value'] = 0

# R-257971 RHEL-09-254010
default['rhel9STIG']['stigrule_257971']['Manage'] = true
default['rhel9STIG']['stigrule_257971']['Title'] = "RHEL 9 must not accept router advertisements on all IPv6 interfaces."
default['rhel9STIG']['stigrule_257971']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257971']['Setting']['net_ipv6_conf_all_accept_ra_Key'] = 'net.ipv6.conf.all.accept_ra'
default['rhel9STIG']['stigrule_257971']['Setting']['net_ipv6_conf_all_accept_ra_Value'] = 0

# R-257972 RHEL-09-254015
default['rhel9STIG']['stigrule_257972']['Manage'] = true
default['rhel9STIG']['stigrule_257972']['Title'] = "RHEL 9 must ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages."
default['rhel9STIG']['stigrule_257972']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257972']['Setting']['net_ipv6_conf_all_accept_redirects_Key'] = 'net.ipv6.conf.all.accept_redirects'
default['rhel9STIG']['stigrule_257972']['Setting']['net_ipv6_conf_all_accept_redirects_Value'] = 0

# R-257973 RHEL-09-254020
default['rhel9STIG']['stigrule_257973']['Manage'] = true
default['rhel9STIG']['stigrule_257973']['Title'] = "RHEL 9 must not forward IPv6 source-routed packets."
default['rhel9STIG']['stigrule_257973']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257973']['Setting']['net_ipv6_conf_all_accept_source_route_Key'] = 'net.ipv6.conf.all.accept_source_route'
default['rhel9STIG']['stigrule_257973']['Setting']['net_ipv6_conf_all_accept_source_route_Value'] = 0

# R-257974 RHEL-09-254025
default['rhel9STIG']['stigrule_257974']['Manage'] = true
default['rhel9STIG']['stigrule_257974']['Title'] = "RHEL 9 must not enable IPv6 packet forwarding unless the system is a router."
default['rhel9STIG']['stigrule_257974']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257974']['Setting']['net_ipv6_conf_all_forwarding_Key'] = 'net.ipv6.conf.all.forwarding'
default['rhel9STIG']['stigrule_257974']['Setting']['net_ipv6_conf_all_forwarding_Value'] = 0

# R-257975 RHEL-09-254030
default['rhel9STIG']['stigrule_257975']['Manage'] = true
default['rhel9STIG']['stigrule_257975']['Title'] = "RHEL 9 must not accept router advertisements on all IPv6 interfaces by default."
default['rhel9STIG']['stigrule_257975']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257975']['Setting']['net_ipv6_conf_default_accept_ra_Key'] = 'net.ipv6.conf.default.accept_ra'
default['rhel9STIG']['stigrule_257975']['Setting']['net_ipv6_conf_default_accept_ra_Value'] = 0

# R-257976 RHEL-09-254035
default['rhel9STIG']['stigrule_257976']['Manage'] = true
default['rhel9STIG']['stigrule_257976']['Title'] = "RHEL 9 must prevent IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted."
default['rhel9STIG']['stigrule_257976']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257976']['Setting']['net_ipv6_conf_default_accept_redirects_Key'] = 'net.ipv6.conf.default.accept_redirects'
default['rhel9STIG']['stigrule_257976']['Setting']['net_ipv6_conf_default_accept_redirects_Value'] = 0

# R-257977 RHEL-09-254040
default['rhel9STIG']['stigrule_257977']['Manage'] = true
default['rhel9STIG']['stigrule_257977']['Title'] = "RHEL 9 must not forward IPv6 source-routed packets by default."
default['rhel9STIG']['stigrule_257977']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257977']['Setting']['net_ipv6_conf_default_accept_source_route_Key'] = 'net.ipv6.conf.default.accept_source_route'
default['rhel9STIG']['stigrule_257977']['Setting']['net_ipv6_conf_default_accept_source_route_Value'] = 0

# R-257978 RHEL-09-255010
default['rhel9STIG']['stigrule_257978']['Manage'] = true
default['rhel9STIG']['stigrule_257978']['Title'] = "All RHEL 9 networked systems must have SSH installed."
default['rhel9STIG']['stigrule_257978']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257978']['Setting']['openssh_server_PackageName'] = 'openssh-server'
default['rhel9STIG']['stigrule_257978']['Setting']['openssh_server_Action'] = :install

# R-257979 RHEL-09-255015
default['rhel9STIG']['stigrule_257979']['Manage'] = true
default['rhel9STIG']['stigrule_257979']['Title'] = "All RHEL 9 networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission."
default['rhel9STIG']['stigrule_257979']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257979']['Setting']['sshd_enable_ServiceName'] = 'sshd'
default['rhel9STIG']['stigrule_257979']['Setting']['sshd_enable_Action'] = :enable

default['rhel9STIG']['stigrule_257979']['Setting']['sshd_start_ServiceName'] = 'sshd'
default['rhel9STIG']['stigrule_257979']['Setting']['sshd_start_Action'] = :start

# R-257980 RHEL-09-255020
default['rhel9STIG']['stigrule_257980']['Manage'] = true
default['rhel9STIG']['stigrule_257980']['Title'] = "RHEL 9 must have the openssh-clients package installed."
default['rhel9STIG']['stigrule_257980']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257980']['Setting']['openssh_clients_PackageName'] = 'openssh-clients'
default['rhel9STIG']['stigrule_257980']['Setting']['openssh_clients_Action'] = :install

# R-257981 RHEL-09-255025
default['rhel9STIG']['stigrule_257981']['Manage'] = true
default['rhel9STIG']['stigrule_257981']['Title'] = "RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a SSH logon."
default['rhel9STIG']['stigrule_257981']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257981']['Setting']['Banner_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257981']['Setting']['Banner_Regexp'] = '^\s*(?i)Banner\s+'
default['rhel9STIG']['stigrule_257981']['Setting']['Banner_Line'] = 'Banner /etc/issue'
default['rhel9STIG']['stigrule_257981']['Setting']['Banner_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257982 RHEL-09-255030
default['rhel9STIG']['stigrule_257982']['Manage'] = true
default['rhel9STIG']['stigrule_257982']['Title'] = "RHEL 9 must log SSH connection attempts and failures to the server."
default['rhel9STIG']['stigrule_257982']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257982']['Setting']['LogLevel_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257982']['Setting']['LogLevel_Regexp'] = '^\s*(?i)LogLevel\s+'
default['rhel9STIG']['stigrule_257982']['Setting']['LogLevel_Line'] = 'LogLevel VERBOSE'
default['rhel9STIG']['stigrule_257982']['Setting']['LogLevel_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257983 RHEL-09-255035
default['rhel9STIG']['stigrule_257983']['Manage'] = true
default['rhel9STIG']['stigrule_257983']['Title'] = "RHEL 9 SSHD must accept public key authentication."
default['rhel9STIG']['stigrule_257983']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257983']['Setting']['PubkeyAuthentication_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257983']['Setting']['PubkeyAuthentication_Regexp'] = '^\s*(?i)PubkeyAuthentication\s+'
default['rhel9STIG']['stigrule_257983']['Setting']['PubkeyAuthentication_Line'] = 'PubkeyAuthentication yes'
default['rhel9STIG']['stigrule_257983']['Setting']['PubkeyAuthentication_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257984 RHEL-09-255040
default['rhel9STIG']['stigrule_257984']['Manage'] = true
default['rhel9STIG']['stigrule_257984']['Title'] = "RHEL 9 SSHD must not allow blank passwords."
default['rhel9STIG']['stigrule_257984']['Severity'] = 'high'
default['rhel9STIG']['stigrule_257984']['Setting']['PermitEmptyPasswords_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257984']['Setting']['PermitEmptyPasswords_Regexp'] = '^\s*(?i)PermitEmptyPasswords\s+'
default['rhel9STIG']['stigrule_257984']['Setting']['PermitEmptyPasswords_Line'] = 'PermitEmptyPasswords no'
default['rhel9STIG']['stigrule_257984']['Setting']['PermitEmptyPasswords_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257985 RHEL-09-255045
default['rhel9STIG']['stigrule_257985']['Manage'] = true
default['rhel9STIG']['stigrule_257985']['Title'] = "RHEL 9 must not permit direct logons to the root account using remote access via SSH."
default['rhel9STIG']['stigrule_257985']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257985']['Setting']['PermitRootLogin_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257985']['Setting']['PermitRootLogin_Regexp'] = '^\s*(?i)PermitRootLogin\s+'
default['rhel9STIG']['stigrule_257985']['Setting']['PermitRootLogin_Line'] = 'PermitRootLogin no'
default['rhel9STIG']['stigrule_257985']['Setting']['PermitRootLogin_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257986 RHEL-09-255050
default['rhel9STIG']['stigrule_257986']['Manage'] = true
default['rhel9STIG']['stigrule_257986']['Title'] = "RHEL 9 must enable the Pluggable Authentication Module (PAM) interface for SSHD."
default['rhel9STIG']['stigrule_257986']['Severity'] = 'high'
default['rhel9STIG']['stigrule_257986']['Setting']['UsePAM_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257986']['Setting']['UsePAM_Regexp'] = '^\s*(?i)UsePAM\s+'
default['rhel9STIG']['stigrule_257986']['Setting']['UsePAM_Line'] = 'UsePAM yes'
default['rhel9STIG']['stigrule_257986']['Setting']['UsePAM_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257992 RHEL-09-255080
default['rhel9STIG']['stigrule_257992']['Manage'] = true
default['rhel9STIG']['stigrule_257992']['Title'] = "RHEL 9 must not allow a noncertificate trusted host SSH logon to the system."
default['rhel9STIG']['stigrule_257992']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257992']['Setting']['HostbasedAuthentication_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257992']['Setting']['HostbasedAuthentication_Regexp'] = '^\s*(?i)HostbasedAuthentication\s+'
default['rhel9STIG']['stigrule_257992']['Setting']['HostbasedAuthentication_Line'] = 'HostbasedAuthentication no'
default['rhel9STIG']['stigrule_257992']['Setting']['HostbasedAuthentication_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257993 RHEL-09-255085
default['rhel9STIG']['stigrule_257993']['Manage'] = true
default['rhel9STIG']['stigrule_257993']['Title'] = "RHEL 9 must not allow users to override SSH environment variables."
default['rhel9STIG']['stigrule_257993']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257993']['Setting']['PermitUserEnvironment_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257993']['Setting']['PermitUserEnvironment_Regexp'] = '^\s*(?i)PermitUserEnvironment\s+'
default['rhel9STIG']['stigrule_257993']['Setting']['PermitUserEnvironment_Line'] = 'PermitUserEnvironment no'
default['rhel9STIG']['stigrule_257993']['Setting']['PermitUserEnvironment_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257994 RHEL-09-255090
default['rhel9STIG']['stigrule_257994']['Manage'] = true
default['rhel9STIG']['stigrule_257994']['Title'] = "RHEL 9 must force a frequent session key renegotiation for SSH connections to the server."
default['rhel9STIG']['stigrule_257994']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257994']['Setting']['RekeyLimit_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257994']['Setting']['RekeyLimit_Regexp'] = '^\s*(?i)RekeyLimit\s+'
default['rhel9STIG']['stigrule_257994']['Setting']['RekeyLimit_Line'] = 'RekeyLimit 1G 1h'
default['rhel9STIG']['stigrule_257994']['Setting']['RekeyLimit_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257995 RHEL-09-255095
default['rhel9STIG']['stigrule_257995']['Manage'] = true
default['rhel9STIG']['stigrule_257995']['Title'] = "RHEL 9 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive."
default['rhel9STIG']['stigrule_257995']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257995']['Setting']['ClientAliveCountMax_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257995']['Setting']['ClientAliveCountMax_Regexp'] = '^\s*(?i)ClientAliveCountMax\s+'
default['rhel9STIG']['stigrule_257995']['Setting']['ClientAliveCountMax_Line'] = 'ClientAliveCountMax 1'
default['rhel9STIG']['stigrule_257995']['Setting']['ClientAliveCountMax_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257996 RHEL-09-255100
default['rhel9STIG']['stigrule_257996']['Manage'] = true
default['rhel9STIG']['stigrule_257996']['Title'] = "RHEL 9 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive."
default['rhel9STIG']['stigrule_257996']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257996']['Setting']['ClientAliveInterval_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257996']['Setting']['ClientAliveInterval_Regexp'] = '^\s*(?i)ClientAliveInterval\s+'
default['rhel9STIG']['stigrule_257996']['Setting']['ClientAliveInterval_Line'] = 'ClientAliveInterval 600'
default['rhel9STIG']['stigrule_257996']['Setting']['ClientAliveInterval_Only_if'] = "rpm -q openssh-server.x86_64"

# R-257997 RHEL-09-255105
default['rhel9STIG']['stigrule_257997']['Manage'] = true
default['rhel9STIG']['stigrule_257997']['Title'] = "RHEL 9 SSH server configuration file must be group-owned by root."
default['rhel9STIG']['stigrule_257997']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257997']['Setting']['_etc_ssh_sshd_config_group_owner_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257997']['Setting']['_etc_ssh_sshd_config_group_owner_Group'] = 'root'

# R-257998 RHEL-09-255110
default['rhel9STIG']['stigrule_257998']['Manage'] = true
default['rhel9STIG']['stigrule_257998']['Title'] = "The RHEL 9 SSH server configuration file must be owned by root."
default['rhel9STIG']['stigrule_257998']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_257998']['Setting']['_etc_ssh_sshd_config_owner_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_257998']['Setting']['_etc_ssh_sshd_config_owner_Owner'] = 'root'

# R-258003 RHEL-09-255135
default['rhel9STIG']['stigrule_258003']['Manage'] = true
default['rhel9STIG']['stigrule_258003']['Title'] = "RHEL 9 SSH daemon must not allow GSSAPI authentication."
default['rhel9STIG']['stigrule_258003']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258003']['Setting']['GSSAPIAuthentication_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_258003']['Setting']['GSSAPIAuthentication_Regexp'] = '^\s*(?i)GSSAPIAuthentication\s+'
default['rhel9STIG']['stigrule_258003']['Setting']['GSSAPIAuthentication_Line'] = 'GSSAPIAuthentication no'
default['rhel9STIG']['stigrule_258003']['Setting']['GSSAPIAuthentication_Only_if'] = "rpm -q openssh-server.x86_64"

# R-258004 RHEL-09-255140
default['rhel9STIG']['stigrule_258004']['Manage'] = true
default['rhel9STIG']['stigrule_258004']['Title'] = "RHEL 9 SSH daemon must not allow Kerberos authentication."
default['rhel9STIG']['stigrule_258004']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258004']['Setting']['KerberosAuthentication_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_258004']['Setting']['KerberosAuthentication_Regexp'] = '^\s*(?i)KerberosAuthentication\s+'
default['rhel9STIG']['stigrule_258004']['Setting']['KerberosAuthentication_Line'] = 'KerberosAuthentication no'
default['rhel9STIG']['stigrule_258004']['Setting']['KerberosAuthentication_Only_if'] = "rpm -q openssh-server.x86_64"

# R-258005 RHEL-09-255145
default['rhel9STIG']['stigrule_258005']['Manage'] = true
default['rhel9STIG']['stigrule_258005']['Title'] = "RHEL 9 SSH daemon must not allow rhosts authentication."
default['rhel9STIG']['stigrule_258005']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258005']['Setting']['IgnoreRhosts_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_258005']['Setting']['IgnoreRhosts_Regexp'] = '^\s*(?i)IgnoreRhosts\s+'
default['rhel9STIG']['stigrule_258005']['Setting']['IgnoreRhosts_Line'] = 'IgnoreRhosts yes'
default['rhel9STIG']['stigrule_258005']['Setting']['IgnoreRhosts_Only_if'] = "rpm -q openssh-server.x86_64"

# R-258006 RHEL-09-255150
default['rhel9STIG']['stigrule_258006']['Manage'] = true
default['rhel9STIG']['stigrule_258006']['Title'] = "RHEL 9 SSH daemon must not allow known hosts authentication."
default['rhel9STIG']['stigrule_258006']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258006']['Setting']['IgnoreUserKnownHosts_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_258006']['Setting']['IgnoreUserKnownHosts_Regexp'] = '^\s*(?i)IgnoreUserKnownHosts\s+'
default['rhel9STIG']['stigrule_258006']['Setting']['IgnoreUserKnownHosts_Line'] = 'IgnoreUserKnownHosts yes'
default['rhel9STIG']['stigrule_258006']['Setting']['IgnoreUserKnownHosts_Only_if'] = "rpm -q openssh-server.x86_64"

# R-258007 RHEL-09-255155
default['rhel9STIG']['stigrule_258007']['Manage'] = true
default['rhel9STIG']['stigrule_258007']['Title'] = "RHEL 9 SSH daemon must disable remote X connections for interactive users."
default['rhel9STIG']['stigrule_258007']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258007']['Setting']['X11Forwarding_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_258007']['Setting']['X11Forwarding_Regexp'] = '^\s*(?i)X11Forwarding\s+'
default['rhel9STIG']['stigrule_258007']['Setting']['X11Forwarding_Line'] = 'X11Forwarding no'
default['rhel9STIG']['stigrule_258007']['Setting']['X11Forwarding_Only_if'] = "rpm -q openssh-server.x86_64"

# R-258008 RHEL-09-255160
default['rhel9STIG']['stigrule_258008']['Manage'] = true
default['rhel9STIG']['stigrule_258008']['Title'] = "RHEL 9 SSH daemon must perform strict mode checking of home directory configuration files."
default['rhel9STIG']['stigrule_258008']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258008']['Setting']['StrictModes_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_258008']['Setting']['StrictModes_Regexp'] = '^\s*(?i)StrictModes\s+'
default['rhel9STIG']['stigrule_258008']['Setting']['StrictModes_Line'] = 'StrictModes yes'
default['rhel9STIG']['stigrule_258008']['Setting']['StrictModes_Only_if'] = "rpm -q openssh-server.x86_64"

# R-258009 RHEL-09-255165
default['rhel9STIG']['stigrule_258009']['Manage'] = true
default['rhel9STIG']['stigrule_258009']['Title'] = "RHEL 9 SSH daemon must display the date and time of the last successful account logon upon an SSH logon."
default['rhel9STIG']['stigrule_258009']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258009']['Setting']['PrintLastLog_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_258009']['Setting']['PrintLastLog_Regexp'] = '^\s*(?i)PrintLastLog\s+'
default['rhel9STIG']['stigrule_258009']['Setting']['PrintLastLog_Line'] = 'PrintLastLog yes'
default['rhel9STIG']['stigrule_258009']['Setting']['PrintLastLog_Only_if'] = "rpm -q openssh-server.x86_64"

# R-258011 RHEL-09-255175
default['rhel9STIG']['stigrule_258011']['Manage'] = true
default['rhel9STIG']['stigrule_258011']['Title'] = "RHEL 9 SSH daemon must prevent remote hosts from connecting to the proxy display."
default['rhel9STIG']['stigrule_258011']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258011']['Setting']['X11UseLocalhost_Path'] = '/etc/ssh/sshd_config'
default['rhel9STIG']['stigrule_258011']['Setting']['X11UseLocalhost_Regexp'] = '^\s*(?i)X11UseLocalhost\s+'
default['rhel9STIG']['stigrule_258011']['Setting']['X11UseLocalhost_Line'] = 'X11UseLocalhost yes'
default['rhel9STIG']['stigrule_258011']['Setting']['X11UseLocalhost_Only_if'] = "rpm -q openssh-server.x86_64"

# R-258012 RHEL-09-271010
default['rhel9STIG']['stigrule_258012']['Manage'] = true
default['rhel9STIG']['stigrule_258012']['Title'] = "RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon."
default['rhel9STIG']['stigrule_258012']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258012']['Setting']['_etc_dconf_db_local_d_01_banner_message_Path'] = '/etc/dconf/db/local.d/01-banner-message'
default['rhel9STIG']['stigrule_258012']['Setting']['_etc_dconf_db_local_d_01_banner_message_Section'] = 'org/gnome/login-screen'
default['rhel9STIG']['stigrule_258012']['Setting']['_etc_dconf_db_local_d_01_banner_message_Option'] = 'banner-message-enable'
default['rhel9STIG']['stigrule_258012']['Setting']['_etc_dconf_db_local_d_01_banner_message_Value'] = "true"
default['rhel9STIG']['stigrule_258012']['Setting']['_etc_dconf_db_local_d_01_banner_message_Only_if'] = "rpm -q dconf"

# R-258013 RHEL-09-271015
default['rhel9STIG']['stigrule_258013']['Manage'] = true
default['rhel9STIG']['stigrule_258013']['Title'] = "RHEL 9 must prevent a user from overriding the banner-message-enable setting for the graphical user interface."
default['rhel9STIG']['stigrule_258013']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258013']['Setting']['_etc_dconf_db_local_d_locks_session_banner_message_enable_Path'] = '/etc/dconf/db/local.d/locks/session'
default['rhel9STIG']['stigrule_258013']['Setting']['_etc_dconf_db_local_d_locks_session_banner_message_enable_Line'] = '/org/gnome/login-screen/banner-message-enable'
default['rhel9STIG']['stigrule_258013']['Setting']['_etc_dconf_db_local_d_locks_session_banner_message_enable_Only_if'] = "rpm -q dconf"

# R-258014 RHEL-09-271020
default['rhel9STIG']['stigrule_258014']['Manage'] = true
default['rhel9STIG']['stigrule_258014']['Title'] = "RHEL 9 must disable the graphical user interface automount function unless required."
default['rhel9STIG']['stigrule_258014']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258014']['Setting']['_etc_dconf_db_local_d_00_security_settings_Path'] = '/etc/dconf/db/local.d/00-security-settings'
default['rhel9STIG']['stigrule_258014']['Setting']['_etc_dconf_db_local_d_00_security_settings_Section'] = 'org/gnome/desktop/media-handling'
default['rhel9STIG']['stigrule_258014']['Setting']['_etc_dconf_db_local_d_00_security_settings_Option'] = 'automount-open'
default['rhel9STIG']['stigrule_258014']['Setting']['_etc_dconf_db_local_d_00_security_settings_Value'] = "false"
default['rhel9STIG']['stigrule_258014']['Setting']['_etc_dconf_db_local_d_00_security_settings_Only_if'] = "rpm -q dconf"

# R-258015 RHEL-09-271025
default['rhel9STIG']['stigrule_258015']['Manage'] = true
default['rhel9STIG']['stigrule_258015']['Title'] = "RHEL 9 must prevent a user from overriding the disabling of the graphical user interface automount function."
default['rhel9STIG']['stigrule_258015']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258015']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_Path'] = '/etc/dconf/db/local.d/locks/00-security-settings-lock'
default['rhel9STIG']['stigrule_258015']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_Line'] = '/org/gnome/desktop/media-handling/automount-open'
default['rhel9STIG']['stigrule_258015']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_Only_if'] = "rpm -q dconf"

# R-258016 RHEL-09-271030
default['rhel9STIG']['stigrule_258016']['Manage'] = true
default['rhel9STIG']['stigrule_258016']['Title'] = "RHEL 9 must disable the graphical user interface autorun function unless required."
default['rhel9STIG']['stigrule_258016']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258016']['Setting']['_etc_dconf_db_local_d_00_security_settings_Path'] = '/etc/dconf/db/local.d/00-security-settings'
default['rhel9STIG']['stigrule_258016']['Setting']['_etc_dconf_db_local_d_00_security_settings_Section'] = 'org/gnome/desktop/media-handling'
default['rhel9STIG']['stigrule_258016']['Setting']['_etc_dconf_db_local_d_00_security_settings_Option'] = 'autorun-never'
default['rhel9STIG']['stigrule_258016']['Setting']['_etc_dconf_db_local_d_00_security_settings_Value'] = "true"
default['rhel9STIG']['stigrule_258016']['Setting']['_etc_dconf_db_local_d_00_security_settings_Only_if'] = "rpm -q dconf"

# R-258017 RHEL-09-271035
default['rhel9STIG']['stigrule_258017']['Manage'] = true
default['rhel9STIG']['stigrule_258017']['Title'] = "RHEL 9 must prevent a user from overriding the disabling of the graphical user interface autorun function."
default['rhel9STIG']['stigrule_258017']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258017']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_Path'] = '/etc/dconf/db/local.d/locks/00-security-settings-lock'
default['rhel9STIG']['stigrule_258017']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_Line'] = '/org/gnome/desktop/media-handling/autorun-never'
default['rhel9STIG']['stigrule_258017']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_Only_if'] = "rpm -q dconf"

# R-258019 RHEL-09-271045
default['rhel9STIG']['stigrule_258019']['Manage'] = true
default['rhel9STIG']['stigrule_258019']['Title'] = "RHEL 9 must be able to initiate directly a session lock for all connection types using smart card when the smart card is removed."
default['rhel9STIG']['stigrule_258019']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258019']['Setting']['_etc_dconf_db_local_d_00_security_settings_Path'] = '/etc/dconf/db/local.d/00-security-settings'
default['rhel9STIG']['stigrule_258019']['Setting']['_etc_dconf_db_local_d_00_security_settings_Section'] = 'org/gnome/settings-daemon/peripherals/smartcard'
default['rhel9STIG']['stigrule_258019']['Setting']['_etc_dconf_db_local_d_00_security_settings_Option'] = 'removal-action'
default['rhel9STIG']['stigrule_258019']['Setting']['_etc_dconf_db_local_d_00_security_settings_Value'] = "'lock-screen'"
default['rhel9STIG']['stigrule_258019']['Setting']['_etc_dconf_db_local_d_00_security_settings_Only_if'] = "rpm -q dconf"

# R-258020 RHEL-09-271050
default['rhel9STIG']['stigrule_258020']['Manage'] = true
default['rhel9STIG']['stigrule_258020']['Title'] = "RHEL 9 must prevent a user from overriding the disabling of the graphical user smart card removal action."
default['rhel9STIG']['stigrule_258020']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258020']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_Path'] = '/etc/dconf/db/local.d/locks/00-security-settings-lock'
default['rhel9STIG']['stigrule_258020']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_Line'] = '/org/gnome/settings-daemon/peripherals/smartcard/removal-action'
default['rhel9STIG']['stigrule_258020']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_Only_if'] = "rpm -q dconf"

# R-258021 RHEL-09-271055
default['rhel9STIG']['stigrule_258021']['Manage'] = true
default['rhel9STIG']['stigrule_258021']['Title'] = "RHEL 9 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions."
default['rhel9STIG']['stigrule_258021']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258021']['Setting']['_etc_dconf_db_local_d_00_screensaver_Path'] = '/etc/dconf/db/local.d/00-screensaver'
default['rhel9STIG']['stigrule_258021']['Setting']['_etc_dconf_db_local_d_00_screensaver_Section'] = 'org/gnome/desktop/screensaver'
default['rhel9STIG']['stigrule_258021']['Setting']['_etc_dconf_db_local_d_00_screensaver_Option'] = 'lock-enabled'
default['rhel9STIG']['stigrule_258021']['Setting']['_etc_dconf_db_local_d_00_screensaver_Value'] = "true"
default['rhel9STIG']['stigrule_258021']['Setting']['_etc_dconf_db_local_d_00_screensaver_Only_if'] = "rpm -q dconf"

# R-258022 RHEL-09-271060
default['rhel9STIG']['stigrule_258022']['Manage'] = true
default['rhel9STIG']['stigrule_258022']['Title'] = "RHEL 9 must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface."
default['rhel9STIG']['stigrule_258022']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258022']['Setting']['_etc_dconf_db_local_d_locks_session_lock_enabled_Path'] = '/etc/dconf/db/local.d/locks/session'
default['rhel9STIG']['stigrule_258022']['Setting']['_etc_dconf_db_local_d_locks_session_lock_enabled_Line'] = '/org/gnome/desktop/screensaver/lock-enabled'
default['rhel9STIG']['stigrule_258022']['Setting']['_etc_dconf_db_local_d_locks_session_lock_enabled_Only_if'] = "rpm -q dconf"

# R-258023 RHEL-09-271065
default['rhel9STIG']['stigrule_258023']['Manage'] = true
default['rhel9STIG']['stigrule_258023']['Title'] = "RHEL 9 must automatically lock graphical user sessions after 10 minutes of inactivity."
default['rhel9STIG']['stigrule_258023']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258023']['Setting']['_etc_dconf_db_local_d_00_screensaver_Path'] = '/etc/dconf/db/local.d/00-screensaver'
default['rhel9STIG']['stigrule_258023']['Setting']['_etc_dconf_db_local_d_00_screensaver_Section'] = 'org/gnome/desktop/session'
default['rhel9STIG']['stigrule_258023']['Setting']['_etc_dconf_db_local_d_00_screensaver_Option'] = 'idle-delay'
default['rhel9STIG']['stigrule_258023']['Setting']['_etc_dconf_db_local_d_00_screensaver_Value'] = "uint32 600"
default['rhel9STIG']['stigrule_258023']['Setting']['_etc_dconf_db_local_d_00_screensaver_Only_if'] = "rpm -q dconf"

# R-258024 RHEL-09-271070
default['rhel9STIG']['stigrule_258024']['Manage'] = true
default['rhel9STIG']['stigrule_258024']['Title'] = "RHEL 9 must prevent a user from overriding the session idle-delay setting for the graphical user interface."
default['rhel9STIG']['stigrule_258024']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258024']['Setting']['_etc_dconf_db_local_d_locks_session_idle_delay_Path'] = '/etc/dconf/db/local.d/locks/session'
default['rhel9STIG']['stigrule_258024']['Setting']['_etc_dconf_db_local_d_locks_session_idle_delay_Line'] = '/org/gnome/desktop/session/idle-delay'
default['rhel9STIG']['stigrule_258024']['Setting']['_etc_dconf_db_local_d_locks_session_idle_delay_Only_if'] = "rpm -q dconf"

# R-258025 RHEL-09-271075
default['rhel9STIG']['stigrule_258025']['Manage'] = true
default['rhel9STIG']['stigrule_258025']['Title'] = "RHEL 9 must initiate a session lock for graphical user interfaces when the screensaver is activated."
default['rhel9STIG']['stigrule_258025']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258025']['Setting']['_etc_dconf_db_local_d_00_screensaver_Path'] = '/etc/dconf/db/local.d/00-screensaver'
default['rhel9STIG']['stigrule_258025']['Setting']['_etc_dconf_db_local_d_00_screensaver_Section'] = 'org/gnome/desktop/screensaver'
default['rhel9STIG']['stigrule_258025']['Setting']['_etc_dconf_db_local_d_00_screensaver_Option'] = 'lock-delay'
default['rhel9STIG']['stigrule_258025']['Setting']['_etc_dconf_db_local_d_00_screensaver_Value'] = "uint32 5"
default['rhel9STIG']['stigrule_258025']['Setting']['_etc_dconf_db_local_d_00_screensaver_Only_if'] = "rpm -q dconf"

# R-258026 RHEL-09-271080
default['rhel9STIG']['stigrule_258026']['Manage'] = true
default['rhel9STIG']['stigrule_258026']['Title'] = "RHEL 9 must prevent a user from overriding the session lock-delay setting for the graphical user interface."
default['rhel9STIG']['stigrule_258026']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258026']['Setting']['_etc_dconf_db_local_d_locks_session_lock_delay_Path'] = '/etc/dconf/db/local.d/locks/session'
default['rhel9STIG']['stigrule_258026']['Setting']['_etc_dconf_db_local_d_locks_session_lock_delay_Line'] = '/org/gnome/desktop/screensaver/lock-delay'
default['rhel9STIG']['stigrule_258026']['Setting']['_etc_dconf_db_local_d_locks_session_lock_delay_Only_if'] = "rpm -q dconf"

# R-258027 RHEL-09-271085
default['rhel9STIG']['stigrule_258027']['Manage'] = true
default['rhel9STIG']['stigrule_258027']['Title'] = "RHEL 9 must conceal, via the session lock, information previously visible on the display with a publicly viewable image."
default['rhel9STIG']['stigrule_258027']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_00_security_settings_Path'] = '/etc/dconf/db/local.d/00-security-settings'
default['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_00_security_settings_Section'] = 'org/gnome/desktop/screensaver'
default['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_00_security_settings_Option'] = 'picture-uri'
default['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_00_security_settings_Value'] = "''"
default['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_00_security_settings_Only_if'] = "rpm -q dconf"

default['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_Path'] = '/etc/dconf/db/local.d/locks/00-security-settings-lock'
default['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_Line'] = '/org/gnome/desktop/screensaver/picture-uri'
default['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_Only_if'] = "rpm -q dconf"

# R-258030 RHEL-09-271100
default['rhel9STIG']['stigrule_258030']['Manage'] = true
default['rhel9STIG']['stigrule_258030']['Title'] = "RHEL 9 must prevent a user from overriding the disable-restart-buttons setting for the graphical user interface."
default['rhel9STIG']['stigrule_258030']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258030']['Setting']['_etc_dconf_db_local_d_locks_session_disable_restart_buttons_Path'] = '/etc/dconf/db/local.d/locks/session'
default['rhel9STIG']['stigrule_258030']['Setting']['_etc_dconf_db_local_d_locks_session_disable_restart_buttons_Line'] = '/org/gnome/login-screen/disable-restart-buttons'
default['rhel9STIG']['stigrule_258030']['Setting']['_etc_dconf_db_local_d_locks_session_disable_restart_buttons_Only_if'] = "rpm -q dconf"

# R-258031 RHEL-09-271105
default['rhel9STIG']['stigrule_258031']['Manage'] = true
default['rhel9STIG']['stigrule_258031']['Title'] = "RHEL 9 must disable the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot."
default['rhel9STIG']['stigrule_258031']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258031']['Setting']['_etc_dconf_db_local_d_00_security_settings_Path'] = '/etc/dconf/db/local.d/00-security-settings'
default['rhel9STIG']['stigrule_258031']['Setting']['_etc_dconf_db_local_d_00_security_settings_Section'] = 'org/gnome/settings-daemon/plugins/media-keys'
default['rhel9STIG']['stigrule_258031']['Setting']['_etc_dconf_db_local_d_00_security_settings_Option'] = 'logout'
default['rhel9STIG']['stigrule_258031']['Setting']['_etc_dconf_db_local_d_00_security_settings_Value'] = "['']"
default['rhel9STIG']['stigrule_258031']['Setting']['_etc_dconf_db_local_d_00_security_settings_Only_if'] = "rpm -q dconf"

# R-258032 RHEL-09-271110
default['rhel9STIG']['stigrule_258032']['Manage'] = true
default['rhel9STIG']['stigrule_258032']['Title'] = "RHEL 9 must prevent a user from overriding the Ctrl-Alt-Del sequence settings for the graphical user interface."
default['rhel9STIG']['stigrule_258032']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258032']['Setting']['_etc_dconf_db_local_d_locks_session_logout_Path'] = '/etc/dconf/db/local.d/locks/session'
default['rhel9STIG']['stigrule_258032']['Setting']['_etc_dconf_db_local_d_locks_session_logout_Line'] = '/org/gnome/settings-daemon/plugins/media-keys/logout'
default['rhel9STIG']['stigrule_258032']['Setting']['_etc_dconf_db_local_d_locks_session_logout_Only_if'] = "rpm -q dconf"

# R-258033 RHEL-09-271115
default['rhel9STIG']['stigrule_258033']['Manage'] = true
default['rhel9STIG']['stigrule_258033']['Title'] = "RHEL 9 must disable the user list at logon for graphical user interfaces."
default['rhel9STIG']['stigrule_258033']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258033']['Setting']['_etc_dconf_db_local_d_02_login_screen_Path'] = '/etc/dconf/db/local.d/02-login-screen'
default['rhel9STIG']['stigrule_258033']['Setting']['_etc_dconf_db_local_d_02_login_screen_Section'] = 'org/gnome/login-screen'
default['rhel9STIG']['stigrule_258033']['Setting']['_etc_dconf_db_local_d_02_login_screen_Option'] = 'disable-user-list'
default['rhel9STIG']['stigrule_258033']['Setting']['_etc_dconf_db_local_d_02_login_screen_Value'] = "true"
default['rhel9STIG']['stigrule_258033']['Setting']['_etc_dconf_db_local_d_02_login_screen_Only_if'] = "rpm -q dconf"

# R-258034 RHEL-09-291010
default['rhel9STIG']['stigrule_258034']['Manage'] = true
default['rhel9STIG']['stigrule_258034']['Title'] = "RHEL 9 must be configured to disable USB mass storage."
default['rhel9STIG']['stigrule_258034']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258034']['Setting']['_etc_modprobe_d_usb_storage_conf_install_usb_storage__bin_false_Path'] = '/etc/modprobe.d/usb-storage.conf'
default['rhel9STIG']['stigrule_258034']['Setting']['_etc_modprobe_d_usb_storage_conf_install_usb_storage__bin_false_Line'] = 'install usb-storage /bin/false'

default['rhel9STIG']['stigrule_258034']['Setting']['_etc_modprobe_d_usb_storage_conf_blacklist_usb_storage_Path'] = '/etc/modprobe.d/usb-storage.conf'
default['rhel9STIG']['stigrule_258034']['Setting']['_etc_modprobe_d_usb_storage_conf_blacklist_usb_storage_Line'] = 'blacklist usb-storage'

# R-258035 RHEL-09-291015
default['rhel9STIG']['stigrule_258035']['Manage'] = true
default['rhel9STIG']['stigrule_258035']['Title'] = "RHEL 9 must have the USBGuard package installed."
default['rhel9STIG']['stigrule_258035']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258035']['Setting']['usbguard_PackageName'] = 'usbguard'
default['rhel9STIG']['stigrule_258035']['Setting']['usbguard_Action'] = :install

default['rhel9STIG']['stigrule_258035']['Setting']['usbguard_enable_ServiceName'] = 'usbguard'
default['rhel9STIG']['stigrule_258035']['Setting']['usbguard_enable_Action'] = :enable

default['rhel9STIG']['stigrule_258035']['Setting']['usbguard_start_ServiceName'] = 'usbguard'
default['rhel9STIG']['stigrule_258035']['Setting']['usbguard_start_Action'] = :start

# R-258036 RHEL-09-291020
default['rhel9STIG']['stigrule_258036']['Manage'] = true
default['rhel9STIG']['stigrule_258036']['Title'] = "RHEL 9 must have the USBGuard package enabled."
default['rhel9STIG']['stigrule_258036']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258036']['Setting']['usbguard_enable_ServiceName'] = 'usbguard'
default['rhel9STIG']['stigrule_258036']['Setting']['usbguard_enable_Action'] = :enable

default['rhel9STIG']['stigrule_258036']['Setting']['usbguard_start_ServiceName'] = 'usbguard'
default['rhel9STIG']['stigrule_258036']['Setting']['usbguard_start_Action'] = :start

# R-258037 RHEL-09-291025
default['rhel9STIG']['stigrule_258037']['Manage'] = true
default['rhel9STIG']['stigrule_258037']['Title'] = "RHEL 9 must enable Linux audit logging for the USBGuard daemon."
default['rhel9STIG']['stigrule_258037']['Severity'] = 'low'
default['rhel9STIG']['stigrule_258037']['Setting']['_etc_usbguard_usbguard_daemon_conf_Path'] = '/etc/usbguard/usbguard-daemon.conf'
default['rhel9STIG']['stigrule_258037']['Setting']['_etc_usbguard_usbguard_daemon_conf_Regexp'] = '^\s*AuditBackend\s*='
default['rhel9STIG']['stigrule_258037']['Setting']['_etc_usbguard_usbguard_daemon_conf_Line'] = 'AuditBackend=LinuxAudit'

# R-258039 RHEL-09-291035
default['rhel9STIG']['stigrule_258039']['Manage'] = true
default['rhel9STIG']['stigrule_258039']['Title'] = "RHEL 9 Bluetooth must be disabled."
default['rhel9STIG']['stigrule_258039']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258039']['Setting']['_etc_modprobe_d_bluetooth_conf_install_bluetooth__bin_false_Path'] = '/etc/modprobe.d/bluetooth.conf'
default['rhel9STIG']['stigrule_258039']['Setting']['_etc_modprobe_d_bluetooth_conf_install_bluetooth__bin_false_Line'] = 'install bluetooth /bin/false'

default['rhel9STIG']['stigrule_258039']['Setting']['_etc_modprobe_d_bluetooth_conf_blacklist_bluetooth_Path'] = '/etc/modprobe.d/bluetooth.conf'
default['rhel9STIG']['stigrule_258039']['Setting']['_etc_modprobe_d_bluetooth_conf_blacklist_bluetooth_Line'] = 'blacklist bluetooth'

# R-258040 RHEL-09-291040
default['rhel9STIG']['stigrule_258040']['Manage'] = true
default['rhel9STIG']['stigrule_258040']['Title'] = "RHEL 9 wireless network adapters must be disabled."
default['rhel9STIG']['stigrule_258040']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258040']['Setting']['nmcli_radio_wifi_off_Command'] = "nmcli radio wifi off"
default['rhel9STIG']['stigrule_258040']['Setting']['nmcli_radio_wifi_off_Only_if'] = "[[ $(nmcli radio wifi) == 'enabled' ]]"

# R-258041 RHEL-09-411010
default['rhel9STIG']['stigrule_258041']['Manage'] = true
default['rhel9STIG']['stigrule_258041']['Title'] = "RHEL 9 user account passwords for new users or password changes must have a 60-day maximum password lifetime restriction in /etc/login.defs."
default['rhel9STIG']['stigrule_258041']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258041']['Setting']['_etc_login_defs_Path'] = '/etc/login.defs'
default['rhel9STIG']['stigrule_258041']['Setting']['_etc_login_defs_Regexp'] = '^PASS_MAX_DAYS'
default['rhel9STIG']['stigrule_258041']['Setting']['_etc_login_defs_Line'] = 'PASS_MAX_DAYS 180'

# R-258043 RHEL-09-411020
default['rhel9STIG']['stigrule_258043']['Manage'] = true
default['rhel9STIG']['stigrule_258043']['Title'] = "All RHEL 9 local interactive user accounts must be assigned a home directory upon creation."
default['rhel9STIG']['stigrule_258043']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258043']['Setting']['_etc_login_defs_Path'] = '/etc/login.defs'
default['rhel9STIG']['stigrule_258043']['Setting']['_etc_login_defs_Regexp'] = '^CREATE_HOME'
default['rhel9STIG']['stigrule_258043']['Setting']['_etc_login_defs_Line'] = 'CREATE_HOME yes'

# R-258049 RHEL-09-411050
default['rhel9STIG']['stigrule_258049']['Manage'] = true
default['rhel9STIG']['stigrule_258049']['Title'] = "RHEL 9 must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity."
default['rhel9STIG']['stigrule_258049']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258049']['Setting']['sudo_useradd__D__f_35_Command'] = "sudo useradd -D -f 35"
default['rhel9STIG']['stigrule_258049']['Setting']['sudo_useradd__D__f_35_Only_if'] = "[[ $(sudo grep -i inactive /etc/default/useradd) != 'INACTIVE=35' ]]"

# R-258054 RHEL-09-411075
default['rhel9STIG']['stigrule_258054']['Manage'] = true
default['rhel9STIG']['stigrule_258054']['Title'] = "RHEL 9 must automatically lock an account when three unsuccessful logon attempts occur."
default['rhel9STIG']['stigrule_258054']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258054']['Setting']['_etc_security_faillock_conf_Path'] = '/etc/security/faillock.conf'
default['rhel9STIG']['stigrule_258054']['Setting']['_etc_security_faillock_conf_Regexp'] = '^[\s#]*deny\s*=\s*\d+'
default['rhel9STIG']['stigrule_258054']['Setting']['_etc_security_faillock_conf_Line'] = 'deny = 3'

# R-258055 RHEL-09-411080
default['rhel9STIG']['stigrule_258055']['Manage'] = true
default['rhel9STIG']['stigrule_258055']['Title'] = "RHEL 9 must automatically lock the root account until the root account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period."
default['rhel9STIG']['stigrule_258055']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258055']['Setting']['_etc_security_faillock_conf_Path'] = '/etc/security/faillock.conf'
default['rhel9STIG']['stigrule_258055']['Setting']['_etc_security_faillock_conf_Regexp'] = '^[\s#]*even_deny_root\b'
default['rhel9STIG']['stigrule_258055']['Setting']['_etc_security_faillock_conf_Line'] = 'even_deny_root'

# R-258056 RHEL-09-411085
default['rhel9STIG']['stigrule_258056']['Manage'] = true
default['rhel9STIG']['stigrule_258056']['Title'] = "RHEL 9 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period."
default['rhel9STIG']['stigrule_258056']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258056']['Setting']['_etc_security_faillock_conf_Path'] = '/etc/security/faillock.conf'
default['rhel9STIG']['stigrule_258056']['Setting']['_etc_security_faillock_conf_Regexp'] = '^[\s#]*fail_interval\s*=\s*\d+'
default['rhel9STIG']['stigrule_258056']['Setting']['_etc_security_faillock_conf_Line'] = 'fail_interval = 900'

# R-258057 RHEL-09-411090
default['rhel9STIG']['stigrule_258057']['Manage'] = true
default['rhel9STIG']['stigrule_258057']['Title'] = "RHEL 9 must maintain an account lock until the locked account is released by an administrator."
default['rhel9STIG']['stigrule_258057']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258057']['Setting']['_etc_security_faillock_conf_Path'] = '/etc/security/faillock.conf'
default['rhel9STIG']['stigrule_258057']['Setting']['_etc_security_faillock_conf_Regexp'] = '^[\s#]*unlock_time\s*=\s*\d+'
default['rhel9STIG']['stigrule_258057']['Setting']['_etc_security_faillock_conf_Line'] = 'unlock_time = 0'

# R-258060 RHEL-09-411105
default['rhel9STIG']['stigrule_258060']['Manage'] = true
default['rhel9STIG']['stigrule_258060']['Title'] = "RHEL 9 must ensure account lockouts persist."
default['rhel9STIG']['stigrule_258060']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258060']['Setting']['_etc_security_faillock_conf_Path'] = '/etc/security/faillock.conf'
default['rhel9STIG']['stigrule_258060']['Setting']['_etc_security_faillock_conf_Regexp'] = '^[\s#]*dir\s*=\s*\S+'
default['rhel9STIG']['stigrule_258060']['Setting']['_etc_security_faillock_conf_Line'] = 'dir = /var/log/faillock'

# R-258069 RHEL-09-412040
default['rhel9STIG']['stigrule_258069']['Manage'] = true
default['rhel9STIG']['stigrule_258069']['Title'] = "RHEL 9 must limit the number of concurrent sessions to ten for all accounts and/or account types."
default['rhel9STIG']['stigrule_258069']['Severity'] = 'low'
default['rhel9STIG']['stigrule_258069']['Setting']['_etc_security_limits_conf_Path'] = '/etc/security/limits.conf'
default['rhel9STIG']['stigrule_258069']['Setting']['_etc_security_limits_conf_Regexp'] = '^\s*\*\s+hard\s+maxlogins\b'
default['rhel9STIG']['stigrule_258069']['Setting']['_etc_security_limits_conf_Line'] = '* hard maxlogins 10'

# R-258070 RHEL-09-412045
default['rhel9STIG']['stigrule_258070']['Manage'] = true
default['rhel9STIG']['stigrule_258070']['Title'] = "RHEL 9 must log username information when unsuccessful logon attempts occur."
default['rhel9STIG']['stigrule_258070']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258070']['Setting']['_etc_security_faillock_conf_Path'] = '/etc/security/faillock.conf'
default['rhel9STIG']['stigrule_258070']['Setting']['_etc_security_faillock_conf_Regexp'] = '^[\s#]*audit\b'
default['rhel9STIG']['stigrule_258070']['Setting']['_etc_security_faillock_conf_Line'] = 'audit'

# R-258071 RHEL-09-412050
default['rhel9STIG']['stigrule_258071']['Manage'] = true
default['rhel9STIG']['stigrule_258071']['Title'] = "RHEL 9 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt."
default['rhel9STIG']['stigrule_258071']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258071']['Setting']['_etc_login_defs_Path'] = '/etc/login.defs'
default['rhel9STIG']['stigrule_258071']['Setting']['_etc_login_defs_Regexp'] = '^[#\s]*FAIL_DELAY\s*\d+\s*$'
default['rhel9STIG']['stigrule_258071']['Setting']['_etc_login_defs_Line'] = 'FAIL_DELAY 4'

# R-258072 RHEL-09-412055
default['rhel9STIG']['stigrule_258072']['Manage'] = true
default['rhel9STIG']['stigrule_258072']['Title'] = "RHEL 9 must define default permissions for the bash shell."
default['rhel9STIG']['stigrule_258072']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258072']['Setting']['_etc_bashrc_Path'] = '/etc/bashrc'
default['rhel9STIG']['stigrule_258072']['Setting']['_etc_bashrc_Regexp'] = '^umask\s+\d+'
default['rhel9STIG']['stigrule_258072']['Setting']['_etc_bashrc_Line'] = 'umask 077'

# R-258073 RHEL-09-412060
default['rhel9STIG']['stigrule_258073']['Manage'] = true
default['rhel9STIG']['stigrule_258073']['Title'] = "RHEL 9 must define default permissions for the c shell."
default['rhel9STIG']['stigrule_258073']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258073']['Setting']['_etc_csh_cshrc_Path'] = '/etc/csh.cshrc'
default['rhel9STIG']['stigrule_258073']['Setting']['_etc_csh_cshrc_Regexp'] = '^umask\s+\d+'
default['rhel9STIG']['stigrule_258073']['Setting']['_etc_csh_cshrc_Line'] = 'umask 077'

# R-258074 RHEL-09-412065
default['rhel9STIG']['stigrule_258074']['Manage'] = true
default['rhel9STIG']['stigrule_258074']['Title'] = "RHEL 9 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
default['rhel9STIG']['stigrule_258074']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258074']['Setting']['_etc_login_defs_Path'] = '/etc/login.defs'
default['rhel9STIG']['stigrule_258074']['Setting']['_etc_login_defs_Regexp'] = '^UMASK'
default['rhel9STIG']['stigrule_258074']['Setting']['_etc_login_defs_Line'] = 'UMASK 077'

# R-258075 RHEL-09-412070
default['rhel9STIG']['stigrule_258075']['Manage'] = true
default['rhel9STIG']['stigrule_258075']['Title'] = "RHEL 9 must define default permissions for the system default profile."
default['rhel9STIG']['stigrule_258075']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258075']['Setting']['_etc_profile_Path'] = '/etc/profile'
default['rhel9STIG']['stigrule_258075']['Setting']['_etc_profile_Regexp'] = '^umask\s+\d+'
default['rhel9STIG']['stigrule_258075']['Setting']['_etc_profile_Line'] = 'umask 077'

# R-258078 RHEL-09-431010
default['rhel9STIG']['stigrule_258078']['Manage'] = true
default['rhel9STIG']['stigrule_258078']['Title'] = "RHEL 9 must use a Linux Security Module configured to enforce limits on system services."
default['rhel9STIG']['stigrule_258078']['Severity'] = 'high'
default['rhel9STIG']['stigrule_258078']['Setting']['_etc_selinux_config_Path'] = '/etc/selinux/config'
default['rhel9STIG']['stigrule_258078']['Setting']['_etc_selinux_config_Regexp'] = '^\s*SELINUX\s*='
default['rhel9STIG']['stigrule_258078']['Setting']['_etc_selinux_config_Line'] = 'SELINUX=enforcing'

# R-258079 RHEL-09-431015
default['rhel9STIG']['stigrule_258079']['Manage'] = true
default['rhel9STIG']['stigrule_258079']['Title'] = "RHEL 9 must enable the SELinux targeted policy."
default['rhel9STIG']['stigrule_258079']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258079']['Setting']['_etc_selinux_config_Path'] = '/etc/selinux/config'
default['rhel9STIG']['stigrule_258079']['Setting']['_etc_selinux_config_Regexp'] = '^\s*SELINUXTYPE\s*='
default['rhel9STIG']['stigrule_258079']['Setting']['_etc_selinux_config_Line'] = 'SELINUXTYPE=targeted'

# R-258081 RHEL-09-431025
default['rhel9STIG']['stigrule_258081']['Manage'] = true
default['rhel9STIG']['stigrule_258081']['Title'] = "RHEL 9 must have policycoreutils package installed."
default['rhel9STIG']['stigrule_258081']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258081']['Setting']['policycoreutils_PackageName'] = 'policycoreutils'
default['rhel9STIG']['stigrule_258081']['Setting']['policycoreutils_Action'] = :install

# R-258082 RHEL-09-431030
default['rhel9STIG']['stigrule_258082']['Manage'] = true
default['rhel9STIG']['stigrule_258082']['Title'] = "RHEL 9 policycoreutils-python-utils package must be installed."
default['rhel9STIG']['stigrule_258082']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258082']['Setting']['policycoreutils_python_utils_PackageName'] = 'policycoreutils-python-utils'
default['rhel9STIG']['stigrule_258082']['Setting']['policycoreutils_python_utils_Action'] = :install

# R-258083 RHEL-09-432010
default['rhel9STIG']['stigrule_258083']['Manage'] = true
default['rhel9STIG']['stigrule_258083']['Title'] = "RHEL 9 must have the sudo package installed."
default['rhel9STIG']['stigrule_258083']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258083']['Setting']['sudo_PackageName'] = 'sudo'
default['rhel9STIG']['stigrule_258083']['Setting']['sudo_Action'] = :install

# R-258084 RHEL-09-432015
default['rhel9STIG']['stigrule_258084']['Manage'] = true
default['rhel9STIG']['stigrule_258084']['Title'] = "RHEL 9 must require reauthentication when using the \"sudo\" command."
default['rhel9STIG']['stigrule_258084']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258084']['Setting']['_etc_sudoers_Path'] = '/etc/sudoers'
default['rhel9STIG']['stigrule_258084']['Setting']['_etc_sudoers_Regexp'] = '^\s*Defaults\s+timestamp_timeout\s*='
default['rhel9STIG']['stigrule_258084']['Setting']['_etc_sudoers_Line'] = 'Defaults timestamp_timeout=0'

# R-258089 RHEL-09-433010
default['rhel9STIG']['stigrule_258089']['Manage'] = true
default['rhel9STIG']['stigrule_258089']['Title'] = "RHEL 9 fapolicy module must be installed."
default['rhel9STIG']['stigrule_258089']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258089']['Setting']['fapolicyd_PackageName'] = 'fapolicyd'
default['rhel9STIG']['stigrule_258089']['Setting']['fapolicyd_Action'] = :install

# R-258090 RHEL-09-433015
default['rhel9STIG']['stigrule_258090']['Manage'] = true
default['rhel9STIG']['stigrule_258090']['Title'] = "RHEL 9 fapolicy module must be enabled."
default['rhel9STIG']['stigrule_258090']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258090']['Setting']['fapolicyd_enable_ServiceName'] = 'fapolicyd'
default['rhel9STIG']['stigrule_258090']['Setting']['fapolicyd_enable_Action'] = :enable

default['rhel9STIG']['stigrule_258090']['Setting']['fapolicyd_start_ServiceName'] = 'fapolicyd'
default['rhel9STIG']['stigrule_258090']['Setting']['fapolicyd_start_Action'] = :start

# R-258101 RHEL-09-611060
default['rhel9STIG']['stigrule_258101']['Manage'] = true
default['rhel9STIG']['stigrule_258101']['Title'] = "RHEL 9 must enforce password complexity rules for the root account."
default['rhel9STIG']['stigrule_258101']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258101']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258101']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*enforce_for_root'
default['rhel9STIG']['stigrule_258101']['Setting']['_etc_security_pwquality_conf_Line'] = 'enforce_for_root'

# R-258102 RHEL-09-611065
default['rhel9STIG']['stigrule_258102']['Manage'] = true
default['rhel9STIG']['stigrule_258102']['Title'] = "RHEL 9 must enforce password complexity by requiring that at least one lowercase character be used."
default['rhel9STIG']['stigrule_258102']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258102']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258102']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*lcredit'
default['rhel9STIG']['stigrule_258102']['Setting']['_etc_security_pwquality_conf_Line'] = 'lcredit = -1'

# R-258103 RHEL-09-611070
default['rhel9STIG']['stigrule_258103']['Manage'] = true
default['rhel9STIG']['stigrule_258103']['Title'] = "RHEL 9 must enforce password complexity by requiring that at least one numeric character be used."
default['rhel9STIG']['stigrule_258103']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258103']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258103']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*dcredit'
default['rhel9STIG']['stigrule_258103']['Setting']['_etc_security_pwquality_conf_Line'] = 'dcredit = -1'

# R-258104 RHEL-09-611075
default['rhel9STIG']['stigrule_258104']['Manage'] = true
default['rhel9STIG']['stigrule_258104']['Title'] = "RHEL 9 passwords for new users or password changes must have a 24 hours minimum password lifetime restriction in /etc/login.defs."
default['rhel9STIG']['stigrule_258104']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258104']['Setting']['_etc_login_defs_Path'] = '/etc/login.defs'
default['rhel9STIG']['stigrule_258104']['Setting']['_etc_login_defs_Regexp'] = '^PASS_MIN_DAYS'
default['rhel9STIG']['stigrule_258104']['Setting']['_etc_login_defs_Line'] = 'PASS_MIN_DAYS 1'

# R-258107 RHEL-09-611090
default['rhel9STIG']['stigrule_258107']['Manage'] = true
default['rhel9STIG']['stigrule_258107']['Title'] = "RHEL 9 passwords must be created with a minimum of 15 characters."
default['rhel9STIG']['stigrule_258107']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258107']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258107']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*minlen'
default['rhel9STIG']['stigrule_258107']['Setting']['_etc_security_pwquality_conf_Line'] = 'minlen = 15'

# R-258109 RHEL-09-611100
default['rhel9STIG']['stigrule_258109']['Manage'] = true
default['rhel9STIG']['stigrule_258109']['Title'] = "RHEL 9 must enforce password complexity by requiring that at least one special character be used."
default['rhel9STIG']['stigrule_258109']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258109']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258109']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*ocredit'
default['rhel9STIG']['stigrule_258109']['Setting']['_etc_security_pwquality_conf_Line'] = 'ocredit = -1'

# R-258110 RHEL-09-611105
default['rhel9STIG']['stigrule_258110']['Manage'] = true
default['rhel9STIG']['stigrule_258110']['Title'] = "RHEL 9 must prevent the use of dictionary words for passwords."
default['rhel9STIG']['stigrule_258110']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258110']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258110']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*dictcheck'
default['rhel9STIG']['stigrule_258110']['Setting']['_etc_security_pwquality_conf_Line'] = 'dictcheck = 1'

# R-258111 RHEL-09-611110
default['rhel9STIG']['stigrule_258111']['Manage'] = true
default['rhel9STIG']['stigrule_258111']['Title'] = "RHEL 9 must enforce password complexity by requiring that at least one uppercase character be used."
default['rhel9STIG']['stigrule_258111']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258111']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258111']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*ucredit'
default['rhel9STIG']['stigrule_258111']['Setting']['_etc_security_pwquality_conf_Line'] = 'ucredit = -1'

# R-258112 RHEL-09-611115
default['rhel9STIG']['stigrule_258112']['Manage'] = true
default['rhel9STIG']['stigrule_258112']['Title'] = "RHEL 9 must require the change of at least eight characters when passwords are changed."
default['rhel9STIG']['stigrule_258112']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258112']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258112']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*difok'
default['rhel9STIG']['stigrule_258112']['Setting']['_etc_security_pwquality_conf_Line'] = 'difok = 8'

# R-258113 RHEL-09-611120
default['rhel9STIG']['stigrule_258113']['Manage'] = true
default['rhel9STIG']['stigrule_258113']['Title'] = "RHEL 9 must require the maximum number of repeating characters of the same character class be limited to four when passwords are changed."
default['rhel9STIG']['stigrule_258113']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258113']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258113']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*maxclassrepeat'
default['rhel9STIG']['stigrule_258113']['Setting']['_etc_security_pwquality_conf_Line'] = 'maxclassrepeat = 4'

# R-258114 RHEL-09-611125
default['rhel9STIG']['stigrule_258114']['Manage'] = true
default['rhel9STIG']['stigrule_258114']['Title'] = "RHEL 9 must require the maximum number of repeating characters be limited to three when passwords are changed."
default['rhel9STIG']['stigrule_258114']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258114']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258114']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*maxrepeat'
default['rhel9STIG']['stigrule_258114']['Setting']['_etc_security_pwquality_conf_Line'] = 'maxrepeat = 3'

# R-258115 RHEL-09-611130
default['rhel9STIG']['stigrule_258115']['Manage'] = true
default['rhel9STIG']['stigrule_258115']['Title'] = "RHEL 9 must require the change of at least four character classes when passwords are changed."
default['rhel9STIG']['stigrule_258115']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258115']['Setting']['_etc_security_pwquality_conf_Path'] = '/etc/security/pwquality.conf'
default['rhel9STIG']['stigrule_258115']['Setting']['_etc_security_pwquality_conf_Regexp'] = '^\s*minclass'
default['rhel9STIG']['stigrule_258115']['Setting']['_etc_security_pwquality_conf_Line'] = 'minclass = 4'

# R-258116 RHEL-09-611135
default['rhel9STIG']['stigrule_258116']['Manage'] = true
default['rhel9STIG']['stigrule_258116']['Title'] = "RHEL 9 must be configured so that user and group account administration utilities are configured to store only encrypted representations of passwords."
default['rhel9STIG']['stigrule_258116']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258116']['Setting']['_etc_libuser_conf_Path'] = '/etc/libuser.conf'
default['rhel9STIG']['stigrule_258116']['Setting']['_etc_libuser_conf_Section'] = 'defaults'
default['rhel9STIG']['stigrule_258116']['Setting']['_etc_libuser_conf_Option'] = 'crypt_style'
default['rhel9STIG']['stigrule_258116']['Setting']['_etc_libuser_conf_Value'] = "sha512"

# R-258117 RHEL-09-611140
default['rhel9STIG']['stigrule_258117']['Manage'] = true
default['rhel9STIG']['stigrule_258117']['Title'] = "RHEL 9 must be configured to use the shadow file to store only encrypted representations of passwords."
default['rhel9STIG']['stigrule_258117']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258117']['Setting']['_etc_login_defs_Path'] = '/etc/login.defs'
default['rhel9STIG']['stigrule_258117']['Setting']['_etc_login_defs_Regexp'] = '^ENCRYPT_METHOD'
default['rhel9STIG']['stigrule_258117']['Setting']['_etc_login_defs_Line'] = 'ENCRYPT_METHOD SHA512'

# R-258121 RHEL-09-611160
default['rhel9STIG']['stigrule_258121']['Manage'] = true
default['rhel9STIG']['stigrule_258121']['Title'] = "RHEL 9 must use the common access card (CAC) smart card driver."
default['rhel9STIG']['stigrule_258121']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258121']['Setting']['_etc_opensc_conf_Path'] = '/etc/opensc.conf'
default['rhel9STIG']['stigrule_258121']['Setting']['_etc_opensc_conf_Regexp'] = '^\s*card_drivers\s*='
default['rhel9STIG']['stigrule_258121']['Setting']['_etc_opensc_conf_Line'] = 'card_drivers = cac;'

# R-258122 RHEL-09-611165
default['rhel9STIG']['stigrule_258122']['Manage'] = true
default['rhel9STIG']['stigrule_258122']['Title'] = "RHEL 9 must enable certificate based smart card authentication."
default['rhel9STIG']['stigrule_258122']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258122']['Setting']['_etc_sssd_sssd_conf_Path'] = '/etc/sssd/sssd.conf'
default['rhel9STIG']['stigrule_258122']['Setting']['_etc_sssd_sssd_conf_Section'] = 'pam'
default['rhel9STIG']['stigrule_258122']['Setting']['_etc_sssd_sssd_conf_Option'] = 'pam_cert_auth'
default['rhel9STIG']['stigrule_258122']['Setting']['_etc_sssd_sssd_conf_Value'] = "True"

# R-258124 RHEL-09-611175
default['rhel9STIG']['stigrule_258124']['Manage'] = true
default['rhel9STIG']['stigrule_258124']['Title'] = "RHEL 9 must have the pcsc-lite package installed."
default['rhel9STIG']['stigrule_258124']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258124']['Setting']['pcsc_lite_PackageName'] = 'pcsc-lite'
default['rhel9STIG']['stigrule_258124']['Setting']['pcsc_lite_Action'] = :install

# R-258125 RHEL-09-611180
default['rhel9STIG']['stigrule_258125']['Manage'] = true
default['rhel9STIG']['stigrule_258125']['Title'] = "The pcscd service on RHEL 9 must be active."
default['rhel9STIG']['stigrule_258125']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258125']['Setting']['pcscd_enable_ServiceName'] = 'pcscd'
default['rhel9STIG']['stigrule_258125']['Setting']['pcscd_enable_Action'] = :enable

default['rhel9STIG']['stigrule_258125']['Setting']['pcscd_start_ServiceName'] = 'pcscd'
default['rhel9STIG']['stigrule_258125']['Setting']['pcscd_start_Action'] = :start

# R-258126 RHEL-09-611185
default['rhel9STIG']['stigrule_258126']['Manage'] = true
default['rhel9STIG']['stigrule_258126']['Title'] = "RHEL 9 must have the opensc package installed."
default['rhel9STIG']['stigrule_258126']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258126']['Setting']['opensc_PackageName'] = 'opensc'
default['rhel9STIG']['stigrule_258126']['Setting']['opensc_Action'] = :install

# R-258128 RHEL-09-611195
default['rhel9STIG']['stigrule_258128']['Manage'] = true
default['rhel9STIG']['stigrule_258128']['Title'] = "RHEL 9 must require authentication to access emergency mode."
default['rhel9STIG']['stigrule_258128']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258128']['Setting']['mkdir__p__etc_systemd_system_emergency_service_d_Command'] = "mkdir -p /etc/systemd/system/emergency.service.d"

default['rhel9STIG']['stigrule_258128']['Setting']['_etc_systemd_system_emergency_service_d_emergency_service_conf_Path'] = '/etc/systemd/system/emergency.service.d/emergency.service.conf'
default['rhel9STIG']['stigrule_258128']['Setting']['_etc_systemd_system_emergency_service_d_emergency_service_conf_Content'] = '[Service]
ExecStart=
ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency
'

default['rhel9STIG']['stigrule_258128']['Setting']['systemctl_daemon_reload_Command'] = "systemctl daemon-reload"

# R-258133 RHEL-09-631020
default['rhel9STIG']['stigrule_258133']['Manage'] = true
default['rhel9STIG']['stigrule_258133']['Title'] = "RHEL 9 must prohibit the use of cached authenticators after one day."
default['rhel9STIG']['stigrule_258133']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258133']['Setting']['_etc_sssd_sssd_conf_Path'] = '/etc/sssd/sssd.conf'
default['rhel9STIG']['stigrule_258133']['Setting']['_etc_sssd_sssd_conf_Section'] = 'pam'
default['rhel9STIG']['stigrule_258133']['Setting']['_etc_sssd_sssd_conf_Option'] = 'offline_credentials_expiration'
default['rhel9STIG']['stigrule_258133']['Setting']['_etc_sssd_sssd_conf_Value'] = "1"

# R-258140 RHEL-09-652010
default['rhel9STIG']['stigrule_258140']['Manage'] = true
default['rhel9STIG']['stigrule_258140']['Title'] = "RHEL 9 must have the rsyslog package installed."
default['rhel9STIG']['stigrule_258140']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258140']['Setting']['rsyslog_PackageName'] = 'rsyslog'
default['rhel9STIG']['stigrule_258140']['Setting']['rsyslog_Action'] = :install

# R-258141 RHEL-09-652015
default['rhel9STIG']['stigrule_258141']['Manage'] = true
default['rhel9STIG']['stigrule_258141']['Title'] = "RHEL 9 must have the packages required for encrypting offloaded audit logs installed."
default['rhel9STIG']['stigrule_258141']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258141']['Setting']['rsyslog_gnutls_PackageName'] = 'rsyslog-gnutls'
default['rhel9STIG']['stigrule_258141']['Setting']['rsyslog_gnutls_Action'] = :install

# R-258142 RHEL-09-652020
default['rhel9STIG']['stigrule_258142']['Manage'] = true
default['rhel9STIG']['stigrule_258142']['Title'] = "The rsyslog service on RHEL 9 must be active."
default['rhel9STIG']['stigrule_258142']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258142']['Setting']['rsyslog_enable_ServiceName'] = 'rsyslog'
default['rhel9STIG']['stigrule_258142']['Setting']['rsyslog_enable_Action'] = :enable

default['rhel9STIG']['stigrule_258142']['Setting']['rsyslog_start_ServiceName'] = 'rsyslog'
default['rhel9STIG']['stigrule_258142']['Setting']['rsyslog_start_Action'] = :start

# R-258144 RHEL-09-652030
default['rhel9STIG']['stigrule_258144']['Manage'] = true
default['rhel9STIG']['stigrule_258144']['Title'] = "All RHEL 9 remote access methods must be monitored."
default['rhel9STIG']['stigrule_258144']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258144']['Setting']['_etc_rsyslog_conf_Path'] = '/etc/rsyslog.conf'
default['rhel9STIG']['stigrule_258144']['Setting']['_etc_rsyslog_conf_Regexp'] = '^(?:(?:auth|authpriv|daemon)\.\*;?)+\s+\S+'
default['rhel9STIG']['stigrule_258144']['Setting']['_etc_rsyslog_conf_Line'] = 'auth.*;authpriv.*;daemon.*                              /var/log/secure'

# R-258146 RHEL-09-652040
default['rhel9STIG']['stigrule_258146']['Manage'] = true
default['rhel9STIG']['stigrule_258146']['Title'] = "RHEL 9 must authenticate the remote logging server for offloading audit logs via rsyslog."
default['rhel9STIG']['stigrule_258146']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258146']['Setting']['_etc_rsyslog_conf_Path'] = '/etc/rsyslog.conf'
default['rhel9STIG']['stigrule_258146']['Setting']['_etc_rsyslog_conf_Regexp'] = '^\s*\$ActionSendStreamDriverAuthMode\s+\S+'
default['rhel9STIG']['stigrule_258146']['Setting']['_etc_rsyslog_conf_Line'] = '$ActionSendStreamDriverAuthMode x509/name'

# R-258147 RHEL-09-652045
default['rhel9STIG']['stigrule_258147']['Manage'] = true
default['rhel9STIG']['stigrule_258147']['Title'] = "RHEL 9 must encrypt the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog."
default['rhel9STIG']['stigrule_258147']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258147']['Setting']['_etc_rsyslog_conf_Path'] = '/etc/rsyslog.conf'
default['rhel9STIG']['stigrule_258147']['Setting']['_etc_rsyslog_conf_Regexp'] = '^\s*\$ActionSendStreamDriverMode\s+\d+'
default['rhel9STIG']['stigrule_258147']['Setting']['_etc_rsyslog_conf_Line'] = '$ActionSendStreamDriverMode 1'

# R-258148 RHEL-09-652050
default['rhel9STIG']['stigrule_258148']['Manage'] = true
default['rhel9STIG']['stigrule_258148']['Title'] = "RHEL 9 must encrypt via the gtls driver the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog."
default['rhel9STIG']['stigrule_258148']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258148']['Setting']['_etc_rsyslog_conf_Path'] = '/etc/rsyslog.conf'
default['rhel9STIG']['stigrule_258148']['Setting']['_etc_rsyslog_conf_Regexp'] = '^\s*\$DefaultNetstreamDriver\s+\w+'
default['rhel9STIG']['stigrule_258148']['Setting']['_etc_rsyslog_conf_Line'] = '$DefaultNetstreamDriver gtls'

# R-258150 RHEL-09-652060
default['rhel9STIG']['stigrule_258150']['Manage'] = true
default['rhel9STIG']['stigrule_258150']['Title'] = "RHEL 9 must use cron logging."
default['rhel9STIG']['stigrule_258150']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258150']['Setting']['_etc_rsyslog_conf_Path'] = '/etc/rsyslog.conf'
default['rhel9STIG']['stigrule_258150']['Setting']['_etc_rsyslog_conf_Regexp'] = '^cron\.\*\s+\S+'
default['rhel9STIG']['stigrule_258150']['Setting']['_etc_rsyslog_conf_Line'] = 'cron.*                                                  /var/log/cron'

# R-258151 RHEL-09-653010
default['rhel9STIG']['stigrule_258151']['Manage'] = true
default['rhel9STIG']['stigrule_258151']['Title'] = "RHEL 9 audit package must be installed."
default['rhel9STIG']['stigrule_258151']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258151']['Setting']['audit_PackageName'] = 'audit'
default['rhel9STIG']['stigrule_258151']['Setting']['audit_Action'] = :install

# R-258152 RHEL-09-653015
default['rhel9STIG']['stigrule_258152']['Manage'] = true
default['rhel9STIG']['stigrule_258152']['Title'] = "RHEL 9 audit service must be enabled."
default['rhel9STIG']['stigrule_258152']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258152']['Setting']['auditd_enable_ServiceName'] = 'auditd'
default['rhel9STIG']['stigrule_258152']['Setting']['auditd_enable_Action'] = :enable

default['rhel9STIG']['stigrule_258152']['Setting']['auditd_start_ServiceName'] = 'auditd'
default['rhel9STIG']['stigrule_258152']['Setting']['auditd_start_Action'] = :start

# R-258153 RHEL-09-653020
default['rhel9STIG']['stigrule_258153']['Manage'] = true
default['rhel9STIG']['stigrule_258153']['Title'] = "RHEL 9 audit system must take appropriate action when an error writing to the audit storage volume occurs."
default['rhel9STIG']['stigrule_258153']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258153']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258153']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^disk_error_action = '
default['rhel9STIG']['stigrule_258153']['Setting']['_etc_audit_auditd_conf_Line'] = 'disk_error_action = HALT'

# R-258154 RHEL-09-653025
default['rhel9STIG']['stigrule_258154']['Manage'] = true
default['rhel9STIG']['stigrule_258154']['Title'] = "RHEL 9 audit system must take appropriate action when the audit storage volume is full."
default['rhel9STIG']['stigrule_258154']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258154']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258154']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^disk_full_action = '
default['rhel9STIG']['stigrule_258154']['Setting']['_etc_audit_auditd_conf_Line'] = 'disk_full_action = HALT'

# R-258156 RHEL-09-653035
default['rhel9STIG']['stigrule_258156']['Manage'] = true
default['rhel9STIG']['stigrule_258156']['Title'] = "RHEL 9 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
default['rhel9STIG']['stigrule_258156']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258156']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258156']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^space_left = '
default['rhel9STIG']['stigrule_258156']['Setting']['_etc_audit_auditd_conf_Line'] = 'space_left = 25%'

# R-258157 RHEL-09-653040
default['rhel9STIG']['stigrule_258157']['Manage'] = true
default['rhel9STIG']['stigrule_258157']['Title'] = "RHEL 9 must notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent utilization."
default['rhel9STIG']['stigrule_258157']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258157']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258157']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^space_left_action = '
default['rhel9STIG']['stigrule_258157']['Setting']['_etc_audit_auditd_conf_Line'] = 'space_left_action = email'

# R-258158 RHEL-09-653045
default['rhel9STIG']['stigrule_258158']['Manage'] = true
default['rhel9STIG']['stigrule_258158']['Title'] = "RHEL 9 must take action when allocated audit record storage volume reaches 95 percent of the audit record storage capacity."
default['rhel9STIG']['stigrule_258158']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258158']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258158']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^admin_space_left = '
default['rhel9STIG']['stigrule_258158']['Setting']['_etc_audit_auditd_conf_Line'] = 'admin_space_left = 5%'

# R-258159 RHEL-09-653050
default['rhel9STIG']['stigrule_258159']['Manage'] = true
default['rhel9STIG']['stigrule_258159']['Title'] = "RHEL 9 must take action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity."
default['rhel9STIG']['stigrule_258159']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258159']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258159']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^admin_space_left_action = '
default['rhel9STIG']['stigrule_258159']['Setting']['_etc_audit_auditd_conf_Line'] = 'admin_space_left_action = single'

# R-258160 RHEL-09-653055
default['rhel9STIG']['stigrule_258160']['Manage'] = true
default['rhel9STIG']['stigrule_258160']['Title'] = "RHEL 9 audit system must take appropriate action when the audit files have reached maximum size."
default['rhel9STIG']['stigrule_258160']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258160']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258160']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^max_log_file_action = '
default['rhel9STIG']['stigrule_258160']['Setting']['_etc_audit_auditd_conf_Line'] = 'max_log_file_action = ROTATE'

# R-258161 RHEL-09-653060
default['rhel9STIG']['stigrule_258161']['Manage'] = true
default['rhel9STIG']['stigrule_258161']['Title'] = "RHEL 9 must label all offloaded audit logs before sending them to the central log server."
default['rhel9STIG']['stigrule_258161']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258161']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258161']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^name_format = '
default['rhel9STIG']['stigrule_258161']['Setting']['_etc_audit_auditd_conf_Line'] = 'name_format = hostname'

# R-258162 RHEL-09-653065
default['rhel9STIG']['stigrule_258162']['Manage'] = true
default['rhel9STIG']['stigrule_258162']['Title'] = "RHEL 9 must take appropriate action when the internal event queue is full."
default['rhel9STIG']['stigrule_258162']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258162']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258162']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^overflow_action = '
default['rhel9STIG']['stigrule_258162']['Setting']['_etc_audit_auditd_conf_Line'] = 'overflow_action = syslog'

# R-258163 RHEL-09-653070
default['rhel9STIG']['stigrule_258163']['Manage'] = true
default['rhel9STIG']['stigrule_258163']['Title'] = "RHEL 9 System Administrator (SA) and/or information system security officer (ISSO) (at a minimum) must be alerted of an audit processing failure event."
default['rhel9STIG']['stigrule_258163']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258163']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258163']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^action_mail_acct = '
default['rhel9STIG']['stigrule_258163']['Setting']['_etc_audit_auditd_conf_Line'] = 'action_mail_acct = root'

# R-258164 RHEL-09-653075
default['rhel9STIG']['stigrule_258164']['Manage'] = true
default['rhel9STIG']['stigrule_258164']['Title'] = "RHEL 9 audit system must audit local events."
default['rhel9STIG']['stigrule_258164']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258164']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258164']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^local_events = '
default['rhel9STIG']['stigrule_258164']['Setting']['_etc_audit_auditd_conf_Line'] = 'local_events = yes'

# R-258168 RHEL-09-653095
default['rhel9STIG']['stigrule_258168']['Manage'] = true
default['rhel9STIG']['stigrule_258168']['Title'] = "RHEL 9 must periodically flush audit records to disk to prevent the loss of audit records."
default['rhel9STIG']['stigrule_258168']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258168']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258168']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^freq = '
default['rhel9STIG']['stigrule_258168']['Setting']['_etc_audit_auditd_conf_Line'] = 'freq = 100'

# R-258169 RHEL-09-653100
default['rhel9STIG']['stigrule_258169']['Manage'] = true
default['rhel9STIG']['stigrule_258169']['Title'] = "RHEL 9 must produce audit records containing information to establish the identity of any individual or process associated with the event."
default['rhel9STIG']['stigrule_258169']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258169']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258169']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^log_format = '
default['rhel9STIG']['stigrule_258169']['Setting']['_etc_audit_auditd_conf_Line'] = 'log_format = ENRICHED'

# R-258170 RHEL-09-653105
default['rhel9STIG']['stigrule_258170']['Manage'] = true
default['rhel9STIG']['stigrule_258170']['Title'] = "RHEL 9 must write audit records to disk."
default['rhel9STIG']['stigrule_258170']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258170']['Setting']['_etc_audit_auditd_conf_Path'] = '/etc/audit/auditd.conf'
default['rhel9STIG']['stigrule_258170']['Setting']['_etc_audit_auditd_conf_Regexp'] = '^write_logs = '
default['rhel9STIG']['stigrule_258170']['Setting']['_etc_audit_auditd_conf_Line'] = 'write_logs = yes'

# R-258175 RHEL-09-653130
default['rhel9STIG']['stigrule_258175']['Manage'] = true
default['rhel9STIG']['stigrule_258175']['Title'] = "RHEL 9 audispd-plugins package must be installed."
default['rhel9STIG']['stigrule_258175']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258175']['Setting']['audispd_plugins_PackageName'] = 'audispd-plugins'
default['rhel9STIG']['stigrule_258175']['Setting']['audispd_plugins_Action'] = :install

# R-258176 RHEL-09-654010
default['rhel9STIG']['stigrule_258176']['Manage'] = true
default['rhel9STIG']['stigrule_258176']['Title'] = "RHEL 9 must audit uses of the \"execve\" system call."
default['rhel9STIG']['stigrule_258176']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b32_Regexp'] = '^-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv$'
default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b32_Line'] = '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv'

default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b64_Regexp'] = '^-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv$'
default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b64_Line'] = '-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv'

default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b32_Regexp'] = '^-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv$'
default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b32_Line'] = '-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv'

default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b64_Regexp'] = '^-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv$'
default['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b64_Line'] = '-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv'

# R-258177 RHEL-09-654015
default['rhel9STIG']['stigrule_258177']['Manage'] = true
default['rhel9STIG']['stigrule_258177']['Title'] = "RHEL 9 must audit all uses of the chmod, fchmod, and fchmodat system calls."
default['rhel9STIG']['stigrule_258177']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b32_Regexp'] = '^-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod$'
default['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b32_Line'] = '-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod'

default['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b64_Regexp'] = '^-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod$'
default['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b64_Line'] = '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod'

# R-258178 RHEL-09-654020
default['rhel9STIG']['stigrule_258178']['Manage'] = true
default['rhel9STIG']['stigrule_258178']['Title'] = "RHEL 9 must audit all uses of the chown, fchown, fchownat, and lchown system calls."
default['rhel9STIG']['stigrule_258178']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b32_Regexp'] = '^-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod$'
default['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b32_Line'] = '-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod'

default['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b64_Regexp'] = '^-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod$'
default['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b64_Line'] = '-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod'

# R-258179 RHEL-09-654025
default['rhel9STIG']['stigrule_258179']['Manage'] = true
default['rhel9STIG']['stigrule_258179']['Title'] = "RHEL 9 must audit all uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls."
default['rhel9STIG']['stigrule_258179']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_unset_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_unset_Regexp'] = '^-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod$'
default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_unset_Line'] = '-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod'

default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_unset_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_unset_Regexp'] = '^-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod$'
default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_unset_Line'] = '-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod'

default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_Regexp'] = '^-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod$'
default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_Line'] = '-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod'

default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_Regexp'] = '^-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod$'
default['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_Line'] = '-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod'

# R-258180 RHEL-09-654030
default['rhel9STIG']['stigrule_258180']['Manage'] = true
default['rhel9STIG']['stigrule_258180']['Title'] = "RHEL 9 must audit all uses of umount system calls."
default['rhel9STIG']['stigrule_258180']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258180']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_umount_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258180']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_umount_Regexp'] = '^-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount$'
default['rhel9STIG']['stigrule_258180']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_umount_Line'] = '-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount'

# R-258181 RHEL-09-654035
default['rhel9STIG']['stigrule_258181']['Manage'] = true
default['rhel9STIG']['stigrule_258181']['Title'] = "RHEL 9 must audit all uses of the chacl command."
default['rhel9STIG']['stigrule_258181']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258181']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chacl_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258181']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chacl_Regexp'] = '^-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod$'
default['rhel9STIG']['stigrule_258181']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chacl_Line'] = '-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod'

# R-258182 RHEL-09-654040
default['rhel9STIG']['stigrule_258182']['Manage'] = true
default['rhel9STIG']['stigrule_258182']['Title'] = "RHEL 9 must audit all uses of the setfacl command."
default['rhel9STIG']['stigrule_258182']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258182']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_setfacl_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258182']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_setfacl_Regexp'] = '^-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod$'
default['rhel9STIG']['stigrule_258182']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_setfacl_Line'] = '-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod'

# R-258183 RHEL-09-654045
default['rhel9STIG']['stigrule_258183']['Manage'] = true
default['rhel9STIG']['stigrule_258183']['Title'] = "RHEL 9 must audit all uses of the chcon command."
default['rhel9STIG']['stigrule_258183']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258183']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chcon_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258183']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chcon_Regexp'] = '^-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod$'
default['rhel9STIG']['stigrule_258183']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chcon_Line'] = '-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod'

# R-258184 RHEL-09-654050
default['rhel9STIG']['stigrule_258184']['Manage'] = true
default['rhel9STIG']['stigrule_258184']['Title'] = "RHEL 9 must audit all uses of the semanage command."
default['rhel9STIG']['stigrule_258184']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258184']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_semanage_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258184']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_semanage_Regexp'] = '^-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update$'
default['rhel9STIG']['stigrule_258184']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_semanage_Line'] = '-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update'

# R-258185 RHEL-09-654055
default['rhel9STIG']['stigrule_258185']['Manage'] = true
default['rhel9STIG']['stigrule_258185']['Title'] = "RHEL 9 must audit all uses of the setfiles command."
default['rhel9STIG']['stigrule_258185']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258185']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setfiles_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258185']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setfiles_Regexp'] = '^-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update$'
default['rhel9STIG']['stigrule_258185']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setfiles_Line'] = '-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update'

# R-258186 RHEL-09-654060
default['rhel9STIG']['stigrule_258186']['Manage'] = true
default['rhel9STIG']['stigrule_258186']['Title'] = "RHEL 9 must audit all uses of the setsebool command."
default['rhel9STIG']['stigrule_258186']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258186']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setsebool_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258186']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setsebool_Regexp'] = '^-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged$'
default['rhel9STIG']['stigrule_258186']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setsebool_Line'] = '-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged'

# R-258187 RHEL-09-654065
default['rhel9STIG']['stigrule_258187']['Manage'] = true
default['rhel9STIG']['stigrule_258187']['Title'] = "RHEL 9 must audit all uses of the rename, unlink, rmdir, renameat, and unlinkat system calls."
default['rhel9STIG']['stigrule_258187']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b32_Regexp'] = '^-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete$'
default['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b32_Line'] = '-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete'

default['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b64_Regexp'] = '^-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete$'
default['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b64_Line'] = '-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete'

# R-258188 RHEL-09-654070
default['rhel9STIG']['stigrule_258188']['Manage'] = true
default['rhel9STIG']['stigrule_258188']['Title'] = "RHEL 9 must audit all uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls."
default['rhel9STIG']['stigrule_258188']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b32_Regexp'] = '^-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access$'
default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b32_Line'] = '-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access'

default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b64_Regexp'] = '^-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access$'
default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b64_Line'] = '-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access'

default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b32_Regexp'] = '^-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access$'
default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b32_Line'] = '-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access'

default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b64_Regexp'] = '^-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access$'
default['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b64_Line'] = '-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access'

# R-258189 RHEL-09-654075
default['rhel9STIG']['stigrule_258189']['Manage'] = true
default['rhel9STIG']['stigrule_258189']['Title'] = "RHEL 9 must audit all uses of the delete_module system call."
default['rhel9STIG']['stigrule_258189']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b32_Regexp'] = '^-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng$'
default['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b32_Line'] = '-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng'

default['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b64_Regexp'] = '^-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng$'
default['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b64_Line'] = '-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng'

# R-258190 RHEL-09-654080
default['rhel9STIG']['stigrule_258190']['Manage'] = true
default['rhel9STIG']['stigrule_258190']['Title'] = "RHEL 9 must audit all uses of the init_module and finit_module system calls."
default['rhel9STIG']['stigrule_258190']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b32_Regexp'] = '^-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng$'
default['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b32_Line'] = '-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng'

default['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b64_Regexp'] = '^-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng$'
default['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b64_Line'] = '-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng'

# R-258191 RHEL-09-654085
default['rhel9STIG']['stigrule_258191']['Manage'] = true
default['rhel9STIG']['stigrule_258191']['Title'] = "RHEL 9 must audit all uses of the chage command."
default['rhel9STIG']['stigrule_258191']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258191']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chage_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258191']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chage_Regexp'] = '^-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage$'
default['rhel9STIG']['stigrule_258191']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chage_Line'] = '-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage'

# R-258192 RHEL-09-654090
default['rhel9STIG']['stigrule_258192']['Manage'] = true
default['rhel9STIG']['stigrule_258192']['Title'] = "RHEL 9 must audit all uses of the chsh command."
default['rhel9STIG']['stigrule_258192']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258192']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chsh_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258192']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chsh_Regexp'] = '^-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd$'
default['rhel9STIG']['stigrule_258192']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chsh_Line'] = '-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd'

# R-258193 RHEL-09-654095
default['rhel9STIG']['stigrule_258193']['Manage'] = true
default['rhel9STIG']['stigrule_258193']['Title'] = "RHEL 9 must audit all uses of the crontab command."
default['rhel9STIG']['stigrule_258193']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258193']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_crontab_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258193']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_crontab_Regexp'] = '^-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab$'
default['rhel9STIG']['stigrule_258193']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_crontab_Line'] = '-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab'

# R-258194 RHEL-09-654100
default['rhel9STIG']['stigrule_258194']['Manage'] = true
default['rhel9STIG']['stigrule_258194']['Title'] = "RHEL 9 must audit all uses of the gpasswd command."
default['rhel9STIG']['stigrule_258194']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/usr/bin/gpasswd -F perm=x -k identity$'
default['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b32_Line'] = '-a always,exit -F arch=b32 -F path=/usr/bin/gpasswd -F perm=x -k identity'

default['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/usr/bin/gpasswd -F perm=x -k identity$'
default['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b64_Line'] = '-a always,exit -F arch=b64 -F path=/usr/bin/gpasswd -F perm=x -k identity'

# R-258195 RHEL-09-654105
default['rhel9STIG']['stigrule_258195']['Manage'] = true
default['rhel9STIG']['stigrule_258195']['Title'] = "RHEL 9 must audit all uses of the kmod command."
default['rhel9STIG']['stigrule_258195']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258195']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_kmod_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258195']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_kmod_Regexp'] = '^-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules$'
default['rhel9STIG']['stigrule_258195']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_kmod_Line'] = '-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules'

# R-258196 RHEL-09-654110
default['rhel9STIG']['stigrule_258196']['Manage'] = true
default['rhel9STIG']['stigrule_258196']['Title'] = "RHEL 9 must audit all uses of the newgrp command."
default['rhel9STIG']['stigrule_258196']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258196']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_newgrp_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258196']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_newgrp_Regexp'] = '^-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd$'
default['rhel9STIG']['stigrule_258196']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_newgrp_Line'] = '-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd'

# R-258197 RHEL-09-654115
default['rhel9STIG']['stigrule_258197']['Manage'] = true
default['rhel9STIG']['stigrule_258197']['Title'] = "RHEL 9 must audit all uses of the pam_timestamp_check command."
default['rhel9STIG']['stigrule_258197']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258197']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_pam_timestamp_check_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258197']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_pam_timestamp_check_Regexp'] = '^-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam_timestamp_check$'
default['rhel9STIG']['stigrule_258197']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_pam_timestamp_check_Line'] = '-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam_timestamp_check'

# R-258198 RHEL-09-654120
default['rhel9STIG']['stigrule_258198']['Manage'] = true
default['rhel9STIG']['stigrule_258198']['Title'] = "RHEL 9 must audit all uses of the passwd command."
default['rhel9STIG']['stigrule_258198']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/usr/bin/passwd -F perm=x -k identity$'
default['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b32_Line'] = '-a always,exit -F arch=b32 -F path=/usr/bin/passwd -F perm=x -k identity'

default['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/usr/bin/passwd -F perm=x -k identity$'
default['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b64_Line'] = '-a always,exit -F arch=b64 -F path=/usr/bin/passwd -F perm=x -k identity'

# R-258199 RHEL-09-654125
default['rhel9STIG']['stigrule_258199']['Manage'] = true
default['rhel9STIG']['stigrule_258199']['Title'] = "RHEL 9 must audit all uses of the postdrop command."
default['rhel9STIG']['stigrule_258199']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258199']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postdrop_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258199']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postdrop_Regexp'] = '^-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update$'
default['rhel9STIG']['stigrule_258199']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postdrop_Line'] = '-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update'

# R-258200 RHEL-09-654130
default['rhel9STIG']['stigrule_258200']['Manage'] = true
default['rhel9STIG']['stigrule_258200']['Title'] = "RHEL 9 must audit all uses of the postqueue command."
default['rhel9STIG']['stigrule_258200']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258200']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postqueue_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258200']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postqueue_Regexp'] = '^-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update$'
default['rhel9STIG']['stigrule_258200']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postqueue_Line'] = '-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update'

# R-258201 RHEL-09-654135
default['rhel9STIG']['stigrule_258201']['Manage'] = true
default['rhel9STIG']['stigrule_258201']['Title'] = "RHEL 9 must audit all uses of the ssh-agent command."
default['rhel9STIG']['stigrule_258201']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258201']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_ssh_agent_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258201']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_ssh_agent_Regexp'] = '^-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh$'
default['rhel9STIG']['stigrule_258201']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_ssh_agent_Line'] = '-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh'

# R-258202 RHEL-09-654140
default['rhel9STIG']['stigrule_258202']['Manage'] = true
default['rhel9STIG']['stigrule_258202']['Title'] = "RHEL 9 must audit all uses of the ssh-keysign command."
default['rhel9STIG']['stigrule_258202']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258202']['Setting']['_etc_audit_rules_d_audit_rules__usr_libexec_openssh_ssh_keysign_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258202']['Setting']['_etc_audit_rules_d_audit_rules__usr_libexec_openssh_ssh_keysign_Regexp'] = '^-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh$'
default['rhel9STIG']['stigrule_258202']['Setting']['_etc_audit_rules_d_audit_rules__usr_libexec_openssh_ssh_keysign_Line'] = '-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh'

# R-258203 RHEL-09-654145
default['rhel9STIG']['stigrule_258203']['Manage'] = true
default['rhel9STIG']['stigrule_258203']['Title'] = "RHEL 9 must audit all uses of the su command."
default['rhel9STIG']['stigrule_258203']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258203']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_su_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258203']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_su_Regexp'] = '^-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change$'
default['rhel9STIG']['stigrule_258203']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_su_Line'] = '-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change'

# R-258204 RHEL-09-654150
default['rhel9STIG']['stigrule_258204']['Manage'] = true
default['rhel9STIG']['stigrule_258204']['Title'] = "RHEL 9 must audit all uses of the sudo command."
default['rhel9STIG']['stigrule_258204']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258204']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudo_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258204']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudo_Regexp'] = '^-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd$'
default['rhel9STIG']['stigrule_258204']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudo_Line'] = '-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd'

# R-258205 RHEL-09-654155
default['rhel9STIG']['stigrule_258205']['Manage'] = true
default['rhel9STIG']['stigrule_258205']['Title'] = "RHEL 9 must audit all uses of the sudoedit command."
default['rhel9STIG']['stigrule_258205']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258205']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudoedit_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258205']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudoedit_Regexp'] = '^-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd$'
default['rhel9STIG']['stigrule_258205']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudoedit_Line'] = '-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd'

# R-258206 RHEL-09-654160
default['rhel9STIG']['stigrule_258206']['Manage'] = true
default['rhel9STIG']['stigrule_258206']['Title'] = "RHEL 9 must audit all uses of the unix_chkpwd command."
default['rhel9STIG']['stigrule_258206']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258206']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_chkpwd_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258206']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_chkpwd_Regexp'] = '^-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update$'
default['rhel9STIG']['stigrule_258206']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_chkpwd_Line'] = '-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update'

# R-258207 RHEL-09-654165
default['rhel9STIG']['stigrule_258207']['Manage'] = true
default['rhel9STIG']['stigrule_258207']['Title'] = "RHEL 9 must audit all uses of the unix_update command."
default['rhel9STIG']['stigrule_258207']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258207']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_update_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258207']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_update_Regexp'] = '^-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update$'
default['rhel9STIG']['stigrule_258207']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_update_Line'] = '-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update'

# R-258208 RHEL-09-654170
default['rhel9STIG']['stigrule_258208']['Manage'] = true
default['rhel9STIG']['stigrule_258208']['Title'] = "RHEL 9 must audit all uses of the userhelper command."
default['rhel9STIG']['stigrule_258208']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258208']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_userhelper_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258208']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_userhelper_Regexp'] = '^-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update$'
default['rhel9STIG']['stigrule_258208']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_userhelper_Line'] = '-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update'

# R-258209 RHEL-09-654175
default['rhel9STIG']['stigrule_258209']['Manage'] = true
default['rhel9STIG']['stigrule_258209']['Title'] = "RHEL 9 must audit all uses of the usermod command."
default['rhel9STIG']['stigrule_258209']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258209']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_usermod_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258209']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_usermod_Regexp'] = '^-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod$'
default['rhel9STIG']['stigrule_258209']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_usermod_Line'] = '-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod'

# R-258210 RHEL-09-654180
default['rhel9STIG']['stigrule_258210']['Manage'] = true
default['rhel9STIG']['stigrule_258210']['Title'] = "RHEL 9 must audit all uses of the mount command."
default['rhel9STIG']['stigrule_258210']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258210']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_mount_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258210']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_mount_Regexp'] = '^-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount$'
default['rhel9STIG']['stigrule_258210']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_mount_Line'] = '-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount'

# R-258211 RHEL-09-654185
default['rhel9STIG']['stigrule_258211']['Manage'] = true
default['rhel9STIG']['stigrule_258211']['Title'] = "Successful/unsuccessful uses of the init command in RHEL 9 must generate an audit record."
default['rhel9STIG']['stigrule_258211']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258211']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_init_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258211']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_init_Regexp'] = '^-a always,exit -F path=/usr/sbin/init -F perm=x -F auid>=1000 -F auid!=unset -k privileged-init$'
default['rhel9STIG']['stigrule_258211']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_init_Line'] = '-a always,exit -F path=/usr/sbin/init -F perm=x -F auid>=1000 -F auid!=unset -k privileged-init'

# R-258212 RHEL-09-654190
default['rhel9STIG']['stigrule_258212']['Manage'] = true
default['rhel9STIG']['stigrule_258212']['Title'] = "Successful/unsuccessful uses of the poweroff command in RHEL 9 must generate an audit record."
default['rhel9STIG']['stigrule_258212']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258212']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_poweroff_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258212']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_poweroff_Regexp'] = '^-a always,exit -F path=/usr/sbin/poweroff -F perm=x -F auid>=1000 -F auid!=unset -k privileged-poweroff$'
default['rhel9STIG']['stigrule_258212']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_poweroff_Line'] = '-a always,exit -F path=/usr/sbin/poweroff -F perm=x -F auid>=1000 -F auid!=unset -k privileged-poweroff'

# R-258213 RHEL-09-654195
default['rhel9STIG']['stigrule_258213']['Manage'] = true
default['rhel9STIG']['stigrule_258213']['Title'] = "Successful/unsuccessful uses of the reboot command in RHEL 9 must generate an audit record."
default['rhel9STIG']['stigrule_258213']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258213']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_reboot_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258213']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_reboot_Regexp'] = '^-a always,exit -F path=/usr/sbin/reboot -F perm=x -F auid>=1000 -F auid!=unset -k privileged-reboot$'
default['rhel9STIG']['stigrule_258213']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_reboot_Line'] = '-a always,exit -F path=/usr/sbin/reboot -F perm=x -F auid>=1000 -F auid!=unset -k privileged-reboot'

# R-258214 RHEL-09-654200
default['rhel9STIG']['stigrule_258214']['Manage'] = true
default['rhel9STIG']['stigrule_258214']['Title'] = "Successful/unsuccessful uses of the shutdown command in RHEL 9 must generate an audit record."
default['rhel9STIG']['stigrule_258214']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258214']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_shutdown_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258214']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_shutdown_Regexp'] = '^-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown$'
default['rhel9STIG']['stigrule_258214']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_shutdown_Line'] = '-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown'

# R-258217 RHEL-09-654215
default['rhel9STIG']['stigrule_258217']['Manage'] = true
default['rhel9STIG']['stigrule_258217']['Title'] = "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers."
default['rhel9STIG']['stigrule_258217']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b32_Line'] = '-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -k identity'

default['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b64_Line'] = '-a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -k identity'

# R-258218 RHEL-09-654220
default['rhel9STIG']['stigrule_258218']['Manage'] = true
default['rhel9STIG']['stigrule_258218']['Title'] = "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.d/ directory."
default['rhel9STIG']['stigrule_258218']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/etc/sudoers.d -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b32_Line'] = '-a always,exit -F arch=b32 -F path=/etc/sudoers.d -F perm=wa -k identity'

default['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/etc/sudoers.d -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b64_Line'] = '-a always,exit -F arch=b64 -F path=/etc/sudoers.d -F perm=wa -k identity'

# R-258219 RHEL-09-654225
default['rhel9STIG']['stigrule_258219']['Manage'] = true
default['rhel9STIG']['stigrule_258219']['Title'] = "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
default['rhel9STIG']['stigrule_258219']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/etc/group -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b32_Line'] = '-a always,exit -F arch=b32 -F path=/etc/group -F perm=wa -k identity'

default['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/etc/group -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b64_Line'] = '-a always,exit -F arch=b64 -F path=/etc/group -F perm=wa -k identity'

# R-258220 RHEL-09-654230
default['rhel9STIG']['stigrule_258220']['Manage'] = true
default['rhel9STIG']['stigrule_258220']['Title'] = "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
default['rhel9STIG']['stigrule_258220']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/etc/gshadow -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b32_Line'] = '-a always,exit -F arch=b32 -F path=/etc/gshadow -F perm=wa -k identity'

default['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/etc/gshadow -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b64_Line'] = '-a always,exit -F arch=b64 -F path=/etc/gshadow -F perm=wa -k identity'

# R-258221 RHEL-09-654235
default['rhel9STIG']['stigrule_258221']['Manage'] = true
default['rhel9STIG']['stigrule_258221']['Title'] = "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd."
default['rhel9STIG']['stigrule_258221']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/etc/security/opasswd -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b32_Line'] = '-a always,exit -F arch=b32 -F path=/etc/security/opasswd -F perm=wa -k identity'

default['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/etc/security/opasswd -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b64_Line'] = '-a always,exit -F arch=b64 -F path=/etc/security/opasswd -F perm=wa -k identity'

# R-258222 RHEL-09-654240
default['rhel9STIG']['stigrule_258222']['Manage'] = true
default['rhel9STIG']['stigrule_258222']['Title'] = "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
default['rhel9STIG']['stigrule_258222']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b32_Line'] = '-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -k identity'

default['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b64_Line'] = '-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity'

# R-258223 RHEL-09-654245
default['rhel9STIG']['stigrule_258223']['Manage'] = true
default['rhel9STIG']['stigrule_258223']['Title'] = "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
default['rhel9STIG']['stigrule_258223']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/etc/shadow -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b32_Line'] = '-a always,exit -F arch=b32 -F path=/etc/shadow -F perm=wa -k identity'

default['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -k identity$'
default['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b64_Line'] = '-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -k identity'

# R-258224 RHEL-09-654250
default['rhel9STIG']['stigrule_258224']['Manage'] = true
default['rhel9STIG']['stigrule_258224']['Title'] = "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/faillock."
default['rhel9STIG']['stigrule_258224']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins$'
default['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b32_Line'] = '-a always,exit -F arch=b32 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins'

default['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins$'
default['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b64_Line'] = '-a always,exit -F arch=b64 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins'

# R-258225 RHEL-09-654255
default['rhel9STIG']['stigrule_258225']['Manage'] = true
default['rhel9STIG']['stigrule_258225']['Title'] = "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/lastlog."
default['rhel9STIG']['stigrule_258225']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b32_Regexp'] = '^-a always,exit -F arch=b32 -F path=/var/log/lastlog -F perm=wa -F auid>=1000 -F auid!=unset -k logins$'
default['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b32_Line'] = '-a always,exit -F arch=b32 -F path=/var/log/lastlog -F perm=wa -F auid>=1000 -F auid!=unset -k logins'

default['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b64_Regexp'] = '^-a always,exit -F arch=b64 -F path=/var/log/lastlog -F perm=wa -F auid>=1000 -F auid!=unset -k logins$'
default['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b64_Line'] = '-a always,exit -F arch=b64 -F path=/var/log/lastlog -F perm=wa -F auid>=1000 -F auid!=unset -k logins'

# R-258227 RHEL-09-654265
default['rhel9STIG']['stigrule_258227']['Manage'] = true
default['rhel9STIG']['stigrule_258227']['Title'] = "RHEL 9 must take appropriate action when a critical audit processing failure occurs."
default['rhel9STIG']['stigrule_258227']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258227']['Setting']['_etc_audit_rules_d_audit_rules_f2_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258227']['Setting']['_etc_audit_rules_d_audit_rules_f2_Regexp'] = '^-f 2$'
default['rhel9STIG']['stigrule_258227']['Setting']['_etc_audit_rules_d_audit_rules_f2_Line'] = '-f 2'

# R-258228 RHEL-09-654270
default['rhel9STIG']['stigrule_258228']['Manage'] = true
default['rhel9STIG']['stigrule_258228']['Title'] = "RHEL 9 audit system must protect logon UIDs from unauthorized change."
default['rhel9STIG']['stigrule_258228']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258228']['Setting']['_etc_audit_rules_d_audit_rules_loginuid_immutable_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258228']['Setting']['_etc_audit_rules_d_audit_rules_loginuid_immutable_Regexp'] = '^--loginuid-immutable$'
default['rhel9STIG']['stigrule_258228']['Setting']['_etc_audit_rules_d_audit_rules_loginuid_immutable_Line'] = '--loginuid-immutable'

# R-258229 RHEL-09-654275
default['rhel9STIG']['stigrule_258229']['Manage'] = true
default['rhel9STIG']['stigrule_258229']['Title'] = "RHEL 9 audit system must protect auditing rules from unauthorized change."
default['rhel9STIG']['stigrule_258229']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258229']['Setting']['_etc_audit_rules_d_audit_rules_e2_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_258229']['Setting']['_etc_audit_rules_d_audit_rules_e2_Regexp'] = '^-e 2$'
default['rhel9STIG']['stigrule_258229']['Setting']['_etc_audit_rules_d_audit_rules_e2_Line'] = '-e 2'

# R-258234 RHEL-09-215100
default['rhel9STIG']['stigrule_258234']['Manage'] = true
default['rhel9STIG']['stigrule_258234']['Title'] = "RHEL 9 must have the crypto-policies package installed."
default['rhel9STIG']['stigrule_258234']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_258234']['Setting']['crypto_policies_PackageName'] = 'crypto-policies'
default['rhel9STIG']['stigrule_258234']['Setting']['crypto_policies_Action'] = :install

# R-272488 RHEL-09-215101
default['rhel9STIG']['stigrule_272488']['Manage'] = true
default['rhel9STIG']['stigrule_272488']['Title'] = "RHEL 9 must have the Postfix package installed."
default['rhel9STIG']['stigrule_272488']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_272488']['Setting']['postfix_PackageName'] = 'postfix'
default['rhel9STIG']['stigrule_272488']['Setting']['postfix_Action'] = :install

# R-279936 RHEL-09-654097
default['rhel9STIG']['stigrule_279936']['Manage'] = true
default['rhel9STIG']['stigrule_279936']['Title'] = "RHEL 9 must audit any script or executable called by cron as root or by any privileged user."
default['rhel9STIG']['stigrule_279936']['Severity'] = 'medium'
default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b64_Regexp'] = '^-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec$'
default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b64_Line'] = '-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec'

default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b32_Regexp'] = '^-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec$'
default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b32_Line'] = '-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec'

default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b64_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b64_Regexp'] = '^-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec$'
default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b64_Line'] = '-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec'

default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b32_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b32_Regexp'] = '^-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec$'
default['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b32_Line'] = '-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec'

# R-288832 
default['rhel9STIG']['stigrule_288832']['Manage'] = true
default['rhel9STIG']['stigrule_288832']['Title'] = ""
default['rhel9STIG']['stigrule_288832']['Severity'] = ''
default['rhel9STIG']['stigrule_288832']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_useradd_Path'] = '/etc/audit/rules.d/audit.rules'
default['rhel9STIG']['stigrule_288832']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_useradd_Regexp'] = '^-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd$'
default['rhel9STIG']['stigrule_288832']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_useradd_Line'] = '-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd'

# R-288833 
default['rhel9STIG']['stigrule_288833']['Manage'] = true
default['rhel9STIG']['stigrule_288833']['Title'] = ""
default['rhel9STIG']['stigrule_288833']['Severity'] = ''
default['rhel9STIG']['stigrule_288833']['Setting']['_etc_pki_tls_openssl_cnf_Path'] = '/etc/pki/tls/openssl.cnf'
default['rhel9STIG']['stigrule_288833']['Setting']['_etc_pki_tls_openssl_cnf_Regexp'] = '^\.include = '
default['rhel9STIG']['stigrule_288833']['Setting']['_etc_pki_tls_openssl_cnf_Line'] = '.include = /etc/crypto-policies/back-ends/opensslcnf.config'

