execute 'dconf_update' do
  command 'dconf update'
  action :nothing
end
service 'ssh_restart' do
  service_name 'sshd'
  action :nothing
end
execute 'auditd_restart' do
  command 'service auditd restart'
  action :nothing
end
execute 'augenrules_load' do
  command 'augenrules --load'
  action :nothing
end
execute 'do_reboot' do
  command 'shutdown -r 1'
  action :nothing
end
execute 'daemon_reload' do
  command 'systemctl daemon-reload'
  action :nothing
end
execute 'networkmanager_reload' do
  command 'systemctl restart NetworkManager'
  action :nothing
end
execute 'with_faillock_enable' do
  command 'authselect enable-feature with-faillock'
  action :nothing
  only_if 'authselect current >/dev/null 2>&1'
end
execute 'rsyslog_restart' do
  command 'systemctl restart rsyslog'
  action :nothing
end
if node['rhel9STIG']['XCCDF_result']['Manage']
  cookbook_file "#{Chef::Config[:file_cache_path]}/stig_xml.rb" do
    source 'stig_xml.rb'
  end
  cookbook_file "#{Chef::Config[:file_cache_path]}/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml" do
    source 'U_RHEL_9_STIG_V2R10_Manual-xccdf.xml'
  end
  chef_handler 'Chef::Handler::StigXml' do
    source "#{Chef::Config[:file_cache_path]}/stig_xml.rb"
    arguments :stigName => 'U_RHEL_9_STIG_V2R10_Manual-xccdf.xml'
  end
end
if node['rhel9STIG']['stigrule_257779']['Manage']
  file '_etc_issue_257779' do
    path node['rhel9STIG']['stigrule_257779']['Setting']['_etc_issue_Path']
    content node['rhel9STIG']['stigrule_257779']['Setting']['_etc_issue_Content']
  end
end
if node['rhel9STIG']['stigrule_257783']['Manage']
  service 'systemd_journald_enable_257783' do
    service_name node['rhel9STIG']['stigrule_257783']['Setting']['systemd_journald_enable_ServiceName']
    action node['rhel9STIG']['stigrule_257783']['Setting']['systemd_journald_enable_Action']
  end
end
if node['rhel9STIG']['stigrule_257783']['Manage']
  service 'systemd_journald_start_257783' do
    service_name node['rhel9STIG']['stigrule_257783']['Setting']['systemd_journald_start_ServiceName']
    action node['rhel9STIG']['stigrule_257783']['Setting']['systemd_journald_start_Action']
  end
end
if node['rhel9STIG']['stigrule_257784']['Manage']
  _etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Path = node['rhel9STIG']['stigrule_257784']['Setting']['_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Path']
  _etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Dir = ::File.dirname(_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Path)
  directory _etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Dir do
    recursive true
  end
  file _etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Path) }
  end
  ini_setting '_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_257784' do
    path _etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Path
    section node['rhel9STIG']['stigrule_257784']['Setting']['_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Section']
    setting node['rhel9STIG']['stigrule_257784']['Setting']['_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Option']
    value node['rhel9STIG']['stigrule_257784']['Setting']['_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_257784']['Setting']['_etc_systemd_system_conf_d_55_CtrlAltDel_BurstAction_conf_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_257785']['Manage']
  systemd_unit 'ctrl_alt_del_target_disable_257785' do
    unit_name node['rhel9STIG']['stigrule_257785']['Setting']['ctrl_alt_del_target_disable_UnitName']
    action node['rhel9STIG']['stigrule_257785']['Setting']['ctrl_alt_del_target_disable_Action']
  end
end
if node['rhel9STIG']['stigrule_257785']['Manage']
  systemd_unit 'ctrl_alt_del_target_mask_257785' do
    unit_name node['rhel9STIG']['stigrule_257785']['Setting']['ctrl_alt_del_target_mask_UnitName']
    action node['rhel9STIG']['stigrule_257785']['Setting']['ctrl_alt_del_target_mask_Action']
  end
end
if node['rhel9STIG']['stigrule_257786']['Manage']
  systemd_unit 'debug_shell_service_disable_257786' do
    unit_name node['rhel9STIG']['stigrule_257786']['Setting']['debug_shell_service_disable_UnitName']
    action node['rhel9STIG']['stigrule_257786']['Setting']['debug_shell_service_disable_Action']
  end
end
if node['rhel9STIG']['stigrule_257786']['Manage']
  systemd_unit 'debug_shell_service_mask_257786' do
    unit_name node['rhel9STIG']['stigrule_257786']['Setting']['debug_shell_service_mask_UnitName']
    action node['rhel9STIG']['stigrule_257786']['Setting']['debug_shell_service_mask_Action']
  end
end
if node['rhel9STIG']['stigrule_257790']['Manage']
  file '_boot_grub2_grub_cfg_group_owner_257790' do
    path node['rhel9STIG']['stigrule_257790']['Setting']['_boot_grub2_grub_cfg_group_owner_Path']
    group node['rhel9STIG']['stigrule_257790']['Setting']['_boot_grub2_grub_cfg_group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257791']['Manage']
  file '_boot_grub2_grub_cfg_owner_257791' do
    path node['rhel9STIG']['stigrule_257791']['Setting']['_boot_grub2_grub_cfg_owner_Path']
    owner node['rhel9STIG']['stigrule_257791']['Setting']['_boot_grub2_grub_cfg_owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257797']['Manage']
  sysctl 'kernel_dmesg_restrict_257797' do
    key node['rhel9STIG']['stigrule_257797']['Setting']['kernel_dmesg_restrict_Key']
    value node['rhel9STIG']['stigrule_257797']['Setting']['kernel_dmesg_restrict_Value']
  end
end
if node['rhel9STIG']['stigrule_257798']['Manage']
  sysctl 'kernel_perf_event_paranoid_257798' do
    key node['rhel9STIG']['stigrule_257798']['Setting']['kernel_perf_event_paranoid_Key']
    value node['rhel9STIG']['stigrule_257798']['Setting']['kernel_perf_event_paranoid_Value']
  end
end
if node['rhel9STIG']['stigrule_257799']['Manage']
  sysctl 'kernel_kexec_load_disabled_257799' do
    key node['rhel9STIG']['stigrule_257799']['Setting']['kernel_kexec_load_disabled_Key']
    value node['rhel9STIG']['stigrule_257799']['Setting']['kernel_kexec_load_disabled_Value']
  end
end
if node['rhel9STIG']['stigrule_257800']['Manage']
  sysctl 'kernel_kptr_restrict_257800' do
    key node['rhel9STIG']['stigrule_257800']['Setting']['kernel_kptr_restrict_Key']
    value node['rhel9STIG']['stigrule_257800']['Setting']['kernel_kptr_restrict_Value']
  end
end
if node['rhel9STIG']['stigrule_257801']['Manage']
  sysctl 'fs_protected_hardlinks_257801' do
    key node['rhel9STIG']['stigrule_257801']['Setting']['fs_protected_hardlinks_Key']
    value node['rhel9STIG']['stigrule_257801']['Setting']['fs_protected_hardlinks_Value']
  end
end
if node['rhel9STIG']['stigrule_257802']['Manage']
  sysctl 'fs_protected_symlinks_257802' do
    key node['rhel9STIG']['stigrule_257802']['Setting']['fs_protected_symlinks_Key']
    value node['rhel9STIG']['stigrule_257802']['Setting']['fs_protected_symlinks_Value']
  end
end
if node['rhel9STIG']['stigrule_257803']['Manage']
  sysctl 'kernel_core_pattern_257803' do
    key node['rhel9STIG']['stigrule_257803']['Setting']['kernel_core_pattern_Key']
    value node['rhel9STIG']['stigrule_257803']['Setting']['kernel_core_pattern_Value']
  end
end
if node['rhel9STIG']['stigrule_257804']['Manage']
  _etc_modprobe_d_atm_conf_install_atm__bin_false_Path = node['rhel9STIG']['stigrule_257804']['Setting']['_etc_modprobe_d_atm_conf_install_atm__bin_false_Path']
  file _etc_modprobe_d_atm_conf_install_atm__bin_false_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_atm_conf_install_atm__bin_false_Path) }
  end
  file_line '_etc_modprobe_d_atm_conf_install_atm__bin_false_257804' do
    path _etc_modprobe_d_atm_conf_install_atm__bin_false_Path
    line node['rhel9STIG']['stigrule_257804']['Setting']['_etc_modprobe_d_atm_conf_install_atm__bin_false_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257804']['Manage']
  _etc_modprobe_d_atm_conf_blacklist_atm_Path = node['rhel9STIG']['stigrule_257804']['Setting']['_etc_modprobe_d_atm_conf_blacklist_atm_Path']
  file _etc_modprobe_d_atm_conf_blacklist_atm_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_atm_conf_blacklist_atm_Path) }
  end
  file_line '_etc_modprobe_d_atm_conf_blacklist_atm_257804' do
    path _etc_modprobe_d_atm_conf_blacklist_atm_Path
    line node['rhel9STIG']['stigrule_257804']['Setting']['_etc_modprobe_d_atm_conf_blacklist_atm_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257805']['Manage']
  _etc_modprobe_d_can_conf_install_can__bin_false_Path = node['rhel9STIG']['stigrule_257805']['Setting']['_etc_modprobe_d_can_conf_install_can__bin_false_Path']
  file _etc_modprobe_d_can_conf_install_can__bin_false_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_can_conf_install_can__bin_false_Path) }
  end
  file_line '_etc_modprobe_d_can_conf_install_can__bin_false_257805' do
    path _etc_modprobe_d_can_conf_install_can__bin_false_Path
    line node['rhel9STIG']['stigrule_257805']['Setting']['_etc_modprobe_d_can_conf_install_can__bin_false_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257805']['Manage']
  _etc_modprobe_d_can_conf_blacklist_can_Path = node['rhel9STIG']['stigrule_257805']['Setting']['_etc_modprobe_d_can_conf_blacklist_can_Path']
  file _etc_modprobe_d_can_conf_blacklist_can_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_can_conf_blacklist_can_Path) }
  end
  file_line '_etc_modprobe_d_can_conf_blacklist_can_257805' do
    path _etc_modprobe_d_can_conf_blacklist_can_Path
    line node['rhel9STIG']['stigrule_257805']['Setting']['_etc_modprobe_d_can_conf_blacklist_can_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257806']['Manage']
  _etc_modprobe_d_firewire_core_conf_install_firewire_core__bin_false_Path = node['rhel9STIG']['stigrule_257806']['Setting']['_etc_modprobe_d_firewire_core_conf_install_firewire_core__bin_false_Path']
  file _etc_modprobe_d_firewire_core_conf_install_firewire_core__bin_false_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_firewire_core_conf_install_firewire_core__bin_false_Path) }
  end
  file_line '_etc_modprobe_d_firewire_core_conf_install_firewire_core__bin_false_257806' do
    path _etc_modprobe_d_firewire_core_conf_install_firewire_core__bin_false_Path
    line node['rhel9STIG']['stigrule_257806']['Setting']['_etc_modprobe_d_firewire_core_conf_install_firewire_core__bin_false_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257806']['Manage']
  _etc_modprobe_d_firewire_core_conf_blacklist_firewire_core_Path = node['rhel9STIG']['stigrule_257806']['Setting']['_etc_modprobe_d_firewire_core_conf_blacklist_firewire_core_Path']
  file _etc_modprobe_d_firewire_core_conf_blacklist_firewire_core_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_firewire_core_conf_blacklist_firewire_core_Path) }
  end
  file_line '_etc_modprobe_d_firewire_core_conf_blacklist_firewire_core_257806' do
    path _etc_modprobe_d_firewire_core_conf_blacklist_firewire_core_Path
    line node['rhel9STIG']['stigrule_257806']['Setting']['_etc_modprobe_d_firewire_core_conf_blacklist_firewire_core_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257807']['Manage']
  _etc_modprobe_d_sctp_conf_install_sctp__bin_false_Path = node['rhel9STIG']['stigrule_257807']['Setting']['_etc_modprobe_d_sctp_conf_install_sctp__bin_false_Path']
  file _etc_modprobe_d_sctp_conf_install_sctp__bin_false_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_sctp_conf_install_sctp__bin_false_Path) }
  end
  file_line '_etc_modprobe_d_sctp_conf_install_sctp__bin_false_257807' do
    path _etc_modprobe_d_sctp_conf_install_sctp__bin_false_Path
    line node['rhel9STIG']['stigrule_257807']['Setting']['_etc_modprobe_d_sctp_conf_install_sctp__bin_false_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257807']['Manage']
  _etc_modprobe_d_sctp_conf_blacklist_sctp_Path = node['rhel9STIG']['stigrule_257807']['Setting']['_etc_modprobe_d_sctp_conf_blacklist_sctp_Path']
  file _etc_modprobe_d_sctp_conf_blacklist_sctp_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_sctp_conf_blacklist_sctp_Path) }
  end
  file_line '_etc_modprobe_d_sctp_conf_blacklist_sctp_257807' do
    path _etc_modprobe_d_sctp_conf_blacklist_sctp_Path
    line node['rhel9STIG']['stigrule_257807']['Setting']['_etc_modprobe_d_sctp_conf_blacklist_sctp_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257808']['Manage']
  _etc_modprobe_d_tipc_conf_install_tipc__bin_false_Path = node['rhel9STIG']['stigrule_257808']['Setting']['_etc_modprobe_d_tipc_conf_install_tipc__bin_false_Path']
  file _etc_modprobe_d_tipc_conf_install_tipc__bin_false_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_tipc_conf_install_tipc__bin_false_Path) }
  end
  file_line '_etc_modprobe_d_tipc_conf_install_tipc__bin_false_257808' do
    path _etc_modprobe_d_tipc_conf_install_tipc__bin_false_Path
    line node['rhel9STIG']['stigrule_257808']['Setting']['_etc_modprobe_d_tipc_conf_install_tipc__bin_false_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257808']['Manage']
  _etc_modprobe_d_tipc_conf_blacklist_tipc_Path = node['rhel9STIG']['stigrule_257808']['Setting']['_etc_modprobe_d_tipc_conf_blacklist_tipc_Path']
  file _etc_modprobe_d_tipc_conf_blacklist_tipc_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_tipc_conf_blacklist_tipc_Path) }
  end
  file_line '_etc_modprobe_d_tipc_conf_blacklist_tipc_257808' do
    path _etc_modprobe_d_tipc_conf_blacklist_tipc_Path
    line node['rhel9STIG']['stigrule_257808']['Setting']['_etc_modprobe_d_tipc_conf_blacklist_tipc_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257809']['Manage']
  sysctl 'kernel_randomize_va_space_257809' do
    key node['rhel9STIG']['stigrule_257809']['Setting']['kernel_randomize_va_space_Key']
    value node['rhel9STIG']['stigrule_257809']['Setting']['kernel_randomize_va_space_Value']
  end
end
if node['rhel9STIG']['stigrule_257810']['Manage']
  sysctl 'kernel_unprivileged_bpf_disabled_257810' do
    key node['rhel9STIG']['stigrule_257810']['Setting']['kernel_unprivileged_bpf_disabled_Key']
    value node['rhel9STIG']['stigrule_257810']['Setting']['kernel_unprivileged_bpf_disabled_Value']
  end
end
if node['rhel9STIG']['stigrule_257811']['Manage']
  sysctl 'kernel_yama_ptrace_scope_257811' do
    key node['rhel9STIG']['stigrule_257811']['Setting']['kernel_yama_ptrace_scope_Key']
    value node['rhel9STIG']['stigrule_257811']['Setting']['kernel_yama_ptrace_scope_Value']
  end
end
if node['rhel9STIG']['stigrule_257812']['Manage']
  _etc_systemd_coredump_conf_Path = node['rhel9STIG']['stigrule_257812']['Setting']['_etc_systemd_coredump_conf_Path']
  file _etc_systemd_coredump_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_systemd_coredump_conf_Path) }
  end
  file_line '_etc_systemd_coredump_conf_257812' do
    path _etc_systemd_coredump_conf_Path
    match node['rhel9STIG']['stigrule_257812']['Setting']['_etc_systemd_coredump_conf_Regexp']
    line node['rhel9STIG']['stigrule_257812']['Setting']['_etc_systemd_coredump_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_257813']['Manage']
  _etc_systemd_coredump_conf_Path = node['rhel9STIG']['stigrule_257813']['Setting']['_etc_systemd_coredump_conf_Path']
  file _etc_systemd_coredump_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_systemd_coredump_conf_Path) }
  end
  file_line '_etc_systemd_coredump_conf_257813' do
    path _etc_systemd_coredump_conf_Path
    match node['rhel9STIG']['stigrule_257813']['Setting']['_etc_systemd_coredump_conf_Regexp']
    line node['rhel9STIG']['stigrule_257813']['Setting']['_etc_systemd_coredump_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_257814']['Manage']
  _etc_security_limits_conf_Path = node['rhel9STIG']['stigrule_257814']['Setting']['_etc_security_limits_conf_Path']
  file _etc_security_limits_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_limits_conf_Path) }
  end
  file_line '_etc_security_limits_conf_257814' do
    path _etc_security_limits_conf_Path
    match node['rhel9STIG']['stigrule_257814']['Setting']['_etc_security_limits_conf_Regexp']
    line node['rhel9STIG']['stigrule_257814']['Setting']['_etc_security_limits_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_257815']['Manage']
  systemd_unit 'systemd_coredump_socket_disable_257815' do
    unit_name node['rhel9STIG']['stigrule_257815']['Setting']['systemd_coredump_socket_disable_UnitName']
    action node['rhel9STIG']['stigrule_257815']['Setting']['systemd_coredump_socket_disable_Action']
  end
end
if node['rhel9STIG']['stigrule_257815']['Manage']
  systemd_unit 'systemd_coredump_socket_mask_257815' do
    unit_name node['rhel9STIG']['stigrule_257815']['Setting']['systemd_coredump_socket_mask_UnitName']
    action node['rhel9STIG']['stigrule_257815']['Setting']['systemd_coredump_socket_mask_Action']
    notifies :run, 'execute[daemon_reload]', :immediately
  end
end
if node['rhel9STIG']['stigrule_257816']['Manage']
  sysctl 'user_max_user_namespaces_257816' do
    key node['rhel9STIG']['stigrule_257816']['Setting']['user_max_user_namespaces_Key']
    value node['rhel9STIG']['stigrule_257816']['Setting']['user_max_user_namespaces_Value']
  end
end
if node['rhel9STIG']['stigrule_257818']['Manage']
  systemd_unit 'kdump_disable_257818' do
    unit_name node['rhel9STIG']['stigrule_257818']['Setting']['kdump_disable_UnitName']
    action node['rhel9STIG']['stigrule_257818']['Setting']['kdump_disable_Action']
  end
end
if node['rhel9STIG']['stigrule_257818']['Manage']
  systemd_unit 'kdump_mask_257818' do
    unit_name node['rhel9STIG']['stigrule_257818']['Setting']['kdump_mask_UnitName']
    action node['rhel9STIG']['stigrule_257818']['Setting']['kdump_mask_Action']
  end
end
if node['rhel9STIG']['stigrule_257820']['Manage']
  _etc_dnf_dnf_conf_Path = node['rhel9STIG']['stigrule_257820']['Setting']['_etc_dnf_dnf_conf_Path']
  _etc_dnf_dnf_conf_Dir = ::File.dirname(_etc_dnf_dnf_conf_Path)
  directory _etc_dnf_dnf_conf_Dir do
    recursive true
  end
  file _etc_dnf_dnf_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_dnf_dnf_conf_Path) }
  end
  ini_setting '_etc_dnf_dnf_conf_257820' do
    path _etc_dnf_dnf_conf_Path
    section node['rhel9STIG']['stigrule_257820']['Setting']['_etc_dnf_dnf_conf_Section']
    setting node['rhel9STIG']['stigrule_257820']['Setting']['_etc_dnf_dnf_conf_Option']
    value node['rhel9STIG']['stigrule_257820']['Setting']['_etc_dnf_dnf_conf_Value']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_257821']['Manage']
  _etc_dnf_dnf_conf_Path = node['rhel9STIG']['stigrule_257821']['Setting']['_etc_dnf_dnf_conf_Path']
  _etc_dnf_dnf_conf_Dir = ::File.dirname(_etc_dnf_dnf_conf_Path)
  directory _etc_dnf_dnf_conf_Dir do
    recursive true
  end
  file _etc_dnf_dnf_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_dnf_dnf_conf_Path) }
  end
  ini_setting '_etc_dnf_dnf_conf_257821' do
    path _etc_dnf_dnf_conf_Path
    section node['rhel9STIG']['stigrule_257821']['Setting']['_etc_dnf_dnf_conf_Section']
    setting node['rhel9STIG']['stigrule_257821']['Setting']['_etc_dnf_dnf_conf_Option']
    value node['rhel9STIG']['stigrule_257821']['Setting']['_etc_dnf_dnf_conf_Value']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_257824']['Manage']
  _etc_dnf_dnf_conf_Path = node['rhel9STIG']['stigrule_257824']['Setting']['_etc_dnf_dnf_conf_Path']
  _etc_dnf_dnf_conf_Dir = ::File.dirname(_etc_dnf_dnf_conf_Path)
  directory _etc_dnf_dnf_conf_Dir do
    recursive true
  end
  file _etc_dnf_dnf_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_dnf_dnf_conf_Path) }
  end
  ini_setting '_etc_dnf_dnf_conf_257824' do
    path _etc_dnf_dnf_conf_Path
    section node['rhel9STIG']['stigrule_257824']['Setting']['_etc_dnf_dnf_conf_Section']
    setting node['rhel9STIG']['stigrule_257824']['Setting']['_etc_dnf_dnf_conf_Option']
    value node['rhel9STIG']['stigrule_257824']['Setting']['_etc_dnf_dnf_conf_Value']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_257825']['Manage']
  dnf_package 'subscription_manager_257825' do
    package_name node['rhel9STIG']['stigrule_257825']['Setting']['subscription_manager_PackageName']
    action node['rhel9STIG']['stigrule_257825']['Setting']['subscription_manager_Action']
  end
end
if node['rhel9STIG']['stigrule_257827']['Manage']
  dnf_package 'sendmail_257827' do
    package_name node['rhel9STIG']['stigrule_257827']['Setting']['sendmail_PackageName']
    action node['rhel9STIG']['stigrule_257827']['Setting']['sendmail_Action']
  end
end
if node['rhel9STIG']['stigrule_257828']['Manage']
  dnf_package 'nfs_utils_257828' do
    package_name node['rhel9STIG']['stigrule_257828']['Setting']['nfs_utils_PackageName']
    action node['rhel9STIG']['stigrule_257828']['Setting']['nfs_utils_Action']
  end
end
if node['rhel9STIG']['stigrule_257830']['Manage']
  dnf_package 'epel_release_257830' do
    package_name node['rhel9STIG']['stigrule_257830']['Setting']['epel_release_PackageName']
    action node['rhel9STIG']['stigrule_257830']['Setting']['epel_release_Action']
  end
end
if node['rhel9STIG']['stigrule_257831']['Manage']
  dnf_package 'telnet_server_257831' do
    package_name node['rhel9STIG']['stigrule_257831']['Setting']['telnet_server_PackageName']
    action node['rhel9STIG']['stigrule_257831']['Setting']['telnet_server_Action']
  end
end
if node['rhel9STIG']['stigrule_257832']['Manage']
  dnf_package 'gssproxy_257832' do
    package_name node['rhel9STIG']['stigrule_257832']['Setting']['gssproxy_PackageName']
    action node['rhel9STIG']['stigrule_257832']['Setting']['gssproxy_Action']
  end
end
if node['rhel9STIG']['stigrule_257833']['Manage']
  dnf_package 'iprutils_257833' do
    package_name node['rhel9STIG']['stigrule_257833']['Setting']['iprutils_PackageName']
    action node['rhel9STIG']['stigrule_257833']['Setting']['iprutils_Action']
  end
end
if node['rhel9STIG']['stigrule_257834']['Manage']
  dnf_package 'tuned_257834' do
    package_name node['rhel9STIG']['stigrule_257834']['Setting']['tuned_PackageName']
    action node['rhel9STIG']['stigrule_257834']['Setting']['tuned_Action']
  end
end
if node['rhel9STIG']['stigrule_257838']['Manage']
  dnf_package 'openssl_pkcs11_257838' do
    package_name node['rhel9STIG']['stigrule_257838']['Setting']['openssl_pkcs11_PackageName']
    action node['rhel9STIG']['stigrule_257838']['Setting']['openssl_pkcs11_Action']
  end
end
if node['rhel9STIG']['stigrule_257839']['Manage']
  dnf_package 'gnutls_utils_257839' do
    package_name node['rhel9STIG']['stigrule_257839']['Setting']['gnutls_utils_PackageName']
    action node['rhel9STIG']['stigrule_257839']['Setting']['gnutls_utils_Action']
  end
end
if node['rhel9STIG']['stigrule_257840']['Manage']
  dnf_package 'nss_tools_257840' do
    package_name node['rhel9STIG']['stigrule_257840']['Setting']['nss_tools_PackageName']
    action node['rhel9STIG']['stigrule_257840']['Setting']['nss_tools_Action']
  end
end
if node['rhel9STIG']['stigrule_257841']['Manage']
  dnf_package 'rng_tools_257841' do
    package_name node['rhel9STIG']['stigrule_257841']['Setting']['rng_tools_PackageName']
    action node['rhel9STIG']['stigrule_257841']['Setting']['rng_tools_Action']
  end
end
if node['rhel9STIG']['stigrule_257842']['Manage']
  dnf_package 's_nail_257842' do
    package_name node['rhel9STIG']['stigrule_257842']['Setting']['s_nail_PackageName']
    action node['rhel9STIG']['stigrule_257842']['Setting']['s_nail_Action']
  end
end
if node['rhel9STIG']['stigrule_257849']['Manage']
  systemd_unit 'autofs_service_disable_257849' do
    unit_name node['rhel9STIG']['stigrule_257849']['Setting']['autofs_service_disable_UnitName']
    action node['rhel9STIG']['stigrule_257849']['Setting']['autofs_service_disable_Action']
  end
end
if node['rhel9STIG']['stigrule_257849']['Manage']
  systemd_unit 'autofs_service_mask_257849' do
    unit_name node['rhel9STIG']['stigrule_257849']['Setting']['autofs_service_mask_UnitName']
    action node['rhel9STIG']['stigrule_257849']['Setting']['autofs_service_mask_Action']
  end
end
if node['rhel9STIG']['stigrule_257880']['Manage']
  _etc_modprobe_d_cramfs_conf_install_cramfs__bin_false_Path = node['rhel9STIG']['stigrule_257880']['Setting']['_etc_modprobe_d_cramfs_conf_install_cramfs__bin_false_Path']
  file _etc_modprobe_d_cramfs_conf_install_cramfs__bin_false_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_cramfs_conf_install_cramfs__bin_false_Path) }
  end
  file_line '_etc_modprobe_d_cramfs_conf_install_cramfs__bin_false_257880' do
    path _etc_modprobe_d_cramfs_conf_install_cramfs__bin_false_Path
    line node['rhel9STIG']['stigrule_257880']['Setting']['_etc_modprobe_d_cramfs_conf_install_cramfs__bin_false_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257880']['Manage']
  _etc_modprobe_d_cramfs_conf_blacklist_cramfs_Path = node['rhel9STIG']['stigrule_257880']['Setting']['_etc_modprobe_d_cramfs_conf_blacklist_cramfs_Path']
  file _etc_modprobe_d_cramfs_conf_blacklist_cramfs_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_cramfs_conf_blacklist_cramfs_Path) }
  end
  file_line '_etc_modprobe_d_cramfs_conf_blacklist_cramfs_257880' do
    path _etc_modprobe_d_cramfs_conf_blacklist_cramfs_Path
    line node['rhel9STIG']['stigrule_257880']['Setting']['_etc_modprobe_d_cramfs_conf_blacklist_cramfs_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_257885']['Manage']
  directory '_var_log_mode_257885' do
    path node['rhel9STIG']['stigrule_257885']['Setting']['_var_log_mode_Path']
    mode node['rhel9STIG']['stigrule_257885']['Setting']['_var_log_mode_Mode']
  end
end
if node['rhel9STIG']['stigrule_257886']['Manage']
  file '_var_log_messages_mode_257886' do
    path node['rhel9STIG']['stigrule_257886']['Setting']['_var_log_messages_mode_Path']
    mode node['rhel9STIG']['stigrule_257886']['Setting']['_var_log_messages_mode_Mode']
  end
end
if node['rhel9STIG']['stigrule_257891']['Manage']
  file '_etc_group_mode_257891' do
    path node['rhel9STIG']['stigrule_257891']['Setting']['_etc_group_mode_Path']
    mode node['rhel9STIG']['stigrule_257891']['Setting']['_etc_group_mode_Mode']
  end
end
if node['rhel9STIG']['stigrule_257892']['Manage']
  file '_etc_group__mode_257892' do
    path node['rhel9STIG']['stigrule_257892']['Setting']['_etc_group__mode_Path']
    mode node['rhel9STIG']['stigrule_257892']['Setting']['_etc_group__mode_Mode']
  end
end
if node['rhel9STIG']['stigrule_257893']['Manage']
  file '_etc_gshadow_mode_257893' do
    path node['rhel9STIG']['stigrule_257893']['Setting']['_etc_gshadow_mode_Path']
    mode node['rhel9STIG']['stigrule_257893']['Setting']['_etc_gshadow_mode_Mode']
  end
end
if node['rhel9STIG']['stigrule_257894']['Manage']
  file '_etc_gshadow__mode_257894' do
    path node['rhel9STIG']['stigrule_257894']['Setting']['_etc_gshadow__mode_Path']
    mode node['rhel9STIG']['stigrule_257894']['Setting']['_etc_gshadow__mode_Mode']
  end
end
if node['rhel9STIG']['stigrule_257895']['Manage']
  file '_etc_passwd_mode_257895' do
    path node['rhel9STIG']['stigrule_257895']['Setting']['_etc_passwd_mode_Path']
    mode node['rhel9STIG']['stigrule_257895']['Setting']['_etc_passwd_mode_Mode']
  end
end
if node['rhel9STIG']['stigrule_257896']['Manage']
  file '_etc_passwd__mode_257896' do
    path node['rhel9STIG']['stigrule_257896']['Setting']['_etc_passwd__mode_Path']
    mode node['rhel9STIG']['stigrule_257896']['Setting']['_etc_passwd__mode_Mode']
  end
end
if node['rhel9STIG']['stigrule_257897']['Manage']
  file '_etc_shadow__mode_257897' do
    path node['rhel9STIG']['stigrule_257897']['Setting']['_etc_shadow__mode_Path']
    mode node['rhel9STIG']['stigrule_257897']['Setting']['_etc_shadow__mode_Mode']
  end
end
if node['rhel9STIG']['stigrule_257898']['Manage']
  file '_etc_group_owner_257898' do
    path node['rhel9STIG']['stigrule_257898']['Setting']['_etc_group_owner_Path']
    owner node['rhel9STIG']['stigrule_257898']['Setting']['_etc_group_owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257899']['Manage']
  file '_etc_group_group_owner_257899' do
    path node['rhel9STIG']['stigrule_257899']['Setting']['_etc_group_group_owner_Path']
    group node['rhel9STIG']['stigrule_257899']['Setting']['_etc_group_group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257900']['Manage']
  file '_etc_group__owner_257900' do
    path node['rhel9STIG']['stigrule_257900']['Setting']['_etc_group__owner_Path']
    owner node['rhel9STIG']['stigrule_257900']['Setting']['_etc_group__owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257901']['Manage']
  file '_etc_group__group_owner_257901' do
    path node['rhel9STIG']['stigrule_257901']['Setting']['_etc_group__group_owner_Path']
    group node['rhel9STIG']['stigrule_257901']['Setting']['_etc_group__group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257902']['Manage']
  file '_etc_gshadow_owner_257902' do
    path node['rhel9STIG']['stigrule_257902']['Setting']['_etc_gshadow_owner_Path']
    owner node['rhel9STIG']['stigrule_257902']['Setting']['_etc_gshadow_owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257903']['Manage']
  file '_etc_gshadow_group_owner_257903' do
    path node['rhel9STIG']['stigrule_257903']['Setting']['_etc_gshadow_group_owner_Path']
    group node['rhel9STIG']['stigrule_257903']['Setting']['_etc_gshadow_group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257904']['Manage']
  file '_etc_gshadow__owner_257904' do
    path node['rhel9STIG']['stigrule_257904']['Setting']['_etc_gshadow__owner_Path']
    owner node['rhel9STIG']['stigrule_257904']['Setting']['_etc_gshadow__owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257905']['Manage']
  file '_etc_gshadow__group_owner_257905' do
    path node['rhel9STIG']['stigrule_257905']['Setting']['_etc_gshadow__group_owner_Path']
    group node['rhel9STIG']['stigrule_257905']['Setting']['_etc_gshadow__group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257906']['Manage']
  file '_etc_passwd_owner_257906' do
    path node['rhel9STIG']['stigrule_257906']['Setting']['_etc_passwd_owner_Path']
    owner node['rhel9STIG']['stigrule_257906']['Setting']['_etc_passwd_owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257907']['Manage']
  file '_etc_passwd_group_owner_257907' do
    path node['rhel9STIG']['stigrule_257907']['Setting']['_etc_passwd_group_owner_Path']
    group node['rhel9STIG']['stigrule_257907']['Setting']['_etc_passwd_group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257908']['Manage']
  file '_etc_passwd__owner_257908' do
    path node['rhel9STIG']['stigrule_257908']['Setting']['_etc_passwd__owner_Path']
    owner node['rhel9STIG']['stigrule_257908']['Setting']['_etc_passwd__owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257909']['Manage']
  file '_etc_passwd__group_owner_257909' do
    path node['rhel9STIG']['stigrule_257909']['Setting']['_etc_passwd__group_owner_Path']
    group node['rhel9STIG']['stigrule_257909']['Setting']['_etc_passwd__group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257910']['Manage']
  file '_etc_shadow_owner_257910' do
    path node['rhel9STIG']['stigrule_257910']['Setting']['_etc_shadow_owner_Path']
    owner node['rhel9STIG']['stigrule_257910']['Setting']['_etc_shadow_owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257911']['Manage']
  file '_etc_shadow_group_owner_257911' do
    path node['rhel9STIG']['stigrule_257911']['Setting']['_etc_shadow_group_owner_Path']
    group node['rhel9STIG']['stigrule_257911']['Setting']['_etc_shadow_group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257912']['Manage']
  file '_etc_shadow__owner_257912' do
    path node['rhel9STIG']['stigrule_257912']['Setting']['_etc_shadow__owner_Path']
    owner node['rhel9STIG']['stigrule_257912']['Setting']['_etc_shadow__owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257913']['Manage']
  file '_etc_shadow__group_owner_257913' do
    path node['rhel9STIG']['stigrule_257913']['Setting']['_etc_shadow__group_owner_Path']
    group node['rhel9STIG']['stigrule_257913']['Setting']['_etc_shadow__group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257914']['Manage']
  directory '_var_log_owner_257914' do
    path node['rhel9STIG']['stigrule_257914']['Setting']['_var_log_owner_Path']
    owner node['rhel9STIG']['stigrule_257914']['Setting']['_var_log_owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257915']['Manage']
  directory '_var_log_group_owner_257915' do
    path node['rhel9STIG']['stigrule_257915']['Setting']['_var_log_group_owner_Path']
    group node['rhel9STIG']['stigrule_257915']['Setting']['_var_log_group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257916']['Manage']
  file '_var_log_messages_owner_257916' do
    path node['rhel9STIG']['stigrule_257916']['Setting']['_var_log_messages_owner_Path']
    owner node['rhel9STIG']['stigrule_257916']['Setting']['_var_log_messages_owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_257917']['Manage']
  file '_var_log_messages_group_owner_257917' do
    path node['rhel9STIG']['stigrule_257917']['Setting']['_var_log_messages_group_owner_Path']
    group node['rhel9STIG']['stigrule_257917']['Setting']['_var_log_messages_group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257934']['Manage']
  file '_etc_shadow_mode_257934' do
    path node['rhel9STIG']['stigrule_257934']['Setting']['_etc_shadow_mode_Path']
    mode node['rhel9STIG']['stigrule_257934']['Setting']['_etc_shadow_mode_Mode']
  end
end
if node['rhel9STIG']['stigrule_257935']['Manage']
  dnf_package 'firewalld_257935' do
    package_name node['rhel9STIG']['stigrule_257935']['Setting']['firewalld_PackageName']
    action node['rhel9STIG']['stigrule_257935']['Setting']['firewalld_Action']
  end
end
if node['rhel9STIG']['stigrule_257936']['Manage']
  service 'firewalld_enable_257936' do
    service_name node['rhel9STIG']['stigrule_257936']['Setting']['firewalld_enable_ServiceName']
    action node['rhel9STIG']['stigrule_257936']['Setting']['firewalld_enable_Action']
  end
end
if node['rhel9STIG']['stigrule_257936']['Manage']
  service 'firewalld_start_257936' do
    service_name node['rhel9STIG']['stigrule_257936']['Setting']['firewalld_start_ServiceName']
    action node['rhel9STIG']['stigrule_257936']['Setting']['firewalld_start_Action']
  end
end
if node['rhel9STIG']['stigrule_257939']['Manage']
  _etc_firewalld_firewalld_conf_Path = node['rhel9STIG']['stigrule_257939']['Setting']['_etc_firewalld_firewalld_conf_Path']
  file _etc_firewalld_firewalld_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_firewalld_firewalld_conf_Path) }
  end
  file_line '_etc_firewalld_firewalld_conf_257939' do
    path _etc_firewalld_firewalld_conf_Path
    match node['rhel9STIG']['stigrule_257939']['Setting']['_etc_firewalld_firewalld_conf_Regexp']
    line node['rhel9STIG']['stigrule_257939']['Setting']['_etc_firewalld_firewalld_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_257942']['Manage']
  sysctl 'net_core_bpf_jit_harden_257942' do
    key node['rhel9STIG']['stigrule_257942']['Setting']['net_core_bpf_jit_harden_Key']
    value node['rhel9STIG']['stigrule_257942']['Setting']['net_core_bpf_jit_harden_Value']
  end
end
if node['rhel9STIG']['stigrule_257943']['Manage']
  dnf_package 'chrony_257943' do
    package_name node['rhel9STIG']['stigrule_257943']['Setting']['chrony_PackageName']
    action node['rhel9STIG']['stigrule_257943']['Setting']['chrony_Action']
  end
end
if node['rhel9STIG']['stigrule_257944']['Manage']
  service 'chronyd_enable_257944' do
    service_name node['rhel9STIG']['stigrule_257944']['Setting']['chronyd_enable_ServiceName']
    action node['rhel9STIG']['stigrule_257944']['Setting']['chronyd_enable_Action']
  end
end
if node['rhel9STIG']['stigrule_257944']['Manage']
  service 'chronyd_start_257944' do
    service_name node['rhel9STIG']['stigrule_257944']['Setting']['chronyd_start_ServiceName']
    action node['rhel9STIG']['stigrule_257944']['Setting']['chronyd_start_Action']
  end
end
if node['rhel9STIG']['stigrule_257946']['Manage']
  _etc_chrony_conf_Path = node['rhel9STIG']['stigrule_257946']['Setting']['_etc_chrony_conf_Path']
  file _etc_chrony_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_chrony_conf_Path) }
  end
  file_line '_etc_chrony_conf_257946' do
    path _etc_chrony_conf_Path
    match node['rhel9STIG']['stigrule_257946']['Setting']['_etc_chrony_conf_Regexp']
    line node['rhel9STIG']['stigrule_257946']['Setting']['_etc_chrony_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_257947']['Manage']
  _etc_chrony_conf_Path = node['rhel9STIG']['stigrule_257947']['Setting']['_etc_chrony_conf_Path']
  file _etc_chrony_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_chrony_conf_Path) }
  end
  file_line '_etc_chrony_conf_257947' do
    path _etc_chrony_conf_Path
    match node['rhel9STIG']['stigrule_257947']['Setting']['_etc_chrony_conf_Regexp']
    line node['rhel9STIG']['stigrule_257947']['Setting']['_etc_chrony_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_257949']['Manage']
  _etc_NetworkManager_NetworkManager_conf_Path = node['rhel9STIG']['stigrule_257949']['Setting']['_etc_NetworkManager_NetworkManager_conf_Path']
  _etc_NetworkManager_NetworkManager_conf_Dir = ::File.dirname(_etc_NetworkManager_NetworkManager_conf_Path)
  directory _etc_NetworkManager_NetworkManager_conf_Dir do
    recursive true
  end
  file _etc_NetworkManager_NetworkManager_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_NetworkManager_NetworkManager_conf_Path) }
  end
  ini_setting '_etc_NetworkManager_NetworkManager_conf_257949' do
    path _etc_NetworkManager_NetworkManager_conf_Path
    section node['rhel9STIG']['stigrule_257949']['Setting']['_etc_NetworkManager_NetworkManager_conf_Section']
    setting node['rhel9STIG']['stigrule_257949']['Setting']['_etc_NetworkManager_NetworkManager_conf_Option']
    value node['rhel9STIG']['stigrule_257949']['Setting']['_etc_NetworkManager_NetworkManager_conf_Value']
    notifies :run, 'execute[networkmanager_reload]', :delayed
    separator '='
  end
end
if node['rhel9STIG']['stigrule_257954']['Manage']
  dnf_package 'libreswan_257954' do
    package_name node['rhel9STIG']['stigrule_257954']['Setting']['libreswan_PackageName']
    action node['rhel9STIG']['stigrule_257954']['Setting']['libreswan_Action']
  end
end
if node['rhel9STIG']['stigrule_257957']['Manage']
  sysctl 'net_ipv4_tcp_syncookies_257957' do
    key node['rhel9STIG']['stigrule_257957']['Setting']['net_ipv4_tcp_syncookies_Key']
    value node['rhel9STIG']['stigrule_257957']['Setting']['net_ipv4_tcp_syncookies_Value']
  end
end
if node['rhel9STIG']['stigrule_257958']['Manage']
  sysctl 'net_ipv4_conf_all_accept_redirects_257958' do
    key node['rhel9STIG']['stigrule_257958']['Setting']['net_ipv4_conf_all_accept_redirects_Key']
    value node['rhel9STIG']['stigrule_257958']['Setting']['net_ipv4_conf_all_accept_redirects_Value']
  end
end
if node['rhel9STIG']['stigrule_257959']['Manage']
  sysctl 'net_ipv4_conf_all_accept_source_route_257959' do
    key node['rhel9STIG']['stigrule_257959']['Setting']['net_ipv4_conf_all_accept_source_route_Key']
    value node['rhel9STIG']['stigrule_257959']['Setting']['net_ipv4_conf_all_accept_source_route_Value']
  end
end
if node['rhel9STIG']['stigrule_257960']['Manage']
  sysctl 'net_ipv4_conf_all_log_martians_257960' do
    key node['rhel9STIG']['stigrule_257960']['Setting']['net_ipv4_conf_all_log_martians_Key']
    value node['rhel9STIG']['stigrule_257960']['Setting']['net_ipv4_conf_all_log_martians_Value']
  end
end
if node['rhel9STIG']['stigrule_257961']['Manage']
  sysctl 'net_ipv4_conf_default_log_martians_257961' do
    key node['rhel9STIG']['stigrule_257961']['Setting']['net_ipv4_conf_default_log_martians_Key']
    value node['rhel9STIG']['stigrule_257961']['Setting']['net_ipv4_conf_default_log_martians_Value']
  end
end
if node['rhel9STIG']['stigrule_257962']['Manage']
  sysctl 'net_ipv4_conf_all_rp_filter_257962' do
    key node['rhel9STIG']['stigrule_257962']['Setting']['net_ipv4_conf_all_rp_filter_Key']
    value node['rhel9STIG']['stigrule_257962']['Setting']['net_ipv4_conf_all_rp_filter_Value']
  end
end
if node['rhel9STIG']['stigrule_257963']['Manage']
  sysctl 'net_ipv4_conf_default_accept_redirects_257963' do
    key node['rhel9STIG']['stigrule_257963']['Setting']['net_ipv4_conf_default_accept_redirects_Key']
    value node['rhel9STIG']['stigrule_257963']['Setting']['net_ipv4_conf_default_accept_redirects_Value']
  end
end
if node['rhel9STIG']['stigrule_257964']['Manage']
  sysctl 'net_ipv4_conf_default_accept_source_route_257964' do
    key node['rhel9STIG']['stigrule_257964']['Setting']['net_ipv4_conf_default_accept_source_route_Key']
    value node['rhel9STIG']['stigrule_257964']['Setting']['net_ipv4_conf_default_accept_source_route_Value']
  end
end
if node['rhel9STIG']['stigrule_257965']['Manage']
  sysctl 'net_ipv4_conf_default_rp_filter_257965' do
    key node['rhel9STIG']['stigrule_257965']['Setting']['net_ipv4_conf_default_rp_filter_Key']
    value node['rhel9STIG']['stigrule_257965']['Setting']['net_ipv4_conf_default_rp_filter_Value']
  end
end
if node['rhel9STIG']['stigrule_257966']['Manage']
  sysctl 'net_ipv4_icmp_echo_ignore_broadcasts_257966' do
    key node['rhel9STIG']['stigrule_257966']['Setting']['net_ipv4_icmp_echo_ignore_broadcasts_Key']
    value node['rhel9STIG']['stigrule_257966']['Setting']['net_ipv4_icmp_echo_ignore_broadcasts_Value']
  end
end
if node['rhel9STIG']['stigrule_257967']['Manage']
  sysctl 'net_ipv4_icmp_ignore_bogus_error_responses_257967' do
    key node['rhel9STIG']['stigrule_257967']['Setting']['net_ipv4_icmp_ignore_bogus_error_responses_Key']
    value node['rhel9STIG']['stigrule_257967']['Setting']['net_ipv4_icmp_ignore_bogus_error_responses_Value']
  end
end
if node['rhel9STIG']['stigrule_257968']['Manage']
  sysctl 'net_ipv4_conf_all_send_redirects_257968' do
    key node['rhel9STIG']['stigrule_257968']['Setting']['net_ipv4_conf_all_send_redirects_Key']
    value node['rhel9STIG']['stigrule_257968']['Setting']['net_ipv4_conf_all_send_redirects_Value']
  end
end
if node['rhel9STIG']['stigrule_257969']['Manage']
  sysctl 'net_ipv4_conf_default_send_redirects_257969' do
    key node['rhel9STIG']['stigrule_257969']['Setting']['net_ipv4_conf_default_send_redirects_Key']
    value node['rhel9STIG']['stigrule_257969']['Setting']['net_ipv4_conf_default_send_redirects_Value']
  end
end
if node['rhel9STIG']['stigrule_257970']['Manage']
  sysctl 'net_ipv4_conf_all_forwarding_257970' do
    key node['rhel9STIG']['stigrule_257970']['Setting']['net_ipv4_conf_all_forwarding_Key']
    value node['rhel9STIG']['stigrule_257970']['Setting']['net_ipv4_conf_all_forwarding_Value']
  end
end
if node['rhel9STIG']['stigrule_257971']['Manage']
  sysctl 'net_ipv6_conf_all_accept_ra_257971' do
    key node['rhel9STIG']['stigrule_257971']['Setting']['net_ipv6_conf_all_accept_ra_Key']
    value node['rhel9STIG']['stigrule_257971']['Setting']['net_ipv6_conf_all_accept_ra_Value']
  end
end
if node['rhel9STIG']['stigrule_257972']['Manage']
  sysctl 'net_ipv6_conf_all_accept_redirects_257972' do
    key node['rhel9STIG']['stigrule_257972']['Setting']['net_ipv6_conf_all_accept_redirects_Key']
    value node['rhel9STIG']['stigrule_257972']['Setting']['net_ipv6_conf_all_accept_redirects_Value']
  end
end
if node['rhel9STIG']['stigrule_257973']['Manage']
  sysctl 'net_ipv6_conf_all_accept_source_route_257973' do
    key node['rhel9STIG']['stigrule_257973']['Setting']['net_ipv6_conf_all_accept_source_route_Key']
    value node['rhel9STIG']['stigrule_257973']['Setting']['net_ipv6_conf_all_accept_source_route_Value']
  end
end
if node['rhel9STIG']['stigrule_257974']['Manage']
  sysctl 'net_ipv6_conf_all_forwarding_257974' do
    key node['rhel9STIG']['stigrule_257974']['Setting']['net_ipv6_conf_all_forwarding_Key']
    value node['rhel9STIG']['stigrule_257974']['Setting']['net_ipv6_conf_all_forwarding_Value']
  end
end
if node['rhel9STIG']['stigrule_257975']['Manage']
  sysctl 'net_ipv6_conf_default_accept_ra_257975' do
    key node['rhel9STIG']['stigrule_257975']['Setting']['net_ipv6_conf_default_accept_ra_Key']
    value node['rhel9STIG']['stigrule_257975']['Setting']['net_ipv6_conf_default_accept_ra_Value']
  end
end
if node['rhel9STIG']['stigrule_257976']['Manage']
  sysctl 'net_ipv6_conf_default_accept_redirects_257976' do
    key node['rhel9STIG']['stigrule_257976']['Setting']['net_ipv6_conf_default_accept_redirects_Key']
    value node['rhel9STIG']['stigrule_257976']['Setting']['net_ipv6_conf_default_accept_redirects_Value']
  end
end
if node['rhel9STIG']['stigrule_257977']['Manage']
  sysctl 'net_ipv6_conf_default_accept_source_route_257977' do
    key node['rhel9STIG']['stigrule_257977']['Setting']['net_ipv6_conf_default_accept_source_route_Key']
    value node['rhel9STIG']['stigrule_257977']['Setting']['net_ipv6_conf_default_accept_source_route_Value']
  end
end
if node['rhel9STIG']['stigrule_257978']['Manage']
  dnf_package 'openssh_server_257978' do
    package_name node['rhel9STIG']['stigrule_257978']['Setting']['openssh_server_PackageName']
    action node['rhel9STIG']['stigrule_257978']['Setting']['openssh_server_Action']
  end
end
if node['rhel9STIG']['stigrule_257979']['Manage']
  service 'sshd_enable_257979' do
    service_name node['rhel9STIG']['stigrule_257979']['Setting']['sshd_enable_ServiceName']
    action node['rhel9STIG']['stigrule_257979']['Setting']['sshd_enable_Action']
  end
end
if node['rhel9STIG']['stigrule_257979']['Manage']
  service 'sshd_start_257979' do
    service_name node['rhel9STIG']['stigrule_257979']['Setting']['sshd_start_ServiceName']
    action node['rhel9STIG']['stigrule_257979']['Setting']['sshd_start_Action']
  end
end
if node['rhel9STIG']['stigrule_257980']['Manage']
  dnf_package 'openssh_clients_257980' do
    package_name node['rhel9STIG']['stigrule_257980']['Setting']['openssh_clients_PackageName']
    action node['rhel9STIG']['stigrule_257980']['Setting']['openssh_clients_Action']
  end
end
if node['rhel9STIG']['stigrule_257981']['Manage']
  file_line 'Banner_257981' do
    path node['rhel9STIG']['stigrule_257981']['Setting']['Banner_Path']
    match node['rhel9STIG']['stigrule_257981']['Setting']['Banner_Regexp']
    line node['rhel9STIG']['stigrule_257981']['Setting']['Banner_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257981']['Setting']['Banner_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257982']['Manage']
  file_line 'LogLevel_257982' do
    path node['rhel9STIG']['stigrule_257982']['Setting']['LogLevel_Path']
    match node['rhel9STIG']['stigrule_257982']['Setting']['LogLevel_Regexp']
    line node['rhel9STIG']['stigrule_257982']['Setting']['LogLevel_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257982']['Setting']['LogLevel_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257983']['Manage']
  file_line 'PubkeyAuthentication_257983' do
    path node['rhel9STIG']['stigrule_257983']['Setting']['PubkeyAuthentication_Path']
    match node['rhel9STIG']['stigrule_257983']['Setting']['PubkeyAuthentication_Regexp']
    line node['rhel9STIG']['stigrule_257983']['Setting']['PubkeyAuthentication_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257983']['Setting']['PubkeyAuthentication_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257984']['Manage']
  file_line 'PermitEmptyPasswords_257984' do
    path node['rhel9STIG']['stigrule_257984']['Setting']['PermitEmptyPasswords_Path']
    match node['rhel9STIG']['stigrule_257984']['Setting']['PermitEmptyPasswords_Regexp']
    line node['rhel9STIG']['stigrule_257984']['Setting']['PermitEmptyPasswords_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257984']['Setting']['PermitEmptyPasswords_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257985']['Manage']
  file_line 'PermitRootLogin_257985' do
    path node['rhel9STIG']['stigrule_257985']['Setting']['PermitRootLogin_Path']
    match node['rhel9STIG']['stigrule_257985']['Setting']['PermitRootLogin_Regexp']
    line node['rhel9STIG']['stigrule_257985']['Setting']['PermitRootLogin_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257985']['Setting']['PermitRootLogin_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257986']['Manage']
  file_line 'UsePAM_257986' do
    path node['rhel9STIG']['stigrule_257986']['Setting']['UsePAM_Path']
    match node['rhel9STIG']['stigrule_257986']['Setting']['UsePAM_Regexp']
    line node['rhel9STIG']['stigrule_257986']['Setting']['UsePAM_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257986']['Setting']['UsePAM_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257992']['Manage']
  file_line 'HostbasedAuthentication_257992' do
    path node['rhel9STIG']['stigrule_257992']['Setting']['HostbasedAuthentication_Path']
    match node['rhel9STIG']['stigrule_257992']['Setting']['HostbasedAuthentication_Regexp']
    line node['rhel9STIG']['stigrule_257992']['Setting']['HostbasedAuthentication_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257992']['Setting']['HostbasedAuthentication_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257993']['Manage']
  file_line 'PermitUserEnvironment_257993' do
    path node['rhel9STIG']['stigrule_257993']['Setting']['PermitUserEnvironment_Path']
    match node['rhel9STIG']['stigrule_257993']['Setting']['PermitUserEnvironment_Regexp']
    line node['rhel9STIG']['stigrule_257993']['Setting']['PermitUserEnvironment_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257993']['Setting']['PermitUserEnvironment_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257994']['Manage']
  file_line 'RekeyLimit_257994' do
    path node['rhel9STIG']['stigrule_257994']['Setting']['RekeyLimit_Path']
    match node['rhel9STIG']['stigrule_257994']['Setting']['RekeyLimit_Regexp']
    line node['rhel9STIG']['stigrule_257994']['Setting']['RekeyLimit_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257994']['Setting']['RekeyLimit_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257995']['Manage']
  file_line 'ClientAliveCountMax_257995' do
    path node['rhel9STIG']['stigrule_257995']['Setting']['ClientAliveCountMax_Path']
    match node['rhel9STIG']['stigrule_257995']['Setting']['ClientAliveCountMax_Regexp']
    line node['rhel9STIG']['stigrule_257995']['Setting']['ClientAliveCountMax_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257995']['Setting']['ClientAliveCountMax_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257996']['Manage']
  file_line 'ClientAliveInterval_257996' do
    path node['rhel9STIG']['stigrule_257996']['Setting']['ClientAliveInterval_Path']
    match node['rhel9STIG']['stigrule_257996']['Setting']['ClientAliveInterval_Regexp']
    line node['rhel9STIG']['stigrule_257996']['Setting']['ClientAliveInterval_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_257996']['Setting']['ClientAliveInterval_Only_if']
  end
end
if node['rhel9STIG']['stigrule_257997']['Manage']
  file '_etc_ssh_sshd_config_group_owner_257997' do
    path node['rhel9STIG']['stigrule_257997']['Setting']['_etc_ssh_sshd_config_group_owner_Path']
    group node['rhel9STIG']['stigrule_257997']['Setting']['_etc_ssh_sshd_config_group_owner_Group']
  end
end
if node['rhel9STIG']['stigrule_257998']['Manage']
  file '_etc_ssh_sshd_config_owner_257998' do
    path node['rhel9STIG']['stigrule_257998']['Setting']['_etc_ssh_sshd_config_owner_Path']
    owner node['rhel9STIG']['stigrule_257998']['Setting']['_etc_ssh_sshd_config_owner_Owner']
  end
end
if node['rhel9STIG']['stigrule_258003']['Manage']
  file_line 'GSSAPIAuthentication_258003' do
    path node['rhel9STIG']['stigrule_258003']['Setting']['GSSAPIAuthentication_Path']
    match node['rhel9STIG']['stigrule_258003']['Setting']['GSSAPIAuthentication_Regexp']
    line node['rhel9STIG']['stigrule_258003']['Setting']['GSSAPIAuthentication_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_258003']['Setting']['GSSAPIAuthentication_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258004']['Manage']
  file_line 'KerberosAuthentication_258004' do
    path node['rhel9STIG']['stigrule_258004']['Setting']['KerberosAuthentication_Path']
    match node['rhel9STIG']['stigrule_258004']['Setting']['KerberosAuthentication_Regexp']
    line node['rhel9STIG']['stigrule_258004']['Setting']['KerberosAuthentication_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_258004']['Setting']['KerberosAuthentication_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258005']['Manage']
  file_line 'IgnoreRhosts_258005' do
    path node['rhel9STIG']['stigrule_258005']['Setting']['IgnoreRhosts_Path']
    match node['rhel9STIG']['stigrule_258005']['Setting']['IgnoreRhosts_Regexp']
    line node['rhel9STIG']['stigrule_258005']['Setting']['IgnoreRhosts_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_258005']['Setting']['IgnoreRhosts_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258006']['Manage']
  file_line 'IgnoreUserKnownHosts_258006' do
    path node['rhel9STIG']['stigrule_258006']['Setting']['IgnoreUserKnownHosts_Path']
    match node['rhel9STIG']['stigrule_258006']['Setting']['IgnoreUserKnownHosts_Regexp']
    line node['rhel9STIG']['stigrule_258006']['Setting']['IgnoreUserKnownHosts_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_258006']['Setting']['IgnoreUserKnownHosts_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258007']['Manage']
  file_line 'X11Forwarding_258007' do
    path node['rhel9STIG']['stigrule_258007']['Setting']['X11Forwarding_Path']
    match node['rhel9STIG']['stigrule_258007']['Setting']['X11Forwarding_Regexp']
    line node['rhel9STIG']['stigrule_258007']['Setting']['X11Forwarding_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_258007']['Setting']['X11Forwarding_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258008']['Manage']
  file_line 'StrictModes_258008' do
    path node['rhel9STIG']['stigrule_258008']['Setting']['StrictModes_Path']
    match node['rhel9STIG']['stigrule_258008']['Setting']['StrictModes_Regexp']
    line node['rhel9STIG']['stigrule_258008']['Setting']['StrictModes_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_258008']['Setting']['StrictModes_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258009']['Manage']
  file_line 'PrintLastLog_258009' do
    path node['rhel9STIG']['stigrule_258009']['Setting']['PrintLastLog_Path']
    match node['rhel9STIG']['stigrule_258009']['Setting']['PrintLastLog_Regexp']
    line node['rhel9STIG']['stigrule_258009']['Setting']['PrintLastLog_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_258009']['Setting']['PrintLastLog_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258011']['Manage']
  file_line 'X11UseLocalhost_258011' do
    path node['rhel9STIG']['stigrule_258011']['Setting']['X11UseLocalhost_Path']
    match node['rhel9STIG']['stigrule_258011']['Setting']['X11UseLocalhost_Regexp']
    line node['rhel9STIG']['stigrule_258011']['Setting']['X11UseLocalhost_Line']
    notifies :restart, 'service[ssh_restart]', :delayed
    only_if node['rhel9STIG']['stigrule_258011']['Setting']['X11UseLocalhost_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258012']['Manage']
  _etc_dconf_db_local_d_01_banner_message_Path = node['rhel9STIG']['stigrule_258012']['Setting']['_etc_dconf_db_local_d_01_banner_message_Path']
  _etc_dconf_db_local_d_01_banner_message_Dir = ::File.dirname(_etc_dconf_db_local_d_01_banner_message_Path)
  directory _etc_dconf_db_local_d_01_banner_message_Dir do
    recursive true
  end
  file _etc_dconf_db_local_d_01_banner_message_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_01_banner_message_Path) }
  end
  ini_setting '_etc_dconf_db_local_d_01_banner_message_258012' do
    path _etc_dconf_db_local_d_01_banner_message_Path
    section node['rhel9STIG']['stigrule_258012']['Setting']['_etc_dconf_db_local_d_01_banner_message_Section']
    setting node['rhel9STIG']['stigrule_258012']['Setting']['_etc_dconf_db_local_d_01_banner_message_Option']
    value node['rhel9STIG']['stigrule_258012']['Setting']['_etc_dconf_db_local_d_01_banner_message_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258012']['Setting']['_etc_dconf_db_local_d_01_banner_message_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258013']['Manage']
  _etc_dconf_db_local_d_locks_session_banner_message_enable_Path = node['rhel9STIG']['stigrule_258013']['Setting']['_etc_dconf_db_local_d_locks_session_banner_message_enable_Path']
  file _etc_dconf_db_local_d_locks_session_banner_message_enable_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_locks_session_banner_message_enable_Path) }
  end
  file_line '_etc_dconf_db_local_d_locks_session_banner_message_enable_258013' do
    path _etc_dconf_db_local_d_locks_session_banner_message_enable_Path
    line node['rhel9STIG']['stigrule_258013']['Setting']['_etc_dconf_db_local_d_locks_session_banner_message_enable_Line']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258013']['Setting']['_etc_dconf_db_local_d_locks_session_banner_message_enable_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258014']['Manage']
  _etc_dconf_db_local_d_00_security_settings_Path = node['rhel9STIG']['stigrule_258014']['Setting']['_etc_dconf_db_local_d_00_security_settings_Path']
  _etc_dconf_db_local_d_00_security_settings_Dir = ::File.dirname(_etc_dconf_db_local_d_00_security_settings_Path)
  directory _etc_dconf_db_local_d_00_security_settings_Dir do
    recursive true
  end
  file _etc_dconf_db_local_d_00_security_settings_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_00_security_settings_Path) }
  end
  ini_setting '_etc_dconf_db_local_d_00_security_settings_258014' do
    path _etc_dconf_db_local_d_00_security_settings_Path
    section node['rhel9STIG']['stigrule_258014']['Setting']['_etc_dconf_db_local_d_00_security_settings_Section']
    setting node['rhel9STIG']['stigrule_258014']['Setting']['_etc_dconf_db_local_d_00_security_settings_Option']
    value node['rhel9STIG']['stigrule_258014']['Setting']['_etc_dconf_db_local_d_00_security_settings_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258014']['Setting']['_etc_dconf_db_local_d_00_security_settings_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258015']['Manage']
  _etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_Path = node['rhel9STIG']['stigrule_258015']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_Path']
  file _etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_Path) }
  end
  file_line '_etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_258015' do
    path _etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_Path
    line node['rhel9STIG']['stigrule_258015']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_Line']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258015']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_automount_open_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258016']['Manage']
  _etc_dconf_db_local_d_00_security_settings_Path = node['rhel9STIG']['stigrule_258016']['Setting']['_etc_dconf_db_local_d_00_security_settings_Path']
  _etc_dconf_db_local_d_00_security_settings_Dir = ::File.dirname(_etc_dconf_db_local_d_00_security_settings_Path)
  directory _etc_dconf_db_local_d_00_security_settings_Dir do
    recursive true
  end
  file _etc_dconf_db_local_d_00_security_settings_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_00_security_settings_Path) }
  end
  ini_setting '_etc_dconf_db_local_d_00_security_settings_258016' do
    path _etc_dconf_db_local_d_00_security_settings_Path
    section node['rhel9STIG']['stigrule_258016']['Setting']['_etc_dconf_db_local_d_00_security_settings_Section']
    setting node['rhel9STIG']['stigrule_258016']['Setting']['_etc_dconf_db_local_d_00_security_settings_Option']
    value node['rhel9STIG']['stigrule_258016']['Setting']['_etc_dconf_db_local_d_00_security_settings_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258016']['Setting']['_etc_dconf_db_local_d_00_security_settings_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258017']['Manage']
  _etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_Path = node['rhel9STIG']['stigrule_258017']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_Path']
  file _etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_Path) }
  end
  file_line '_etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_258017' do
    path _etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_Path
    line node['rhel9STIG']['stigrule_258017']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_Line']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258017']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_autorun_never_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258019']['Manage']
  _etc_dconf_db_local_d_00_security_settings_Path = node['rhel9STIG']['stigrule_258019']['Setting']['_etc_dconf_db_local_d_00_security_settings_Path']
  _etc_dconf_db_local_d_00_security_settings_Dir = ::File.dirname(_etc_dconf_db_local_d_00_security_settings_Path)
  directory _etc_dconf_db_local_d_00_security_settings_Dir do
    recursive true
  end
  file _etc_dconf_db_local_d_00_security_settings_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_00_security_settings_Path) }
  end
  ini_setting '_etc_dconf_db_local_d_00_security_settings_258019' do
    path _etc_dconf_db_local_d_00_security_settings_Path
    section node['rhel9STIG']['stigrule_258019']['Setting']['_etc_dconf_db_local_d_00_security_settings_Section']
    setting node['rhel9STIG']['stigrule_258019']['Setting']['_etc_dconf_db_local_d_00_security_settings_Option']
    value node['rhel9STIG']['stigrule_258019']['Setting']['_etc_dconf_db_local_d_00_security_settings_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258019']['Setting']['_etc_dconf_db_local_d_00_security_settings_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258020']['Manage']
  _etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_Path = node['rhel9STIG']['stigrule_258020']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_Path']
  file _etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_Path) }
  end
  file_line '_etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_258020' do
    path _etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_Path
    line node['rhel9STIG']['stigrule_258020']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_Line']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258020']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_removal_action_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258021']['Manage']
  _etc_dconf_db_local_d_00_screensaver_Path = node['rhel9STIG']['stigrule_258021']['Setting']['_etc_dconf_db_local_d_00_screensaver_Path']
  _etc_dconf_db_local_d_00_screensaver_Dir = ::File.dirname(_etc_dconf_db_local_d_00_screensaver_Path)
  directory _etc_dconf_db_local_d_00_screensaver_Dir do
    recursive true
  end
  file _etc_dconf_db_local_d_00_screensaver_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_00_screensaver_Path) }
  end
  ini_setting '_etc_dconf_db_local_d_00_screensaver_258021' do
    path _etc_dconf_db_local_d_00_screensaver_Path
    section node['rhel9STIG']['stigrule_258021']['Setting']['_etc_dconf_db_local_d_00_screensaver_Section']
    setting node['rhel9STIG']['stigrule_258021']['Setting']['_etc_dconf_db_local_d_00_screensaver_Option']
    value node['rhel9STIG']['stigrule_258021']['Setting']['_etc_dconf_db_local_d_00_screensaver_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258021']['Setting']['_etc_dconf_db_local_d_00_screensaver_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258022']['Manage']
  _etc_dconf_db_local_d_locks_session_lock_enabled_Path = node['rhel9STIG']['stigrule_258022']['Setting']['_etc_dconf_db_local_d_locks_session_lock_enabled_Path']
  file _etc_dconf_db_local_d_locks_session_lock_enabled_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_locks_session_lock_enabled_Path) }
  end
  file_line '_etc_dconf_db_local_d_locks_session_lock_enabled_258022' do
    path _etc_dconf_db_local_d_locks_session_lock_enabled_Path
    line node['rhel9STIG']['stigrule_258022']['Setting']['_etc_dconf_db_local_d_locks_session_lock_enabled_Line']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258022']['Setting']['_etc_dconf_db_local_d_locks_session_lock_enabled_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258023']['Manage']
  _etc_dconf_db_local_d_00_screensaver_Path = node['rhel9STIG']['stigrule_258023']['Setting']['_etc_dconf_db_local_d_00_screensaver_Path']
  _etc_dconf_db_local_d_00_screensaver_Dir = ::File.dirname(_etc_dconf_db_local_d_00_screensaver_Path)
  directory _etc_dconf_db_local_d_00_screensaver_Dir do
    recursive true
  end
  file _etc_dconf_db_local_d_00_screensaver_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_00_screensaver_Path) }
  end
  ini_setting '_etc_dconf_db_local_d_00_screensaver_258023' do
    path _etc_dconf_db_local_d_00_screensaver_Path
    section node['rhel9STIG']['stigrule_258023']['Setting']['_etc_dconf_db_local_d_00_screensaver_Section']
    setting node['rhel9STIG']['stigrule_258023']['Setting']['_etc_dconf_db_local_d_00_screensaver_Option']
    value node['rhel9STIG']['stigrule_258023']['Setting']['_etc_dconf_db_local_d_00_screensaver_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258023']['Setting']['_etc_dconf_db_local_d_00_screensaver_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258024']['Manage']
  _etc_dconf_db_local_d_locks_session_idle_delay_Path = node['rhel9STIG']['stigrule_258024']['Setting']['_etc_dconf_db_local_d_locks_session_idle_delay_Path']
  file _etc_dconf_db_local_d_locks_session_idle_delay_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_locks_session_idle_delay_Path) }
  end
  file_line '_etc_dconf_db_local_d_locks_session_idle_delay_258024' do
    path _etc_dconf_db_local_d_locks_session_idle_delay_Path
    line node['rhel9STIG']['stigrule_258024']['Setting']['_etc_dconf_db_local_d_locks_session_idle_delay_Line']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258024']['Setting']['_etc_dconf_db_local_d_locks_session_idle_delay_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258025']['Manage']
  _etc_dconf_db_local_d_00_screensaver_Path = node['rhel9STIG']['stigrule_258025']['Setting']['_etc_dconf_db_local_d_00_screensaver_Path']
  _etc_dconf_db_local_d_00_screensaver_Dir = ::File.dirname(_etc_dconf_db_local_d_00_screensaver_Path)
  directory _etc_dconf_db_local_d_00_screensaver_Dir do
    recursive true
  end
  file _etc_dconf_db_local_d_00_screensaver_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_00_screensaver_Path) }
  end
  ini_setting '_etc_dconf_db_local_d_00_screensaver_258025' do
    path _etc_dconf_db_local_d_00_screensaver_Path
    section node['rhel9STIG']['stigrule_258025']['Setting']['_etc_dconf_db_local_d_00_screensaver_Section']
    setting node['rhel9STIG']['stigrule_258025']['Setting']['_etc_dconf_db_local_d_00_screensaver_Option']
    value node['rhel9STIG']['stigrule_258025']['Setting']['_etc_dconf_db_local_d_00_screensaver_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258025']['Setting']['_etc_dconf_db_local_d_00_screensaver_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258026']['Manage']
  _etc_dconf_db_local_d_locks_session_lock_delay_Path = node['rhel9STIG']['stigrule_258026']['Setting']['_etc_dconf_db_local_d_locks_session_lock_delay_Path']
  file _etc_dconf_db_local_d_locks_session_lock_delay_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_locks_session_lock_delay_Path) }
  end
  file_line '_etc_dconf_db_local_d_locks_session_lock_delay_258026' do
    path _etc_dconf_db_local_d_locks_session_lock_delay_Path
    line node['rhel9STIG']['stigrule_258026']['Setting']['_etc_dconf_db_local_d_locks_session_lock_delay_Line']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258026']['Setting']['_etc_dconf_db_local_d_locks_session_lock_delay_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258027']['Manage']
  _etc_dconf_db_local_d_00_security_settings_Path = node['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_00_security_settings_Path']
  _etc_dconf_db_local_d_00_security_settings_Dir = ::File.dirname(_etc_dconf_db_local_d_00_security_settings_Path)
  directory _etc_dconf_db_local_d_00_security_settings_Dir do
    recursive true
  end
  file _etc_dconf_db_local_d_00_security_settings_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_00_security_settings_Path) }
  end
  ini_setting '_etc_dconf_db_local_d_00_security_settings_258027' do
    path _etc_dconf_db_local_d_00_security_settings_Path
    section node['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_00_security_settings_Section']
    setting node['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_00_security_settings_Option']
    value node['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_00_security_settings_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_00_security_settings_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258027']['Manage']
  _etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_Path = node['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_Path']
  file _etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_Path) }
  end
  file_line '_etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_258027' do
    path _etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_Path
    line node['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_Line']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258027']['Setting']['_etc_dconf_db_local_d_locks_00_security_settings_lock_picture_uri_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258030']['Manage']
  _etc_dconf_db_local_d_locks_session_disable_restart_buttons_Path = node['rhel9STIG']['stigrule_258030']['Setting']['_etc_dconf_db_local_d_locks_session_disable_restart_buttons_Path']
  file _etc_dconf_db_local_d_locks_session_disable_restart_buttons_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_locks_session_disable_restart_buttons_Path) }
  end
  file_line '_etc_dconf_db_local_d_locks_session_disable_restart_buttons_258030' do
    path _etc_dconf_db_local_d_locks_session_disable_restart_buttons_Path
    line node['rhel9STIG']['stigrule_258030']['Setting']['_etc_dconf_db_local_d_locks_session_disable_restart_buttons_Line']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258030']['Setting']['_etc_dconf_db_local_d_locks_session_disable_restart_buttons_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258031']['Manage']
  _etc_dconf_db_local_d_00_security_settings_Path = node['rhel9STIG']['stigrule_258031']['Setting']['_etc_dconf_db_local_d_00_security_settings_Path']
  _etc_dconf_db_local_d_00_security_settings_Dir = ::File.dirname(_etc_dconf_db_local_d_00_security_settings_Path)
  directory _etc_dconf_db_local_d_00_security_settings_Dir do
    recursive true
  end
  file _etc_dconf_db_local_d_00_security_settings_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_00_security_settings_Path) }
  end
  ini_setting '_etc_dconf_db_local_d_00_security_settings_258031' do
    path _etc_dconf_db_local_d_00_security_settings_Path
    section node['rhel9STIG']['stigrule_258031']['Setting']['_etc_dconf_db_local_d_00_security_settings_Section']
    setting node['rhel9STIG']['stigrule_258031']['Setting']['_etc_dconf_db_local_d_00_security_settings_Option']
    value node['rhel9STIG']['stigrule_258031']['Setting']['_etc_dconf_db_local_d_00_security_settings_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258031']['Setting']['_etc_dconf_db_local_d_00_security_settings_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258032']['Manage']
  _etc_dconf_db_local_d_locks_session_logout_Path = node['rhel9STIG']['stigrule_258032']['Setting']['_etc_dconf_db_local_d_locks_session_logout_Path']
  file _etc_dconf_db_local_d_locks_session_logout_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_locks_session_logout_Path) }
  end
  file_line '_etc_dconf_db_local_d_locks_session_logout_258032' do
    path _etc_dconf_db_local_d_locks_session_logout_Path
    line node['rhel9STIG']['stigrule_258032']['Setting']['_etc_dconf_db_local_d_locks_session_logout_Line']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258032']['Setting']['_etc_dconf_db_local_d_locks_session_logout_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258033']['Manage']
  _etc_dconf_db_local_d_02_login_screen_Path = node['rhel9STIG']['stigrule_258033']['Setting']['_etc_dconf_db_local_d_02_login_screen_Path']
  _etc_dconf_db_local_d_02_login_screen_Dir = ::File.dirname(_etc_dconf_db_local_d_02_login_screen_Path)
  directory _etc_dconf_db_local_d_02_login_screen_Dir do
    recursive true
  end
  file _etc_dconf_db_local_d_02_login_screen_Path do
    action :create
    not_if { ::File.exist?(_etc_dconf_db_local_d_02_login_screen_Path) }
  end
  ini_setting '_etc_dconf_db_local_d_02_login_screen_258033' do
    path _etc_dconf_db_local_d_02_login_screen_Path
    section node['rhel9STIG']['stigrule_258033']['Setting']['_etc_dconf_db_local_d_02_login_screen_Section']
    setting node['rhel9STIG']['stigrule_258033']['Setting']['_etc_dconf_db_local_d_02_login_screen_Option']
    value node['rhel9STIG']['stigrule_258033']['Setting']['_etc_dconf_db_local_d_02_login_screen_Value']
    notifies :run, 'execute[dconf_update]', :delayed
    only_if node['rhel9STIG']['stigrule_258033']['Setting']['_etc_dconf_db_local_d_02_login_screen_Only_if']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258034']['Manage']
  _etc_modprobe_d_usb_storage_conf_install_usb_storage__bin_false_Path = node['rhel9STIG']['stigrule_258034']['Setting']['_etc_modprobe_d_usb_storage_conf_install_usb_storage__bin_false_Path']
  file _etc_modprobe_d_usb_storage_conf_install_usb_storage__bin_false_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_usb_storage_conf_install_usb_storage__bin_false_Path) }
  end
  file_line '_etc_modprobe_d_usb_storage_conf_install_usb_storage__bin_false_258034' do
    path _etc_modprobe_d_usb_storage_conf_install_usb_storage__bin_false_Path
    line node['rhel9STIG']['stigrule_258034']['Setting']['_etc_modprobe_d_usb_storage_conf_install_usb_storage__bin_false_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258034']['Manage']
  _etc_modprobe_d_usb_storage_conf_blacklist_usb_storage_Path = node['rhel9STIG']['stigrule_258034']['Setting']['_etc_modprobe_d_usb_storage_conf_blacklist_usb_storage_Path']
  file _etc_modprobe_d_usb_storage_conf_blacklist_usb_storage_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_usb_storage_conf_blacklist_usb_storage_Path) }
  end
  file_line '_etc_modprobe_d_usb_storage_conf_blacklist_usb_storage_258034' do
    path _etc_modprobe_d_usb_storage_conf_blacklist_usb_storage_Path
    line node['rhel9STIG']['stigrule_258034']['Setting']['_etc_modprobe_d_usb_storage_conf_blacklist_usb_storage_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258035']['Manage']
  dnf_package 'usbguard_258035' do
    package_name node['rhel9STIG']['stigrule_258035']['Setting']['usbguard_PackageName']
    action node['rhel9STIG']['stigrule_258035']['Setting']['usbguard_Action']
  end
end
if node['rhel9STIG']['stigrule_258035']['Manage']
  service 'usbguard_enable_258035' do
    service_name node['rhel9STIG']['stigrule_258035']['Setting']['usbguard_enable_ServiceName']
    action node['rhel9STIG']['stigrule_258035']['Setting']['usbguard_enable_Action']
  end
end
if node['rhel9STIG']['stigrule_258035']['Manage']
  service 'usbguard_start_258035' do
    service_name node['rhel9STIG']['stigrule_258035']['Setting']['usbguard_start_ServiceName']
    action node['rhel9STIG']['stigrule_258035']['Setting']['usbguard_start_Action']
  end
end
if node['rhel9STIG']['stigrule_258036']['Manage']
  service 'usbguard_enable_258036' do
    service_name node['rhel9STIG']['stigrule_258036']['Setting']['usbguard_enable_ServiceName']
    action node['rhel9STIG']['stigrule_258036']['Setting']['usbguard_enable_Action']
  end
end
if node['rhel9STIG']['stigrule_258036']['Manage']
  service 'usbguard_start_258036' do
    service_name node['rhel9STIG']['stigrule_258036']['Setting']['usbguard_start_ServiceName']
    action node['rhel9STIG']['stigrule_258036']['Setting']['usbguard_start_Action']
  end
end
if node['rhel9STIG']['stigrule_258037']['Manage']
  _etc_usbguard_usbguard_daemon_conf_Path = node['rhel9STIG']['stigrule_258037']['Setting']['_etc_usbguard_usbguard_daemon_conf_Path']
  file _etc_usbguard_usbguard_daemon_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_usbguard_usbguard_daemon_conf_Path) }
  end
  file_line '_etc_usbguard_usbguard_daemon_conf_258037' do
    path _etc_usbguard_usbguard_daemon_conf_Path
    match node['rhel9STIG']['stigrule_258037']['Setting']['_etc_usbguard_usbguard_daemon_conf_Regexp']
    line node['rhel9STIG']['stigrule_258037']['Setting']['_etc_usbguard_usbguard_daemon_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258039']['Manage']
  _etc_modprobe_d_bluetooth_conf_install_bluetooth__bin_false_Path = node['rhel9STIG']['stigrule_258039']['Setting']['_etc_modprobe_d_bluetooth_conf_install_bluetooth__bin_false_Path']
  file _etc_modprobe_d_bluetooth_conf_install_bluetooth__bin_false_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_bluetooth_conf_install_bluetooth__bin_false_Path) }
  end
  file_line '_etc_modprobe_d_bluetooth_conf_install_bluetooth__bin_false_258039' do
    path _etc_modprobe_d_bluetooth_conf_install_bluetooth__bin_false_Path
    line node['rhel9STIG']['stigrule_258039']['Setting']['_etc_modprobe_d_bluetooth_conf_install_bluetooth__bin_false_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258039']['Manage']
  _etc_modprobe_d_bluetooth_conf_blacklist_bluetooth_Path = node['rhel9STIG']['stigrule_258039']['Setting']['_etc_modprobe_d_bluetooth_conf_blacklist_bluetooth_Path']
  file _etc_modprobe_d_bluetooth_conf_blacklist_bluetooth_Path do
    action :create
    not_if { ::File.exist?(_etc_modprobe_d_bluetooth_conf_blacklist_bluetooth_Path) }
  end
  file_line '_etc_modprobe_d_bluetooth_conf_blacklist_bluetooth_258039' do
    path _etc_modprobe_d_bluetooth_conf_blacklist_bluetooth_Path
    line node['rhel9STIG']['stigrule_258039']['Setting']['_etc_modprobe_d_bluetooth_conf_blacklist_bluetooth_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258040']['Manage']
  execute 'nmcli_radio_wifi_off_258040' do
    command node['rhel9STIG']['stigrule_258040']['Setting']['nmcli_radio_wifi_off_Command']
    only_if node['rhel9STIG']['stigrule_258040']['Setting']['nmcli_radio_wifi_off_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258041']['Manage']
  _etc_login_defs_Path = node['rhel9STIG']['stigrule_258041']['Setting']['_etc_login_defs_Path']
  file _etc_login_defs_Path do
    action :create
    not_if { ::File.exist?(_etc_login_defs_Path) }
  end
  file_line '_etc_login_defs_258041' do
    path _etc_login_defs_Path
    match node['rhel9STIG']['stigrule_258041']['Setting']['_etc_login_defs_Regexp']
    line node['rhel9STIG']['stigrule_258041']['Setting']['_etc_login_defs_Line']
  end
end
if node['rhel9STIG']['stigrule_258043']['Manage']
  _etc_login_defs_Path = node['rhel9STIG']['stigrule_258043']['Setting']['_etc_login_defs_Path']
  file _etc_login_defs_Path do
    action :create
    not_if { ::File.exist?(_etc_login_defs_Path) }
  end
  file_line '_etc_login_defs_258043' do
    path _etc_login_defs_Path
    match node['rhel9STIG']['stigrule_258043']['Setting']['_etc_login_defs_Regexp']
    line node['rhel9STIG']['stigrule_258043']['Setting']['_etc_login_defs_Line']
  end
end
if node['rhel9STIG']['stigrule_258049']['Manage']
  execute 'sudo_useradd__D__f_35_258049' do
    command node['rhel9STIG']['stigrule_258049']['Setting']['sudo_useradd__D__f_35_Command']
    only_if node['rhel9STIG']['stigrule_258049']['Setting']['sudo_useradd__D__f_35_Only_if']
  end
end
if node['rhel9STIG']['stigrule_258054']['Manage']
  _etc_security_faillock_conf_Path = node['rhel9STIG']['stigrule_258054']['Setting']['_etc_security_faillock_conf_Path']
  file _etc_security_faillock_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_faillock_conf_Path) }
  end
  file_line '_etc_security_faillock_conf_258054' do
    path _etc_security_faillock_conf_Path
    match node['rhel9STIG']['stigrule_258054']['Setting']['_etc_security_faillock_conf_Regexp']
    line node['rhel9STIG']['stigrule_258054']['Setting']['_etc_security_faillock_conf_Line']
    notifies :run, 'execute[with_faillock_enable]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258055']['Manage']
  _etc_security_faillock_conf_Path = node['rhel9STIG']['stigrule_258055']['Setting']['_etc_security_faillock_conf_Path']
  file _etc_security_faillock_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_faillock_conf_Path) }
  end
  file_line '_etc_security_faillock_conf_258055' do
    path _etc_security_faillock_conf_Path
    match node['rhel9STIG']['stigrule_258055']['Setting']['_etc_security_faillock_conf_Regexp']
    line node['rhel9STIG']['stigrule_258055']['Setting']['_etc_security_faillock_conf_Line']
    notifies :run, 'execute[with_faillock_enable]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258056']['Manage']
  _etc_security_faillock_conf_Path = node['rhel9STIG']['stigrule_258056']['Setting']['_etc_security_faillock_conf_Path']
  file _etc_security_faillock_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_faillock_conf_Path) }
  end
  file_line '_etc_security_faillock_conf_258056' do
    path _etc_security_faillock_conf_Path
    match node['rhel9STIG']['stigrule_258056']['Setting']['_etc_security_faillock_conf_Regexp']
    line node['rhel9STIG']['stigrule_258056']['Setting']['_etc_security_faillock_conf_Line']
    notifies :run, 'execute[with_faillock_enable]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258057']['Manage']
  _etc_security_faillock_conf_Path = node['rhel9STIG']['stigrule_258057']['Setting']['_etc_security_faillock_conf_Path']
  file _etc_security_faillock_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_faillock_conf_Path) }
  end
  file_line '_etc_security_faillock_conf_258057' do
    path _etc_security_faillock_conf_Path
    match node['rhel9STIG']['stigrule_258057']['Setting']['_etc_security_faillock_conf_Regexp']
    line node['rhel9STIG']['stigrule_258057']['Setting']['_etc_security_faillock_conf_Line']
    notifies :run, 'execute[with_faillock_enable]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258060']['Manage']
  _etc_security_faillock_conf_Path = node['rhel9STIG']['stigrule_258060']['Setting']['_etc_security_faillock_conf_Path']
  file _etc_security_faillock_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_faillock_conf_Path) }
  end
  file_line '_etc_security_faillock_conf_258060' do
    path _etc_security_faillock_conf_Path
    match node['rhel9STIG']['stigrule_258060']['Setting']['_etc_security_faillock_conf_Regexp']
    line node['rhel9STIG']['stigrule_258060']['Setting']['_etc_security_faillock_conf_Line']
    notifies :run, 'execute[with_faillock_enable]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258069']['Manage']
  _etc_security_limits_conf_Path = node['rhel9STIG']['stigrule_258069']['Setting']['_etc_security_limits_conf_Path']
  file _etc_security_limits_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_limits_conf_Path) }
  end
  file_line '_etc_security_limits_conf_258069' do
    path _etc_security_limits_conf_Path
    match node['rhel9STIG']['stigrule_258069']['Setting']['_etc_security_limits_conf_Regexp']
    line node['rhel9STIG']['stigrule_258069']['Setting']['_etc_security_limits_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258070']['Manage']
  _etc_security_faillock_conf_Path = node['rhel9STIG']['stigrule_258070']['Setting']['_etc_security_faillock_conf_Path']
  file _etc_security_faillock_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_faillock_conf_Path) }
  end
  file_line '_etc_security_faillock_conf_258070' do
    path _etc_security_faillock_conf_Path
    match node['rhel9STIG']['stigrule_258070']['Setting']['_etc_security_faillock_conf_Regexp']
    line node['rhel9STIG']['stigrule_258070']['Setting']['_etc_security_faillock_conf_Line']
    notifies :run, 'execute[with_faillock_enable]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258071']['Manage']
  _etc_login_defs_Path = node['rhel9STIG']['stigrule_258071']['Setting']['_etc_login_defs_Path']
  file _etc_login_defs_Path do
    action :create
    not_if { ::File.exist?(_etc_login_defs_Path) }
  end
  file_line '_etc_login_defs_258071' do
    path _etc_login_defs_Path
    match node['rhel9STIG']['stigrule_258071']['Setting']['_etc_login_defs_Regexp']
    line node['rhel9STIG']['stigrule_258071']['Setting']['_etc_login_defs_Line']
  end
end
if node['rhel9STIG']['stigrule_258072']['Manage']
  _etc_bashrc_Path = node['rhel9STIG']['stigrule_258072']['Setting']['_etc_bashrc_Path']
  file _etc_bashrc_Path do
    action :create
    not_if { ::File.exist?(_etc_bashrc_Path) }
  end
  file_line '_etc_bashrc_258072' do
    path _etc_bashrc_Path
    match node['rhel9STIG']['stigrule_258072']['Setting']['_etc_bashrc_Regexp']
    line node['rhel9STIG']['stigrule_258072']['Setting']['_etc_bashrc_Line']
  end
end
if node['rhel9STIG']['stigrule_258073']['Manage']
  _etc_csh_cshrc_Path = node['rhel9STIG']['stigrule_258073']['Setting']['_etc_csh_cshrc_Path']
  file _etc_csh_cshrc_Path do
    action :create
    not_if { ::File.exist?(_etc_csh_cshrc_Path) }
  end
  file_line '_etc_csh_cshrc_258073' do
    path _etc_csh_cshrc_Path
    match node['rhel9STIG']['stigrule_258073']['Setting']['_etc_csh_cshrc_Regexp']
    line node['rhel9STIG']['stigrule_258073']['Setting']['_etc_csh_cshrc_Line']
  end
end
if node['rhel9STIG']['stigrule_258074']['Manage']
  _etc_login_defs_Path = node['rhel9STIG']['stigrule_258074']['Setting']['_etc_login_defs_Path']
  file _etc_login_defs_Path do
    action :create
    not_if { ::File.exist?(_etc_login_defs_Path) }
  end
  file_line '_etc_login_defs_258074' do
    path _etc_login_defs_Path
    match node['rhel9STIG']['stigrule_258074']['Setting']['_etc_login_defs_Regexp']
    line node['rhel9STIG']['stigrule_258074']['Setting']['_etc_login_defs_Line']
  end
end
if node['rhel9STIG']['stigrule_258075']['Manage']
  _etc_profile_Path = node['rhel9STIG']['stigrule_258075']['Setting']['_etc_profile_Path']
  file _etc_profile_Path do
    action :create
    not_if { ::File.exist?(_etc_profile_Path) }
  end
  file_line '_etc_profile_258075' do
    path _etc_profile_Path
    match node['rhel9STIG']['stigrule_258075']['Setting']['_etc_profile_Regexp']
    line node['rhel9STIG']['stigrule_258075']['Setting']['_etc_profile_Line']
  end
end
if node['rhel9STIG']['stigrule_258078']['Manage']
  _etc_selinux_config_Path = node['rhel9STIG']['stigrule_258078']['Setting']['_etc_selinux_config_Path']
  file _etc_selinux_config_Path do
    action :create
    not_if { ::File.exist?(_etc_selinux_config_Path) }
  end
  file_line '_etc_selinux_config_258078' do
    path _etc_selinux_config_Path
    match node['rhel9STIG']['stigrule_258078']['Setting']['_etc_selinux_config_Regexp']
    line node['rhel9STIG']['stigrule_258078']['Setting']['_etc_selinux_config_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258079']['Manage']
  _etc_selinux_config_Path = node['rhel9STIG']['stigrule_258079']['Setting']['_etc_selinux_config_Path']
  file _etc_selinux_config_Path do
    action :create
    not_if { ::File.exist?(_etc_selinux_config_Path) }
  end
  file_line '_etc_selinux_config_258079' do
    path _etc_selinux_config_Path
    match node['rhel9STIG']['stigrule_258079']['Setting']['_etc_selinux_config_Regexp']
    line node['rhel9STIG']['stigrule_258079']['Setting']['_etc_selinux_config_Line']
    notifies :run, 'execute[do_reboot]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258081']['Manage']
  dnf_package 'policycoreutils_258081' do
    package_name node['rhel9STIG']['stigrule_258081']['Setting']['policycoreutils_PackageName']
    action node['rhel9STIG']['stigrule_258081']['Setting']['policycoreutils_Action']
  end
end
if node['rhel9STIG']['stigrule_258082']['Manage']
  dnf_package 'policycoreutils_python_utils_258082' do
    package_name node['rhel9STIG']['stigrule_258082']['Setting']['policycoreutils_python_utils_PackageName']
    action node['rhel9STIG']['stigrule_258082']['Setting']['policycoreutils_python_utils_Action']
  end
end
if node['rhel9STIG']['stigrule_258083']['Manage']
  dnf_package 'sudo_258083' do
    package_name node['rhel9STIG']['stigrule_258083']['Setting']['sudo_PackageName']
    action node['rhel9STIG']['stigrule_258083']['Setting']['sudo_Action']
  end
end
if node['rhel9STIG']['stigrule_258084']['Manage']
  _etc_sudoers_Path = node['rhel9STIG']['stigrule_258084']['Setting']['_etc_sudoers_Path']
  file _etc_sudoers_Path do
    action :create
    not_if { ::File.exist?(_etc_sudoers_Path) }
  end
  file_line '_etc_sudoers_258084' do
    path _etc_sudoers_Path
    match node['rhel9STIG']['stigrule_258084']['Setting']['_etc_sudoers_Regexp']
    line node['rhel9STIG']['stigrule_258084']['Setting']['_etc_sudoers_Line']
  end
end
if node['rhel9STIG']['stigrule_258089']['Manage']
  dnf_package 'fapolicyd_258089' do
    package_name node['rhel9STIG']['stigrule_258089']['Setting']['fapolicyd_PackageName']
    action node['rhel9STIG']['stigrule_258089']['Setting']['fapolicyd_Action']
  end
end
if node['rhel9STIG']['stigrule_258090']['Manage']
  service 'fapolicyd_enable_258090' do
    service_name node['rhel9STIG']['stigrule_258090']['Setting']['fapolicyd_enable_ServiceName']
    action node['rhel9STIG']['stigrule_258090']['Setting']['fapolicyd_enable_Action']
  end
end
if node['rhel9STIG']['stigrule_258090']['Manage']
  service 'fapolicyd_start_258090' do
    service_name node['rhel9STIG']['stigrule_258090']['Setting']['fapolicyd_start_ServiceName']
    action node['rhel9STIG']['stigrule_258090']['Setting']['fapolicyd_start_Action']
  end
end
if node['rhel9STIG']['stigrule_258101']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258101']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258101' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258101']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258101']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258102']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258102']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258102' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258102']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258102']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258103']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258103']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258103' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258103']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258103']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258104']['Manage']
  _etc_login_defs_Path = node['rhel9STIG']['stigrule_258104']['Setting']['_etc_login_defs_Path']
  file _etc_login_defs_Path do
    action :create
    not_if { ::File.exist?(_etc_login_defs_Path) }
  end
  file_line '_etc_login_defs_258104' do
    path _etc_login_defs_Path
    match node['rhel9STIG']['stigrule_258104']['Setting']['_etc_login_defs_Regexp']
    line node['rhel9STIG']['stigrule_258104']['Setting']['_etc_login_defs_Line']
  end
end
if node['rhel9STIG']['stigrule_258107']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258107']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258107' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258107']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258107']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258109']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258109']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258109' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258109']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258109']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258110']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258110']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258110' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258110']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258110']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258111']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258111']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258111' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258111']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258111']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258112']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258112']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258112' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258112']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258112']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258113']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258113']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258113' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258113']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258113']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258114']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258114']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258114' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258114']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258114']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258115']['Manage']
  _etc_security_pwquality_conf_Path = node['rhel9STIG']['stigrule_258115']['Setting']['_etc_security_pwquality_conf_Path']
  file _etc_security_pwquality_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_security_pwquality_conf_Path) }
  end
  file_line '_etc_security_pwquality_conf_258115' do
    path _etc_security_pwquality_conf_Path
    match node['rhel9STIG']['stigrule_258115']['Setting']['_etc_security_pwquality_conf_Regexp']
    line node['rhel9STIG']['stigrule_258115']['Setting']['_etc_security_pwquality_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258116']['Manage']
  _etc_libuser_conf_Path = node['rhel9STIG']['stigrule_258116']['Setting']['_etc_libuser_conf_Path']
  _etc_libuser_conf_Dir = ::File.dirname(_etc_libuser_conf_Path)
  directory _etc_libuser_conf_Dir do
    recursive true
  end
  file _etc_libuser_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_libuser_conf_Path) }
  end
  ini_setting '_etc_libuser_conf_258116' do
    path _etc_libuser_conf_Path
    section node['rhel9STIG']['stigrule_258116']['Setting']['_etc_libuser_conf_Section']
    setting node['rhel9STIG']['stigrule_258116']['Setting']['_etc_libuser_conf_Option']
    value node['rhel9STIG']['stigrule_258116']['Setting']['_etc_libuser_conf_Value']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258117']['Manage']
  _etc_login_defs_Path = node['rhel9STIG']['stigrule_258117']['Setting']['_etc_login_defs_Path']
  file _etc_login_defs_Path do
    action :create
    not_if { ::File.exist?(_etc_login_defs_Path) }
  end
  file_line '_etc_login_defs_258117' do
    path _etc_login_defs_Path
    match node['rhel9STIG']['stigrule_258117']['Setting']['_etc_login_defs_Regexp']
    line node['rhel9STIG']['stigrule_258117']['Setting']['_etc_login_defs_Line']
  end
end
if node['rhel9STIG']['stigrule_258121']['Manage']
  _etc_opensc_conf_Path = node['rhel9STIG']['stigrule_258121']['Setting']['_etc_opensc_conf_Path']
  file _etc_opensc_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_opensc_conf_Path) }
  end
  file_line '_etc_opensc_conf_258121' do
    path _etc_opensc_conf_Path
    match node['rhel9STIG']['stigrule_258121']['Setting']['_etc_opensc_conf_Regexp']
    line node['rhel9STIG']['stigrule_258121']['Setting']['_etc_opensc_conf_Line']
  end
end
if node['rhel9STIG']['stigrule_258122']['Manage']
  _etc_sssd_sssd_conf_Path = node['rhel9STIG']['stigrule_258122']['Setting']['_etc_sssd_sssd_conf_Path']
  _etc_sssd_sssd_conf_Dir = ::File.dirname(_etc_sssd_sssd_conf_Path)
  directory _etc_sssd_sssd_conf_Dir do
    recursive true
  end
  file _etc_sssd_sssd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_sssd_sssd_conf_Path) }
  end
  ini_setting '_etc_sssd_sssd_conf_258122' do
    path _etc_sssd_sssd_conf_Path
    section node['rhel9STIG']['stigrule_258122']['Setting']['_etc_sssd_sssd_conf_Section']
    setting node['rhel9STIG']['stigrule_258122']['Setting']['_etc_sssd_sssd_conf_Option']
    value node['rhel9STIG']['stigrule_258122']['Setting']['_etc_sssd_sssd_conf_Value']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258124']['Manage']
  dnf_package 'pcsc_lite_258124' do
    package_name node['rhel9STIG']['stigrule_258124']['Setting']['pcsc_lite_PackageName']
    action node['rhel9STIG']['stigrule_258124']['Setting']['pcsc_lite_Action']
  end
end
if node['rhel9STIG']['stigrule_258125']['Manage']
  service 'pcscd_enable_258125' do
    service_name node['rhel9STIG']['stigrule_258125']['Setting']['pcscd_enable_ServiceName']
    action node['rhel9STIG']['stigrule_258125']['Setting']['pcscd_enable_Action']
  end
end
if node['rhel9STIG']['stigrule_258125']['Manage']
  service 'pcscd_start_258125' do
    service_name node['rhel9STIG']['stigrule_258125']['Setting']['pcscd_start_ServiceName']
    action node['rhel9STIG']['stigrule_258125']['Setting']['pcscd_start_Action']
  end
end
if node['rhel9STIG']['stigrule_258126']['Manage']
  dnf_package 'opensc_258126' do
    package_name node['rhel9STIG']['stigrule_258126']['Setting']['opensc_PackageName']
    action node['rhel9STIG']['stigrule_258126']['Setting']['opensc_Action']
  end
end
if node['rhel9STIG']['stigrule_258128']['Manage']
  execute 'mkdir__p__etc_systemd_system_emergency_service_d_258128' do
    command node['rhel9STIG']['stigrule_258128']['Setting']['mkdir__p__etc_systemd_system_emergency_service_d_Command']
  end
end
if node['rhel9STIG']['stigrule_258128']['Manage']
  file '_etc_systemd_system_emergency_service_d_emergency_service_conf_258128' do
    path node['rhel9STIG']['stigrule_258128']['Setting']['_etc_systemd_system_emergency_service_d_emergency_service_conf_Path']
    content node['rhel9STIG']['stigrule_258128']['Setting']['_etc_systemd_system_emergency_service_d_emergency_service_conf_Content']
  end
end
if node['rhel9STIG']['stigrule_258128']['Manage']
  execute 'systemctl_daemon_reload_258128' do
    command node['rhel9STIG']['stigrule_258128']['Setting']['systemctl_daemon_reload_Command']
  end
end
if node['rhel9STIG']['stigrule_258133']['Manage']
  _etc_sssd_sssd_conf_Path = node['rhel9STIG']['stigrule_258133']['Setting']['_etc_sssd_sssd_conf_Path']
  _etc_sssd_sssd_conf_Dir = ::File.dirname(_etc_sssd_sssd_conf_Path)
  directory _etc_sssd_sssd_conf_Dir do
    recursive true
  end
  file _etc_sssd_sssd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_sssd_sssd_conf_Path) }
  end
  ini_setting '_etc_sssd_sssd_conf_258133' do
    path _etc_sssd_sssd_conf_Path
    section node['rhel9STIG']['stigrule_258133']['Setting']['_etc_sssd_sssd_conf_Section']
    setting node['rhel9STIG']['stigrule_258133']['Setting']['_etc_sssd_sssd_conf_Option']
    value node['rhel9STIG']['stigrule_258133']['Setting']['_etc_sssd_sssd_conf_Value']
    separator '='
  end
end
if node['rhel9STIG']['stigrule_258140']['Manage']
  dnf_package 'rsyslog_258140' do
    package_name node['rhel9STIG']['stigrule_258140']['Setting']['rsyslog_PackageName']
    action node['rhel9STIG']['stigrule_258140']['Setting']['rsyslog_Action']
  end
end
if node['rhel9STIG']['stigrule_258141']['Manage']
  dnf_package 'rsyslog_gnutls_258141' do
    package_name node['rhel9STIG']['stigrule_258141']['Setting']['rsyslog_gnutls_PackageName']
    action node['rhel9STIG']['stigrule_258141']['Setting']['rsyslog_gnutls_Action']
  end
end
if node['rhel9STIG']['stigrule_258142']['Manage']
  service 'rsyslog_enable_258142' do
    service_name node['rhel9STIG']['stigrule_258142']['Setting']['rsyslog_enable_ServiceName']
    action node['rhel9STIG']['stigrule_258142']['Setting']['rsyslog_enable_Action']
  end
end
if node['rhel9STIG']['stigrule_258142']['Manage']
  service 'rsyslog_start_258142' do
    service_name node['rhel9STIG']['stigrule_258142']['Setting']['rsyslog_start_ServiceName']
    action node['rhel9STIG']['stigrule_258142']['Setting']['rsyslog_start_Action']
  end
end
if node['rhel9STIG']['stigrule_258144']['Manage']
  _etc_rsyslog_conf_Path = node['rhel9STIG']['stigrule_258144']['Setting']['_etc_rsyslog_conf_Path']
  file _etc_rsyslog_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_rsyslog_conf_Path) }
  end
  file_line '_etc_rsyslog_conf_258144' do
    path _etc_rsyslog_conf_Path
    match node['rhel9STIG']['stigrule_258144']['Setting']['_etc_rsyslog_conf_Regexp']
    line node['rhel9STIG']['stigrule_258144']['Setting']['_etc_rsyslog_conf_Line']
    notifies :run, 'execute[rsyslog_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258146']['Manage']
  _etc_rsyslog_conf_Path = node['rhel9STIG']['stigrule_258146']['Setting']['_etc_rsyslog_conf_Path']
  file _etc_rsyslog_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_rsyslog_conf_Path) }
  end
  file_line '_etc_rsyslog_conf_258146' do
    path _etc_rsyslog_conf_Path
    match node['rhel9STIG']['stigrule_258146']['Setting']['_etc_rsyslog_conf_Regexp']
    line node['rhel9STIG']['stigrule_258146']['Setting']['_etc_rsyslog_conf_Line']
    notifies :run, 'execute[rsyslog_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258147']['Manage']
  _etc_rsyslog_conf_Path = node['rhel9STIG']['stigrule_258147']['Setting']['_etc_rsyslog_conf_Path']
  file _etc_rsyslog_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_rsyslog_conf_Path) }
  end
  file_line '_etc_rsyslog_conf_258147' do
    path _etc_rsyslog_conf_Path
    match node['rhel9STIG']['stigrule_258147']['Setting']['_etc_rsyslog_conf_Regexp']
    line node['rhel9STIG']['stigrule_258147']['Setting']['_etc_rsyslog_conf_Line']
    notifies :run, 'execute[rsyslog_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258148']['Manage']
  _etc_rsyslog_conf_Path = node['rhel9STIG']['stigrule_258148']['Setting']['_etc_rsyslog_conf_Path']
  file _etc_rsyslog_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_rsyslog_conf_Path) }
  end
  file_line '_etc_rsyslog_conf_258148' do
    path _etc_rsyslog_conf_Path
    match node['rhel9STIG']['stigrule_258148']['Setting']['_etc_rsyslog_conf_Regexp']
    line node['rhel9STIG']['stigrule_258148']['Setting']['_etc_rsyslog_conf_Line']
    notifies :run, 'execute[rsyslog_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258150']['Manage']
  _etc_rsyslog_conf_Path = node['rhel9STIG']['stigrule_258150']['Setting']['_etc_rsyslog_conf_Path']
  file _etc_rsyslog_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_rsyslog_conf_Path) }
  end
  file_line '_etc_rsyslog_conf_258150' do
    path _etc_rsyslog_conf_Path
    match node['rhel9STIG']['stigrule_258150']['Setting']['_etc_rsyslog_conf_Regexp']
    line node['rhel9STIG']['stigrule_258150']['Setting']['_etc_rsyslog_conf_Line']
    notifies :run, 'execute[rsyslog_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258151']['Manage']
  dnf_package 'audit_258151' do
    package_name node['rhel9STIG']['stigrule_258151']['Setting']['audit_PackageName']
    action node['rhel9STIG']['stigrule_258151']['Setting']['audit_Action']
  end
end
if node['rhel9STIG']['stigrule_258152']['Manage']
  service 'auditd_enable_258152' do
    service_name node['rhel9STIG']['stigrule_258152']['Setting']['auditd_enable_ServiceName']
    action node['rhel9STIG']['stigrule_258152']['Setting']['auditd_enable_Action']
  end
end
if node['rhel9STIG']['stigrule_258152']['Manage']
  service 'auditd_start_258152' do
    service_name node['rhel9STIG']['stigrule_258152']['Setting']['auditd_start_ServiceName']
    action node['rhel9STIG']['stigrule_258152']['Setting']['auditd_start_Action']
  end
end
if node['rhel9STIG']['stigrule_258153']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258153']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258153' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258153']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258153']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258154']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258154']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258154' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258154']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258154']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258156']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258156']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258156' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258156']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258156']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258157']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258157']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258157' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258157']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258157']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258158']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258158']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258158' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258158']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258158']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258159']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258159']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258159' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258159']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258159']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258160']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258160']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258160' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258160']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258160']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258161']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258161']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258161' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258161']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258161']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258162']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258162']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258162' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258162']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258162']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258163']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258163']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258163' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258163']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258163']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258164']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258164']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258164' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258164']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258164']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258168']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258168']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258168' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258168']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258168']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258169']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258169']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258169' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258169']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258169']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258170']['Manage']
  _etc_audit_auditd_conf_Path = node['rhel9STIG']['stigrule_258170']['Setting']['_etc_audit_auditd_conf_Path']
  file _etc_audit_auditd_conf_Path do
    action :create
    not_if { ::File.exist?(_etc_audit_auditd_conf_Path) }
  end
  file_line '_etc_audit_auditd_conf_258170' do
    path _etc_audit_auditd_conf_Path
    match node['rhel9STIG']['stigrule_258170']['Setting']['_etc_audit_auditd_conf_Regexp']
    line node['rhel9STIG']['stigrule_258170']['Setting']['_etc_audit_auditd_conf_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258175']['Manage']
  dnf_package 'audispd_plugins_258175' do
    package_name node['rhel9STIG']['stigrule_258175']['Setting']['audispd_plugins_PackageName']
    action node['rhel9STIG']['stigrule_258175']['Setting']['audispd_plugins_Action']
  end
end
if node['rhel9STIG']['stigrule_258176']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_execve_euid_b32_258176' do
    path node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b32_Path']
    match node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b32_Regexp']
    line node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258176']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_execve_euid_b64_258176' do
    path node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b64_Path']
    match node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b64_Regexp']
    line node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_euid_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258176']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_execve_egid_b32_258176' do
    path node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b32_Path']
    match node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b32_Regexp']
    line node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258176']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_execve_egid_b64_258176' do
    path node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b64_Path']
    match node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b64_Regexp']
    line node['rhel9STIG']['stigrule_258176']['Setting']['_etc_audit_rules_d_audit_rules_execve_egid_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258177']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_chmod_b32_258177' do
    path node['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b32_Path']
    match node['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b32_Regexp']
    line node['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258177']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_chmod_b64_258177' do
    path node['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b64_Path']
    match node['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b64_Regexp']
    line node['rhel9STIG']['stigrule_258177']['Setting']['_etc_audit_rules_d_audit_rules_chmod_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258178']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_chown_b32_258178' do
    path node['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b32_Path']
    match node['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b32_Regexp']
    line node['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258178']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_chown_b64_258178' do
    path node['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b64_Path']
    match node['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b64_Regexp']
    line node['rhel9STIG']['stigrule_258178']['Setting']['_etc_audit_rules_d_audit_rules_chown_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258179']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_lremovexattr_b32_unset_258179' do
    path node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_unset_Path']
    match node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_unset_Regexp']
    line node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_unset_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258179']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_lremovexattr_b64_unset_258179' do
    path node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_unset_Path']
    match node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_unset_Regexp']
    line node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_unset_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258179']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_lremovexattr_b32_258179' do
    path node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_Path']
    match node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_Regexp']
    line node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258179']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_lremovexattr_b64_258179' do
    path node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_Path']
    match node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_Regexp']
    line node['rhel9STIG']['stigrule_258179']['Setting']['_etc_audit_rules_d_audit_rules_lremovexattr_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258180']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_umount_258180' do
    path node['rhel9STIG']['stigrule_258180']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_umount_Path']
    match node['rhel9STIG']['stigrule_258180']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_umount_Regexp']
    line node['rhel9STIG']['stigrule_258180']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_umount_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258181']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_chacl_258181' do
    path node['rhel9STIG']['stigrule_258181']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chacl_Path']
    match node['rhel9STIG']['stigrule_258181']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chacl_Regexp']
    line node['rhel9STIG']['stigrule_258181']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chacl_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258182']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_setfacl_258182' do
    path node['rhel9STIG']['stigrule_258182']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_setfacl_Path']
    match node['rhel9STIG']['stigrule_258182']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_setfacl_Regexp']
    line node['rhel9STIG']['stigrule_258182']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_setfacl_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258183']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_chcon_258183' do
    path node['rhel9STIG']['stigrule_258183']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chcon_Path']
    match node['rhel9STIG']['stigrule_258183']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chcon_Regexp']
    line node['rhel9STIG']['stigrule_258183']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chcon_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258184']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_semanage_258184' do
    path node['rhel9STIG']['stigrule_258184']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_semanage_Path']
    match node['rhel9STIG']['stigrule_258184']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_semanage_Regexp']
    line node['rhel9STIG']['stigrule_258184']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_semanage_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258185']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_setfiles_258185' do
    path node['rhel9STIG']['stigrule_258185']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setfiles_Path']
    match node['rhel9STIG']['stigrule_258185']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setfiles_Regexp']
    line node['rhel9STIG']['stigrule_258185']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setfiles_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258186']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_setsebool_258186' do
    path node['rhel9STIG']['stigrule_258186']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setsebool_Path']
    match node['rhel9STIG']['stigrule_258186']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setsebool_Regexp']
    line node['rhel9STIG']['stigrule_258186']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_setsebool_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258187']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_rename_b32_258187' do
    path node['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b32_Path']
    match node['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b32_Regexp']
    line node['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258187']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_rename_b64_258187' do
    path node['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b64_Path']
    match node['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b64_Regexp']
    line node['rhel9STIG']['stigrule_258187']['Setting']['_etc_audit_rules_d_audit_rules_rename_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258188']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_truncate_EPERM_b32_258188' do
    path node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b32_Path']
    match node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b32_Regexp']
    line node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258188']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_truncate_EPERM_b64_258188' do
    path node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b64_Path']
    match node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b64_Regexp']
    line node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EPERM_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258188']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_truncate_EACCES_b32_258188' do
    path node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b32_Path']
    match node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b32_Regexp']
    line node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258188']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_truncate_EACCES_b64_258188' do
    path node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b64_Path']
    match node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b64_Regexp']
    line node['rhel9STIG']['stigrule_258188']['Setting']['_etc_audit_rules_d_audit_rules_truncate_EACCES_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258189']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_delete_module_b32_258189' do
    path node['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b32_Path']
    match node['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b32_Regexp']
    line node['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258189']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_delete_module_b64_258189' do
    path node['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b64_Path']
    match node['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b64_Regexp']
    line node['rhel9STIG']['stigrule_258189']['Setting']['_etc_audit_rules_d_audit_rules_delete_module_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258190']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_init_module_b32_258190' do
    path node['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b32_Path']
    match node['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b32_Regexp']
    line node['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258190']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_init_module_b64_258190' do
    path node['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b64_Path']
    match node['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b64_Regexp']
    line node['rhel9STIG']['stigrule_258190']['Setting']['_etc_audit_rules_d_audit_rules_init_module_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258191']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_chage_258191' do
    path node['rhel9STIG']['stigrule_258191']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chage_Path']
    match node['rhel9STIG']['stigrule_258191']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chage_Regexp']
    line node['rhel9STIG']['stigrule_258191']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chage_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258192']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_chsh_258192' do
    path node['rhel9STIG']['stigrule_258192']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chsh_Path']
    match node['rhel9STIG']['stigrule_258192']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chsh_Regexp']
    line node['rhel9STIG']['stigrule_258192']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_chsh_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258193']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_crontab_258193' do
    path node['rhel9STIG']['stigrule_258193']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_crontab_Path']
    match node['rhel9STIG']['stigrule_258193']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_crontab_Regexp']
    line node['rhel9STIG']['stigrule_258193']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_crontab_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258194']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b32_258194' do
    path node['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b32_Path']
    match node['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b32_Regexp']
    line node['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258194']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b64_258194' do
    path node['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b64_Path']
    match node['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b64_Regexp']
    line node['rhel9STIG']['stigrule_258194']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_gpasswd_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258195']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_kmod_258195' do
    path node['rhel9STIG']['stigrule_258195']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_kmod_Path']
    match node['rhel9STIG']['stigrule_258195']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_kmod_Regexp']
    line node['rhel9STIG']['stigrule_258195']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_kmod_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258196']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_newgrp_258196' do
    path node['rhel9STIG']['stigrule_258196']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_newgrp_Path']
    match node['rhel9STIG']['stigrule_258196']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_newgrp_Regexp']
    line node['rhel9STIG']['stigrule_258196']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_newgrp_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258197']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_pam_timestamp_check_258197' do
    path node['rhel9STIG']['stigrule_258197']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_pam_timestamp_check_Path']
    match node['rhel9STIG']['stigrule_258197']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_pam_timestamp_check_Regexp']
    line node['rhel9STIG']['stigrule_258197']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_pam_timestamp_check_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258198']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_passwd_b32_258198' do
    path node['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b32_Path']
    match node['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b32_Regexp']
    line node['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258198']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_passwd_b64_258198' do
    path node['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b64_Path']
    match node['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b64_Regexp']
    line node['rhel9STIG']['stigrule_258198']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_passwd_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258199']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_postdrop_258199' do
    path node['rhel9STIG']['stigrule_258199']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postdrop_Path']
    match node['rhel9STIG']['stigrule_258199']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postdrop_Regexp']
    line node['rhel9STIG']['stigrule_258199']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postdrop_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258200']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_postqueue_258200' do
    path node['rhel9STIG']['stigrule_258200']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postqueue_Path']
    match node['rhel9STIG']['stigrule_258200']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postqueue_Regexp']
    line node['rhel9STIG']['stigrule_258200']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_postqueue_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258201']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_ssh_agent_258201' do
    path node['rhel9STIG']['stigrule_258201']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_ssh_agent_Path']
    match node['rhel9STIG']['stigrule_258201']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_ssh_agent_Regexp']
    line node['rhel9STIG']['stigrule_258201']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_ssh_agent_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258202']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_libexec_openssh_ssh_keysign_258202' do
    path node['rhel9STIG']['stigrule_258202']['Setting']['_etc_audit_rules_d_audit_rules__usr_libexec_openssh_ssh_keysign_Path']
    match node['rhel9STIG']['stigrule_258202']['Setting']['_etc_audit_rules_d_audit_rules__usr_libexec_openssh_ssh_keysign_Regexp']
    line node['rhel9STIG']['stigrule_258202']['Setting']['_etc_audit_rules_d_audit_rules__usr_libexec_openssh_ssh_keysign_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258203']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_su_258203' do
    path node['rhel9STIG']['stigrule_258203']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_su_Path']
    match node['rhel9STIG']['stigrule_258203']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_su_Regexp']
    line node['rhel9STIG']['stigrule_258203']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_su_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258204']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_sudo_258204' do
    path node['rhel9STIG']['stigrule_258204']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudo_Path']
    match node['rhel9STIG']['stigrule_258204']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudo_Regexp']
    line node['rhel9STIG']['stigrule_258204']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudo_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258205']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_sudoedit_258205' do
    path node['rhel9STIG']['stigrule_258205']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudoedit_Path']
    match node['rhel9STIG']['stigrule_258205']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudoedit_Regexp']
    line node['rhel9STIG']['stigrule_258205']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_sudoedit_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258206']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_unix_chkpwd_258206' do
    path node['rhel9STIG']['stigrule_258206']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_chkpwd_Path']
    match node['rhel9STIG']['stigrule_258206']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_chkpwd_Regexp']
    line node['rhel9STIG']['stigrule_258206']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_chkpwd_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258207']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_unix_update_258207' do
    path node['rhel9STIG']['stigrule_258207']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_update_Path']
    match node['rhel9STIG']['stigrule_258207']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_update_Regexp']
    line node['rhel9STIG']['stigrule_258207']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_unix_update_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258208']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_userhelper_258208' do
    path node['rhel9STIG']['stigrule_258208']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_userhelper_Path']
    match node['rhel9STIG']['stigrule_258208']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_userhelper_Regexp']
    line node['rhel9STIG']['stigrule_258208']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_userhelper_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258209']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_usermod_258209' do
    path node['rhel9STIG']['stigrule_258209']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_usermod_Path']
    match node['rhel9STIG']['stigrule_258209']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_usermod_Regexp']
    line node['rhel9STIG']['stigrule_258209']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_usermod_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258210']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_bin_mount_258210' do
    path node['rhel9STIG']['stigrule_258210']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_mount_Path']
    match node['rhel9STIG']['stigrule_258210']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_mount_Regexp']
    line node['rhel9STIG']['stigrule_258210']['Setting']['_etc_audit_rules_d_audit_rules__usr_bin_mount_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258211']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_init_258211' do
    path node['rhel9STIG']['stigrule_258211']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_init_Path']
    match node['rhel9STIG']['stigrule_258211']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_init_Regexp']
    line node['rhel9STIG']['stigrule_258211']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_init_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258212']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_poweroff_258212' do
    path node['rhel9STIG']['stigrule_258212']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_poweroff_Path']
    match node['rhel9STIG']['stigrule_258212']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_poweroff_Regexp']
    line node['rhel9STIG']['stigrule_258212']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_poweroff_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258213']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_reboot_258213' do
    path node['rhel9STIG']['stigrule_258213']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_reboot_Path']
    match node['rhel9STIG']['stigrule_258213']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_reboot_Regexp']
    line node['rhel9STIG']['stigrule_258213']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_reboot_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258214']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_shutdown_258214' do
    path node['rhel9STIG']['stigrule_258214']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_shutdown_Path']
    match node['rhel9STIG']['stigrule_258214']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_shutdown_Regexp']
    line node['rhel9STIG']['stigrule_258214']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_shutdown_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258217']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_sudoers_b32_258217' do
    path node['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b32_Path']
    match node['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b32_Regexp']
    line node['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258217']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_sudoers_b64_258217' do
    path node['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b64_Path']
    match node['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b64_Regexp']
    line node['rhel9STIG']['stigrule_258217']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258218']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_sudoers_d__b32_258218' do
    path node['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b32_Path']
    match node['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b32_Regexp']
    line node['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258218']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_sudoers_d__b64_258218' do
    path node['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b64_Path']
    match node['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b64_Regexp']
    line node['rhel9STIG']['stigrule_258218']['Setting']['_etc_audit_rules_d_audit_rules__etc_sudoers_d__b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258219']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_group_b32_258219' do
    path node['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b32_Path']
    match node['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b32_Regexp']
    line node['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258219']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_group_b64_258219' do
    path node['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b64_Path']
    match node['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b64_Regexp']
    line node['rhel9STIG']['stigrule_258219']['Setting']['_etc_audit_rules_d_audit_rules__etc_group_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258220']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_gshadow_b32_258220' do
    path node['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b32_Path']
    match node['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b32_Regexp']
    line node['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258220']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_gshadow_b64_258220' do
    path node['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b64_Path']
    match node['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b64_Regexp']
    line node['rhel9STIG']['stigrule_258220']['Setting']['_etc_audit_rules_d_audit_rules__etc_gshadow_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258221']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_security_opasswd_b32_258221' do
    path node['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b32_Path']
    match node['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b32_Regexp']
    line node['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258221']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_security_opasswd_b64_258221' do
    path node['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b64_Path']
    match node['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b64_Regexp']
    line node['rhel9STIG']['stigrule_258221']['Setting']['_etc_audit_rules_d_audit_rules__etc_security_opasswd_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258222']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_passwd_b32_258222' do
    path node['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b32_Path']
    match node['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b32_Regexp']
    line node['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258222']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_passwd_b64_258222' do
    path node['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b64_Path']
    match node['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b64_Regexp']
    line node['rhel9STIG']['stigrule_258222']['Setting']['_etc_audit_rules_d_audit_rules__etc_passwd_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258223']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_shadow_b32_258223' do
    path node['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b32_Path']
    match node['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b32_Regexp']
    line node['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258223']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__etc_shadow_b64_258223' do
    path node['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b64_Path']
    match node['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b64_Regexp']
    line node['rhel9STIG']['stigrule_258223']['Setting']['_etc_audit_rules_d_audit_rules__etc_shadow_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258224']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__var_log_faillock_b32_258224' do
    path node['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b32_Path']
    match node['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b32_Regexp']
    line node['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258224']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__var_log_faillock_b64_258224' do
    path node['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b64_Path']
    match node['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b64_Regexp']
    line node['rhel9STIG']['stigrule_258224']['Setting']['_etc_audit_rules_d_audit_rules__var_log_faillock_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258225']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__var_log_lastlog_b32_258225' do
    path node['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b32_Path']
    match node['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b32_Regexp']
    line node['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258225']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__var_log_lastlog_b64_258225' do
    path node['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b64_Path']
    match node['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b64_Regexp']
    line node['rhel9STIG']['stigrule_258225']['Setting']['_etc_audit_rules_d_audit_rules__var_log_lastlog_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258227']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_f2_258227' do
    path node['rhel9STIG']['stigrule_258227']['Setting']['_etc_audit_rules_d_audit_rules_f2_Path']
    match node['rhel9STIG']['stigrule_258227']['Setting']['_etc_audit_rules_d_audit_rules_f2_Regexp']
    line node['rhel9STIG']['stigrule_258227']['Setting']['_etc_audit_rules_d_audit_rules_f2_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258228']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_loginuid_immutable_258228' do
    path node['rhel9STIG']['stigrule_258228']['Setting']['_etc_audit_rules_d_audit_rules_loginuid_immutable_Path']
    match node['rhel9STIG']['stigrule_258228']['Setting']['_etc_audit_rules_d_audit_rules_loginuid_immutable_Regexp']
    line node['rhel9STIG']['stigrule_258228']['Setting']['_etc_audit_rules_d_audit_rules_loginuid_immutable_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258229']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_e2_258229' do
    path node['rhel9STIG']['stigrule_258229']['Setting']['_etc_audit_rules_d_audit_rules_e2_Path']
    match node['rhel9STIG']['stigrule_258229']['Setting']['_etc_audit_rules_d_audit_rules_e2_Regexp']
    line node['rhel9STIG']['stigrule_258229']['Setting']['_etc_audit_rules_d_audit_rules_e2_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_258234']['Manage']
  dnf_package 'crypto_policies_258234' do
    package_name node['rhel9STIG']['stigrule_258234']['Setting']['crypto_policies_PackageName']
    action node['rhel9STIG']['stigrule_258234']['Setting']['crypto_policies_Action']
  end
end
if node['rhel9STIG']['stigrule_272488']['Manage']
  dnf_package 'postfix_272488' do
    package_name node['rhel9STIG']['stigrule_272488']['Setting']['postfix_PackageName']
    action node['rhel9STIG']['stigrule_272488']['Setting']['postfix_Action']
  end
end
if node['rhel9STIG']['stigrule_279936']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_euid_b64_279936' do
    path node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b64_Path']
    match node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b64_Regexp']
    line node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_279936']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_euid_b32_279936' do
    path node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b32_Path']
    match node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b32_Regexp']
    line node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_euid_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_279936']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_auid_b64_279936' do
    path node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b64_Path']
    match node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b64_Regexp']
    line node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b64_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_279936']['Manage']
  file_line '_etc_audit_rules_d_audit_rules_auid_b32_279936' do
    path node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b32_Path']
    match node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b32_Regexp']
    line node['rhel9STIG']['stigrule_279936']['Setting']['_etc_audit_rules_d_audit_rules_auid_b32_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_288832']['Manage']
  file_line '_etc_audit_rules_d_audit_rules__usr_sbin_useradd_288832' do
    path node['rhel9STIG']['stigrule_288832']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_useradd_Path']
    match node['rhel9STIG']['stigrule_288832']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_useradd_Regexp']
    line node['rhel9STIG']['stigrule_288832']['Setting']['_etc_audit_rules_d_audit_rules__usr_sbin_useradd_Line']
    notifies :run, 'execute[auditd_restart]', :delayed
  end
end
if node['rhel9STIG']['stigrule_288833']['Manage']
  _etc_pki_tls_openssl_cnf_Path = node['rhel9STIG']['stigrule_288833']['Setting']['_etc_pki_tls_openssl_cnf_Path']
  file _etc_pki_tls_openssl_cnf_Path do
    action :create
    not_if { ::File.exist?(_etc_pki_tls_openssl_cnf_Path) }
  end
  file_line '_etc_pki_tls_openssl_cnf_288833' do
    path _etc_pki_tls_openssl_cnf_Path
    match node['rhel9STIG']['stigrule_288833']['Setting']['_etc_pki_tls_openssl_cnf_Regexp']
    line node['rhel9STIG']['stigrule_288833']['Setting']['_etc_pki_tls_openssl_cnf_Line']
  end
end
