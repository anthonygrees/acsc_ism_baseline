m# copyright: 2018, The Authors

control 'ACSC-OHS-1407' do
  impact 0.8
  tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-1407"]

  title 'Guidelines for System Hardening'
  desc 'The latest version (N), or N-1 version, of an operating system is used for Standard Operating Environments (SOEs).'

  
  describe os.family do
    it { should eq 'windows' }
  end

  describe os.name do
    it { should eq 'windows_server_2016_datacenter' }
  end

  describe os.release do
    it { should > '10.0' }
  end
end

control 'ACSC-OSH-1408' do
  impact 0.8
  tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-1408"]

  title 'Guidelines for System Hardening'
  desc 'When developing a Microsoft Windows SOE, the 64-bit version of the operating system is used.'
  
    script = <<-EOH
    (gwmi win32_operatingsystem | select osarchitecture).osarchitecture
    EOH
    describe powershell(script) do
        its('stdout') { should include "64-bit" }
    end
end


require_controls 'cis-windows2016rtm' do
  control 'xccdf_org.cisecurity.benchmarks_rule_2.3.1.1_L1_Ensure_Accounts_Administrator_account_status_is_set_to_Disabled_MS_only' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-1409"]
  end

  control 'xccdf_org.cisecurity.benchmarks_rule_2.3.1.3_L1_Ensure_Accounts_Guest_account_status_is_set_to_Disabled_MS_only' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-0383"]
  end

  control 'xccdf_org.cisecurity.benchmarks_rule_2.2.21_L1_Ensure_Deny_access_to_this_computer_from_the_network_is_set_to_Guests_Local_account_and_member_of_Administrators_group_MS_only' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-0380"]
    title 'Operating system configuration'
    desc 'Unneeded operating system accounts, software, components, services and functionality are removed or disabled.'
  end

  control 'xccdf_org.cisecurity.benchmarks_rule_2.2.22_L1_Ensure_Deny_log_on_as_a_batch_job_to_include_Guests' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-1491"]
    title 'Operating system configuration - ACSC ISM 1491'
    desc 'Standard users are prevented from running all script execution engines shipped with Microsoft Windows including Windows Script Host (cscript.exe and wscript.exe), powershell.exe, powershell_ise.exe, cmd.exe, wmic.exe and Microsoft HTML Application Host (mshta.exe).'
  end

  control 'xccdf_org.cisecurity.benchmarks_rule_2.3.1.1_L1_Ensure_Accounts_Administrator_account_status_is_set_to_Disabled_MS_only' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-1410"]
    title 'Local administrator accounts - ACSC ISM 1410'
    desc 'Local administrator accounts are disabled; alternatively, passphrases that are random and unique for each device’s local administrator account are used.'
  end

end
