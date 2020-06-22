# copyright: 2018, The Authors

control 'ACSC-OHS-1407' do
  impact 0.8
  tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-1407"]

  title 'ACSC ISM 1407 - Guidelines for System Hardening'
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

  title 'ACSC ISM 1408 - Guidelines for System Hardening'
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
    title 'ACSC ISM 1409 - Operating system configuration'
  end

  control 'xccdf_org.cisecurity.benchmarks_rule_2.3.1.3_L1_Ensure_Accounts_Guest_account_status_is_set_to_Disabled_MS_only' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-0383"]
    title 'ACSC ISM 0383 - Operating system configuration'
  end

  control 'xccdf_org.cisecurity.benchmarks_rule_2.2.21_L1_Ensure_Deny_access_to_this_computer_from_the_network_is_set_to_Guests_Local_account_and_member_of_Administrators_group_MS_only' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-0380"]
    title 'ACSC ISM 0380 - Operating system configuration'
    desc 'Unneeded operating system accounts, software, components, services and functionality are removed or disabled.'
  end

  control 'xccdf_org.cisecurity.benchmarks_rule_2.2.22_L1_Ensure_Deny_log_on_as_a_batch_job_to_include_Guests' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-1491"]
    title 'ACSC ISM 1491 - Operating system configuration'
    desc 'Standard users are prevented from running all script execution engines shipped with Microsoft Windows including Windows Script Host (cscript.exe and wscript.exe), powershell.exe, powershell_ise.exe, cmd.exe, wmic.exe and Microsoft HTML Application Host (mshta.exe).'
  end

  control 'xccdf_org.cisecurity.benchmarks_rule_2.3.1.1_L1_Ensure_Accounts_Administrator_account_status_is_set_to_Disabled_MS_only' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-1410"]
    title 'ACSC ISM 1410 - Local administrator accounts'
    desc 'Local administrator accounts are disabled; alternatively, passphrases that are random and unique for each device’s local administrator account are used.'
  end

  control 'xccdf_org.cisecurity.benchmarks_rule_2.2.26_L1_Ensure_Deny_log_on_through_Remote_Desktop_Services_is_set_to_Guests_Local_account_MS_only' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-1469"]
    title 'ACSC ISM 1469 - Local administrator accounts'
  end

  control 'xccdf_org.cisecurity.benchmarks_rule_2.2.26_L1_Ensure_Deny_log_on_through_Remote_Desktop_Services_is_set_to_Guests_Local_account_MS_only' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "OSH-0382"]
    title 'ACSC ISM 0382 - Application management'
  end

end

## Patch Baseline

require_controls 'windows-patch-baseline' do
  control 'important-count' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "PM-1143", "PM-1493", "PM-1144", "PM-0940"]
    title 'ACSC ISM 1143, 1493, 1144, 0940 - System patching'
  end

  control 'important-patches' do
    tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "PM-1472", "PM-1494", "PM-1495", "PM-1496"]
    title 'ACSC ISM 1472, 1494, 1495, 1496 - System patching'
  end

  control 'optional-count' do
   tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "PM-0300", "PM-0298", "PM-0303", "PM-1497", "PM-1498", "PM-1499", "PM-1500"]
   title 'ACSC ISM 0300, 0298, 0303, 1497, 1498, 1499, 1500 - System patching'
  end

  control 'optional-patches' do
   tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "PM0304", "PM-1501", "PM-1211"]
   title 'ACSC ISM 0304, 1501, 1211 - System patching'
  end

  control 'verify-kb' do
   tag acsc: ["ACSC ISM","June 2020", "Official", "Protected", "Top_Secret", "Secret", "PM-1143", "PM-1493", "PM-1144", "PM-0940"]
   title 'ACSC ISM 1143, 1493, 1144, 0940 - System patching'
  end

end
