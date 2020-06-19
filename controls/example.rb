# copyright: 2018, The Authors

control 'ACSC-OHS-1407' do
  impact 0.8
  tag acsc: ["ACSC ISM","June 2020", "Official", "OSH-1407"]
  tag acsc: ["ACSC ISM","June 2020", "Protected", "OSH-1407"]
  tag acsc: ["ACSC ISM","June 2020", "Secret", "OSH-1407"]
  tag acsc: ["ACSC ISM","June 2020", "Top_Secret", "OSH-1407"]
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
  tag acsc: ["ACSC ISM","June 2020", "Official", "OSH-1408"]
  tag acsc: ["ACSC ISM","June 2020", "Protected", "OSH-1408"]
  tag acsc: ["ACSC ISM","June 2020", "Secret", "OSH-1408"]
  tag acsc: ["ACSC ISM","June 2020", "Top_Secret", "OSH-1408"]
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
  control 'xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Enforce_password_history_is_set_to_24_or_more_passwords' do
    tag acsc: ["ACSC ISM","June 2020", "Top_Secret", "OSH-1408"]
  end
end
