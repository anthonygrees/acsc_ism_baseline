# copyright: 2018, The Authors

require_controls 'cis-windows2016rtm' do
  control 'xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Enforce_password_history_is_set_to_24_or_more_passwords' do
    tag acsc: ["ACSC ISM","June 2020", "Top_Secret", "OSH-1408"]
  end
end
