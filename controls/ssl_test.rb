# frozen_string_literal: true

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Dominik Richter
# author: Christoph Hartmann
# author: Alex Pop
# author: Patrick Muench
# author: Christoph Kappel

invalid_targets = input(
  'invalid_targets',
  value: [
    '127.0.0.1',
    '0.0.0.0',
    '::1',
    '::',
  ],
  description: 'Array of IPv4 and IPv6 Addresses to exclude'
)

# Array of TCP ports to exclude from SSL checking. For example: [443, 8443]
exclude_ports = input(
  'exclude_ports',
  value: [],
  description: 'Array of TCP ports to exclude from SSL checking'
)

target_hostname = input(
  'target_hostname',
  value: command('hostname').stdout.strip,
  description: 'Target hostname to check'
)

force_ssl = input(
  'force_ssl',
  value: false,
  description: 'The profile should not check if SSL is enabled on every port and assume it is'
)

# Find all TCP ports on the system, IPv4 and IPv6
# Eliminate duplicate ports for cleaner reporting and faster scans and sort the
# array by port number.
tcpports = port.protocols(/tcp/).entries.uniq.sort_by { |entry| entry['port'] }

# Make tcpports an array of hashes to be passed to the ssl resource
tcpports = tcpports.map do |socket|
  params = { port: socket.port }
  # Add a host param if the listening address of the port is a valid/non-localhost IP
  params[:host] = socket.address unless invalid_targets.include?(socket.address)
  params[:socket] = socket
  params
end

# Filter out ports that don't respond to any version of SSL
sslports = tcpports.find_all do |tcpport|
  if force_ssl
    !exclude_ports.include?(tcpport[:port])
  else
    !exclude_ports.include?(tcpport[:port]) && ssl(tcpport).enabled?
  end
end

# Troubleshooting control to show InSpec version and list
# discovered tcp ports and the ssl enabled ones. Always succeeds
control 'debugging' do
  title "Inspec::Version=#{Inspec::VERSION}"
  impact 0.0
  describe "tcpports=\n#{tcpports.join("\n")}" do
    it { should_not eq nil }
  end
  describe "sslports=\n#{sslports.join("\n")}" do
    it { should_not eq nil }
  end
end

#######################################################
# Protocol Tests                                      #
# Valid protocols are: tls1.2                         #
# Invalid protocols are : ssl2, ssl3, tls1.0, tls1.1  #
#######################################################
control 'ssl2' do
  title 'Disable SSL 2 from all exposed SSL ports.'
  impact 1.0
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('ssl2') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'ssl3' do
  title 'Disable SSL 3 from all exposed SSL ports.'
  impact 1.0
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('ssl3') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'tls1.0' do
  title 'Disable TLS 1.0 on exposed ports.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('tls1.0') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'tls1.1' do
  title 'Disable TLS 1.1 on exposed ports.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('tls1.1') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'tls1.2' do
  title 'Enable TLS 1.2 on exposed ports.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('tls1.2') do
      it(proc_desc) { should be_enabled }
      it { should be_enabled }
    end
  end
end

#######################################################
# Key Exchange (Kx) Tests                             #
# Valid Kx(s) are: ECDHE                              #
#######################################################
control 'kx-ecdh' do
  title 'Enable ECDH as KX from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/^TLS_ECDH/i) do
      it(proc_desc) { should be_enabled }
      it { should be_enabled }
    end
  end
end

control 'kx-rsa' do
  title 'Disable RSA as KX from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/^TLS_RSA/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'kx-dh' do
  title 'Disable DH as KX from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/^TLS_DH/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'kx-krb5' do
  title 'Disable KRB5 as KX from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/^TLS_KRB5/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'kx-psk' do
  title 'Disable PSK as KX from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/^TLS_PSK/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'kx-gostr' do
  title 'Disable GOSTR as KX from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/^TLS_GOSTR/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'kx-srp' do
  title 'Disable SRP as KX from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/^TLS_SRP/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

#######################################################
# Authentication (Au) Tests                           #
# Valid Au(s) are: ECDSA, RSA                         #
#######################################################

control 'au-ecdsa-rsa' do
  title 'Enable ECDSA or RSA as AU from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/(RSA|ECDSA)_WITH/i) do
      it(proc_desc) { should be_enabled }
      it { should be_enabled }
    end
  end
end

control 'au-anon' do
  title 'Disable ANON as AU from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/ANON_WITH/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'au-dss' do
  title 'Disable DSS as AU from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/DSS_WITH/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'au-psk' do
  title 'Disable PSK as AU from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/PSK_WITH/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'au-export' do
  title 'Disable EXPORT as AU from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/((EXPORT)(\d*)_WITH)/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

#######################################################
# Symmetric Encryption Method (Enc) Tests             #
# Valid Enc modes are:                                #
# AES256, AES128, AES256-GCM, AES128-GCM, CHACHA20    #
#######################################################

control 'enc-aes-gcm-chacha20' do
  title 'Enable AES256 or AES128 or AES256-GCM or AES128-GCM or CHACHA20 as Enc'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/WITH_(AES_256|AES_128|CHACHA20|AES_256_GCM|AES_128_GCM)/i) do
      it(proc_desc) { should be_enabled }
      it { should be_enabled }
    end
  end
end

control 'enc-cbc' do
  title 'Disable CBC as ENC from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/(WITH_(\w+)_(CBC))/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'enc-rc4' do
  title 'Disable RC4 as ENC from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/WITH_RC4/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'enc-export' do
  title 'Disable EXPORT as ENC from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/WITH_EXPORT/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'enc-des' do
  title 'Disable DES, 3DES as ENC from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/(WITH_(\d*)(des))/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'enc-enull' do
  title 'Disable eNULL as ENC from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/WITH_NULL/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'enc-camellia' do
  title 'Disable CAMELLIA as ENC from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/WITH_CAMELLIA/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'enc-seed' do
  title 'Disable SEED as ENC from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/WITH_SEED/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'enc-idea' do
  title 'Disable IDEA as ENC from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/WITH_IDEA/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'enc-aes-ccm' do
  title 'Disable AES-CCM from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/(WITH_AES_(\w+)_(CCM))/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

#######################################################
# Message Authentication Code (Mac) Tests             #
# Valid Mac(s) are: SHA384, SHA256, AEAD, POLY1305    #
#######################################################

control 'mac-sha384-sha256-poly1305' do
  title 'Enable SHA384 or SHA256 or POLY1305 as Mac from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/_(SHA384|SHA256|POLY1305)$/i) do
      it(proc_desc) { should be_enabled }
      it { should be_enabled }
    end
  end
end

control 'mac-md5' do
  title 'Disable MD5 Mac from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/_MD5$/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'mac-sha' do
  title 'Disable SHA(1) Mac from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/_SHA$/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'mac-null' do
  title 'Disable NULL Mac from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/_NULL$/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'robotattack' do
  title "Return Of Bleichenbacher's Oracle Threat"
  desc 'ROBOT is the return of a 19-year-old vulnerability that allows performing RSA decryption and signing operations with the private key of a TLS server.'
  ref "Paper: Return Of Bleichenbacher's Oracle Threat (ROBOT)", url: 'https://ia.cr/2017/1189'
  tag 'sslattack', 'tlsattack'
  impact 0.5
  only_if { !sslports.empty? }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/^TLS_RSA/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end
