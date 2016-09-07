# encoding: utf-8
#
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

# Valid protocols are: ssl2, ssl3, tls1.0, tls1.1, tls1.2

# Find all TCP ports on the system, IPv4 and IPv6
# Eliminate duplicate ports for cleaner reporting and faster scans
sslports = port.protocols(/tcp/).entries.uniq do |entry|
  entry['port']
end

# Filter out ports that don't respond to any version of SSL
sslports = sslports.find_all do |socket|
  ssl(port: socket.port).enabled?
  # ssl(port: tcp_port, timeout: 8, retries: 1).enabled?
end

control 'tls1.2' do
  title 'Run TLS 1.2 whenever SSL is active on a port'
  impact 0.5

  sslports.each do |socket|
    # create a description
    proc_desc = "on node == #{command('hostname').stdout.strip} running #{socket.process.inspect} (#{socket.pid})"
    describe ssl(port: socket.port).protocols('tls1.2') do
      it(proc_desc) { should be_enabled }
      it { should be_enabled }
    end
  end
end

control 'ssl2' do
  title 'Disable SSL2 from all exposed SSL ports.'
  impact 1.0

  sslports.each do |socket|
    # create a description
    proc_desc = "on node == #{command('hostname').stdout.strip} running #{socket.process.inspect} (#{socket.pid})"
    describe ssl(port: socket.port).protocols('ssl2') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'ssl3' do
  title 'Disable SSL3 from all exposed SSL ports.'
  impact 1.0

  sslports.each do |socket|
    # create a description
    proc_desc = "on node == #{command('hostname').stdout.strip} running #{socket.process.inspect} (#{socket.pid})"
    describe ssl(port: socket.port).protocols('ssl3') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'tls1.0' do
  title 'Disable tls1.0 from all exposed ports.'
  impact 0.5

  sslports.each do |socket|
    # create a description
    proc_desc = "on node == #{command('hostname').stdout.strip} running #{socket.process.inspect} (#{socket.pid})"
    describe ssl(port: socket.port).protocols('tls1.0') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'tls1.1' do
  title 'Disable tls1.1 from all exposed ports.'
  impact 0.5

  sslports.each do |socket|
    # create a description
    proc_desc = "on node == #{command('hostname').stdout.strip} running #{socket.process.inspect} (#{socket.pid})"
    describe ssl(port: socket.port).protocols('tls1.1') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'rc4' do
  title 'Disable RC4 ciphers from all exposed SSL/TLS ports and versions.'
  impact 0.5

  sslports.each do |socket|
    # create a description
    proc_desc = "on node == #{command('hostname').stdout.strip} running #{socket.process.inspect} (#{socket.pid})"
    describe ssl(port: socket.port).ciphers(/rc4/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end
