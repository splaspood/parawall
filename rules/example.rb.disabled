#!/usr/bin/env ruby

$:.unshift File.dirname(__FILE__) + "/lib"

require "paravolve/custom_firewall"
STDOUT.sync = true

fw = ParaVolve::CustomFirewall.configure "example", { setup: false } do
  table "filter", { logging: false, flush: false } do
    host_list "admin_hosts", { set_policy: false, create: false } do
      hosts %w{ some.hosts.here and.others.like 1.2.3.4 and 2000:1234:100::/64 }
      type 'source'
    end
	end
end

puts fw
