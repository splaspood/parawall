#!/usr/bin/env ruby

$:.unshift File.dirname(__FILE__)

require "firewall"

fw = CustomFirewall.configure "cerberus custom firewall" do
  table "filter" do

    chain "LOG_REJECT" do
      [ :IPV4, :IPV6 ].each do |t|
        rule "logging log" do
          match       'limit'
          limit       '1/sec'
          log_prefix  "IPT: "
          log_level   7
          jump      :LOG
          type        t
        end

        rule "logging reject" do
          jump :REJECT
          type   t
        end
      end
    end
  end
end

puts fw
