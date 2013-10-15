table "filter", { logging: false, flush: false } do
  # host_list "admin_hosts", { set_policy: false, create: false } do
  #   hosts %w{ some.hosts.here and.others.like 1.2.3.4 and 2000:1234:100::/64 }
  #   type 'source'
  # end

  chain "TESTA", { create: false, set_policy: false } do
    %w{ cerberus0 }.each do |int|
      rule "allow traffic between #{int} and eth0" do
        in_interface  int
        out_interface 'eth0'
        type          :IPV6

        accept
      end
    end
  end
end
