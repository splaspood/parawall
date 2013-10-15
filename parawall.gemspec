Gem::Specification.new do |s|
  s.name        = "parawall"
  s.version     = '0.0.1'
  s.authors     = ["James W. Brinkerhoff"]
  s.email       = "jwb@paravolve.net"
  s.homepage    = "http://github.com/splaspood/parawall"
  s.summary     = "A Ruby based IPTables DSL"
  s.description = "Hate IPTables Syntax?  Me too."
  s.required_rubygems_version = ">= 1.3.6"
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.add_dependency 'net-ssh'
  s.add_dependency 'thor'
  # s.extra_rdoc_files = ['README.md', 'LICENSE']
  s.license = 'GPL'
end
