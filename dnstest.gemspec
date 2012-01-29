# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)
require 'dnstest/version'

Gem::Specification.new do |s|
  s.name        = 'dnstest'
  s.version     = Dnstest::VERSION
  s.authors     = ['Daniele Orlandi']
  s.email       = ['daniele@orlandi.com']
  s.homepage    = 'http://www.orlandi.com/'
  s.summary     = 'DNS Tester'
  s.description = 'Test DNS informations: delegation chains, serials, etc...'

  s.rubyforge_project = 'dnstest'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ['lib']

  # specify any dependencies here; for example:
  # s.add_development_dependency 'rspec'
  s.add_runtime_dependency 'dnsruby'
end
