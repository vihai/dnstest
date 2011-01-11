require 'rubygems'
require 'rake'

begin
  require 'jeweler'

  Jeweler::Tasks.new do |s|
    s.name = 'dnstest'
    s.summary = 'DNS tester'
    s.email = 'daniele@orlandi.com'
    s.homepage = 'http://www.orlandi.com/'
    s.description = 'Tests DNS'
    s.authors = ['Daniele Orlandi']
    s.add_dependency('dnsruby', '>= 1.1.9')
    s.files = FileList['[A-Z]*.*', '{lib,spec}/**/*', 'VERSION']
  end
rescue LoadError
  puts 'Jeweler not available. Install it with: sudo gem install jeweler -s http://gemcutter.org'
end

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new do |spec|
  spec.pattern = 'spec/**/*_spec.rb'
  spec.rspec_opts = ['-f progress', '-r ./spec/spec_helper.rb', '--color', '--backtrace']
end

begin
  require 'yard'
  YARD::Rake::YardocTask.new do |t|
    t.files   = [
      'README',
      'lib/netaddr.rb',
      'lib/netaddr/**/*.rb',
    ]
    t.options = ['--protected', '--private']
  end
rescue LoadError
end

require 'rake/rdoctask'
desc 'Generate documentation'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'netaddr'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README', 'NOTICE')
  rdoc.rdoc_files.include('lib/netaddr.rb')
  rdoc.rdoc_files.include('lib/netaddr/**/*.rb')
end
