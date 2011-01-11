
require 'dnsruby'
require 'pp'

module DnsTest

  A = Dnsruby::Types::A
  AAAA = Dnsruby::Types::AAAA
  NS = Dnsruby::Types::NS
  IN = Dnsruby::Classes::IN

  class RRCache < Hash

    def <<(data)
      if data.kind_of?(Array)
        data.each do |rr|
          self << rr
        end
      else
        add_single(data)
      end
    end

    def find(label, type = Dnsruby::Types::A, klass = Dnsruby::Classes::IN)

      label = label.to_s

      return [] if !self[label]

      if type.respond_to?(:include?)
        self[label].select { |rr| type.include?(rr.type) && rr.klass == klass }
      else
        self[label].select { |rr| rr.type == type && rr.klass == klass }
      end
    end

    private

    def add_single(rr)
      # TODO Implement limiting of TTL to 1 week (per RFC)

      self[rr.name.to_s.downcase] ||= []

      self[rr.name.to_s.downcase].each do |element|
        if element.type == rr.type && element.klass == rr.klass # && check authority
          return
        end
      end

      self[rr.name.to_s.downcase] << rr
    end
  end

  class Tester

    class NullLog
      def debug(str) ; end
      def info(str) ; end
      def warn(str) ; end
    end

    attr_accessor :callback, :recurse, :ipv6_ok
    attr_reader :hints
    # The resolver to use for the queries
    attr_accessor :resolver

    def initialize(opts = {})
      @log = opts[:log] ? opts[:log] : NullLog.new
      @hints = nil
      @cache = RRCache.new
      @ipv6_ok = true
      @system_resolver = Dnsruby::Resolver.new
      @resolver = Dnsruby::Resolver.new
    end

    #Initialize the hint servers.  Recursive queries need a starting name
    #server to work off of. This method takes a list of IP addresses to use
    #as the starting servers.  These name servers should be authoritative for
    #the root (.) zone.
    #
    #  res.hints=(ips)
    #
    #If no hints are passed, the default nameserver is asked for the hints.
    #Normally these IPs can be obtained from the following location:
    #
    #  ftp://ftp.internic.net/domain/named.root
    #

    class RecursorError < StandardError ; end
    class HintNotAuthoritativeForRoot < RecursorError ; end
    class MissingHints < RecursorError ; end
    class NoResponseFromAnyAuthority < RecursorError ; end
    class RecursionTooDeep < RecursorError ; end
    class LameServer < RecursorError ; end

    def cache_hints_from_system_resolver
      # get at least a root server NS from system's recursor
      @system_resolver.recurse = true

      packet = @system_resolver.query('.', NS)

      nameservers = packet.answer.select { |rr| rr.type == NS }

      raise MissingHints if nameservers.empty?

      @cache << nameservers
      @cache << packet.additional.select { |rr| rr.type == Dnsruby::Types::A || rr.type == Dnsruby::Types::AAAA }

      nses = @cache.find('', Dnsruby::Types::NS)

      raise MissingHints if nses.size == 0

      if nses.map { |x| @cache.find(x.nsdname.to_s, [ A, AAAA ]) }.flatten.empty?
        # Gee, the nameserver didn't give anything in the additional section, well, ask him again for an A or AAAA, thanks
        res = @system_resolver.query(packet.answer[0].nsdname, Dnsruby::Types::A)
        @cache << res.answer

        res = @system_resolver.query(packet.answer[0].nsdname, Dnsruby::Types::AAAA)
        @cache << res.answer
      end

      if nses.map { |x| @cache.find(x.nsdname.to_s, [ A, AAAA ]) }.flatten.empty?
        raise MissingHints
      end
    end


    def set_hints(hints = nil)

  raise "TO BE IMPLEMENTED" if hints

      cache_hints_from_system_resolver

      # Now, we have at least one root server IP address. Ask one of them for an authoritative list of NS for the root
      @resolver.do_caching = false
      @resolver.recurse = false
      @resolver.nameserver = @cache.find('', [ A, AAAA ]).map { |x| x.address.to_s }

      # Do a query from one of the (hinted) root servers, the authoritative response will override the hints
      packet = query('.', NS, IN)

      if !packet.header.aa
        raise 'What? Root server not authoritative for root?!?'
      end

      # Fine, the cache is initialized with root servers
    end

    #This method takes a code reference, which is then invoked each time a
    #packet is received during the recursive lookup.  For example to emulate
    #dig's C<+trace> function:
    #
    # res.recursion_callback(Proc.new { |packet|
    #     print packet.additional.inspect
    #
    #     print";; Received %d bytes from %s\n\n",
    #         packetanswersize,
    #         packet.answerfrom);
    # })
    #
    def recursion_callback=(sub)
      #          if (sub && UNIVERSAL::isa(sub, 'CODE'))
      @callback = sub
      #          end
    end

    def recursion_callback
      return @callback
    end

    def clear_cache
      @cache.clear
    end

    def query(name, type = Dnsruby::Types::A, klass = Dnsruby::Classes::IN, no_validation = false)

      # Make sure the hint servers are initialized.
      set_hints if @cache.empty?

      ret =  normal_recursion( name, type, klass, 0, no_validation)
  #    Dnsruby::Dnssec.validate(ret) if !no_validation
      #      print "\n\nRESPONSE:\n#{ret}\n"

      return ret
    end

    def get_closest_zone(name)
      name_split = name.to_s.split('.')

      name_split.count.downto(0) do |i|
        zone = name_split.last(i).join('.')
        if @cache[zone]
          return zone, @cache[zone].select { |rr| rr.type == Dnsruby::Types::NS }
        end
      end
    end

    private

    def normal_recursion(name, type, klass, depth, no_validation) # :nodoc:

      # TODO Lookup question in cache and return immediately if we already know it

      indent = ' ' * depth

      @log.debug "#{indent} >>>>>>>"
      @log.debug "#{indent} Recursion initiated, depth #{depth}, question '#{name}'"
      @log.debug "#{indent} Searching for the most specific authority related to '#{name}'"

      known_zone, known_authorities = get_closest_zone(name)

      @log.debug "#{indent} Found authorities for '#{known_zone}':"

      known_authorities.each do |auth|
        @log.debug "#{indent}   #{auth.nsdname}"
      end

      if depth > 255
        @log.error "#{indent} Recursion too deep, aborting"
        raise RecursionTooDeep
      end

      packet = nil
      catch :got_answer do
        known_authorities.shuffle.each do |ns|
          @log.debug "#{indent} Selected #{ns.nsdname} name server to ask to"

          nsaddr = @cache.find(ns.nsdname, [ A, AAAA ])

          if nsaddr.empty?
  #check to see if there is a glue infinite loop
            @log.debug "#{indent} #{ns.nsdname} does not have A record in cache, recurse searching for it "
            packet = normal_recursion(ns.nsdname, A, IN, depth + 1, true)
            nsaddr = packet.answer #.select { |x| x.type == A || x.type == AAAA }
          end

          nsaddr.each do |addr|
            @log.debug "#{indent} Asking to #{ns.nsdname} for '#{name}' using address '#{addr.address}'"

            @resolver.nameserver = addr.address.to_s
            query = Dnsruby::Message.new(name, type, klass)
            query.header.rd = false
            query.do_validation = false
            query.do_caching = false

            begin
              packet = @resolver.send_message(query)
            rescue Dnsruby::ResolvError => e
  puts "Server error #{e} for #{ns.nsdname}"
              raise
            else
              throw :got_answer
            end
          end
        end

        raise NoResponseFromAnyAuthority
      end

      if !packet.header.qr
        raise "Response bit not set!"
      end

      if !packet.answer.empty?
        # We might have an answer but let's check if the label matches the question
        @log.debug "#{indent} We got an answer"

        packet.answer.each do |rr|
          # Bailiwick rule, do not cache if answer does not match question

          if rr.name == packet.question[0].qname
            # Cache the response
            @cache << rr
          end
        end

        packet.additional.each do |rr|

          knz = Dnsruby::Name.create(known_zone)
          knz.absolute = true

          if rr.name != known_zone &&
             !rr.name.subdomain_of?(knz)
            @log.debug "#{indent} Not caching '#{rr}' because it's not under #{known_zone}"
            next
          end

          if rr.type == Dnsruby::Types::A || rr.type == Dnsruby::Types::AAAA
            @cache << rr
          end
        end

        # Scan again to see if there are CNAMEs
        packet.answer.each do |rr|
          if rr.type == Dnsruby::Types::CNAME &&
             rr.name == packet.question[0].qname

            # If we have a CNAME we recurse again
            @log.debug "#{indent} Resolving CNAME '#{rr.name}' => '#{rr.cname}'"

            return normal_recursion(rr.cname, type, klass, depth + 1, no_validation)
          end
        end

        return packet

      elsif !packet.authority.empty?
        @log.debug "#{indent} We got a referral"

  #      if !packet.header.aa
  #        @log.debug "#{indent} We have a lame server!"
  #        raise LameServer
  #      end
  #
        packet.authority.each do |rr|
          next if rr.type != Dnsruby::Types::NS

          knz = Dnsruby::Name.create(known_zone)
          knz.absolute = true

          if rr.name != known_zone &&
             !rr.name.subdomain_of?(knz)
            raise "Bailiwick violation! Authority not subdomain of referral"
          end

          if !packet.question[0].qname.subdomain_of?(rr.name)
            raise "Bailiwick violation! Question is not subdomain of authority"
          end

          @cache << rr
        end

        packet.additional.each do |rr|
          knz = Dnsruby::Name.create(known_zone)
          knz.absolute = true

          if rr.name != known_zone &&
             !rr.name.subdomain_of?(knz)

            @log.debug "Not caching '#{rr}' because it's not under #{known_zone}" if rr.type != Dnsruby::Types::OPT

            next
          end

          if rr.type == Dnsruby::Types::A || rr.type == Dnsruby::Types::AAAA
            @cache << rr
          end
        end

        return normal_recursion(name, type, klass, depth + 1, no_validation)
      else
        raise "Whaaat?"
      end
    end
  end

end
