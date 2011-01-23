

module DnsTest

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

      # Implement cache overriding policies
      self[rr.name.to_s.downcase].each do |element|
        return if element == rr
      end

      self[rr.name.to_s.downcase] << rr
    end
  end

end
