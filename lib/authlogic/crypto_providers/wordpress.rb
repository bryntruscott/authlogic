require 'digest/md5'
module Authlogic
  module CryptoProviders
    class Wordpress
      class << self
        ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

        def matches?(crypted, *tokens)
          stretches = 1 << ITOA64.index(crypted[3,1])
          plain, salt = *tokens
          if salt.nil?
            salt = crypted[4, 8]
          end
          hashed = Digest::MD5.digest(salt+plain)
          stretches.times do |i|
            hashed = Digest::MD5.digest(hashed+plain)
          end
          crypted[0,12]+encode_64(hashed, 16) == crypted

        rescue Exception => e
          # probably not a WordPress hash
          false
        end

        def encode_64(input, length)
          output = "" 
          i = 0
          while i < length
            value = input[i] 
            i+=1
            break if value.nil?
            value_ord = value.ord
            output += ITOA64[value_ord & 0x3f, 1]
            value_ord |= input[i].ord << 8 if i < length
            output += ITOA64[(value_ord >> 6) & 0x3f, 1]

            i+=1
            break if i >= length
            value_ord |= input[i].ord << 16 if i < length
            output += ITOA64[(value_ord >> 12) & 0x3f,1]

            i+=1
            break if i >= length
            output += ITOA64[(value_ord >> 18) & 0x3f,1]
          end
          output
        end
      end
    end
  end
end
