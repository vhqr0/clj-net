(ns clj-net.inet.core
  (:require [clj-net.inet.packet :as pkt]
            clj-net.inet.ether
            clj-net.inet.arp
            clj-net.inet.ip
            clj-net.inet.ipv4
            clj-net.inet.ipv6
            clj-net.inet.icmpv4
            clj-net.inet.icmpv6
            clj-net.inet.tcp
            clj-net.inet.udp
            clj-net.inet.dns
            clj-net.inet.dhcpv4
            clj-net.inet.dhcpv6))

(defn parse-ether [buffer] (pkt/parse-all {:type :ether} {} buffer))
(defn parse-ip [buffer] (pkt/parse-all {:type :ip} {} buffer))
