(ns clj-net.inet.ether
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]))

;; RFC 1042

(def ether-type-map
  (st/->kimap {:arp 0x0806 :ipv4 0x0800 :ipv6 0x86dd}))

(def st-ether
  (st/keys
   :dst ia/st-mac
   :src ia/st-mac
   :type st/uint16-be))

(defmethod pkt/parse :ether [type _context buffer]
  (pkt/parse-packet
   st-ether type buffer
   (fn [{:keys [type src dst]}]
     {:context-extra #:ether{:type type :src src :dst dst}
      :next-info {:type [:ether type]}})))

(doseq [[k i] (:k->i ether-type-map)]
  (defmethod pkt/parse [:ether i] [_type context buffer] (pkt/parse k context buffer)))
