(ns clj-net.inet.arp
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]))

;; RFC 826

(def arp-hwtype-map
  (st/->kimap {:ether 1}))

(def st-arp-hwtype
  (st/enum st/uint16-be arp-hwtype-map))

(def arp-ptype-map
  (st/->kimap {:ipv4 0x0800}))

(def st-arp-ptype
  (st/enum st/uint16-be arp-ptype-map))

(def arp-op-map
  (st/->kimap {:request 1 :reply 2}))

(def st-arp-op
  (st/enum st/uint16-be arp-op-map))

(def st-arp
  (-> (st/keys
       :hwtype st-arp-hwtype
       :ptype st-arp-ptype
       :hwlen (-> st/int8 (st/wrap-validator #(= % 6)))
       :plen (-> st/int8 (st/wrap-validator #(= % 4)))
       :op st-arp-op
       :hwsrc ia/st-mac
       :psrc ia/st-ipv4
       :hwdst ia/st-mac
       :pdst ia/st-ipv4)
      (st/wrap-merge
       {:hwtype :ether :ptype :ipv4 :hwlen 6 :plen 4 :op :request
        :hwsrc ia/mac-zero :psrc ia/ipv4-zero :hwdst ia/mac-zero :pdst ia/ipv4-zero})))

(defmethod pkt/parse :arp [type _context buffer]
  (pkt/unpack-packet st-arp type buffer))
