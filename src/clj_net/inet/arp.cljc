(ns clj-net.inet.arp
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]))

;; RFC 826

(def arp-op-map
  (st/->kimap {:request 1 :reply 2}))

(def st-arp
  (-> (st/keys
       :hwtype st/uint16-be
       :ptype st/uint16-be
       :hwlen (-> st/uint8 (st/wrap-validator #(= % 6)))
       :plen (-> st/uint8 (st/wrap-validator #(= % 4)))
       :op st/uint16-be
       :hwsrc ia/st-mac
       :psrc ia/st-ipv4
       :hwdst ia/st-mac
       :pdst ia/st-ipv4)
      (st/wrap-merge
       {:hwtype 1 :ptype 0x0800 :hwlen 6 :plen 4 :op 1
        :hwsrc ia/mac-zero :psrc ia/ipv4-zero :hwdst ia/mac-zero :pdst ia/ipv4-zero})))

(defmethod pkt/parse :arp [type _context buffer]
  (pkt/unpack-packet st-arp type buffer))
