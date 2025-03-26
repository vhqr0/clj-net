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

(defmethod pkt/parse :ether [_type {:ether/keys [type-map] :as opts} context buffer]
  (pkt/parse-simple-packet
   st-ether type opts context buffer
   (fn [packet context]
     (let [{:keys [dst src type]} (:st packet)
           type (get-in type-map [:i->k type])
           context (merge context #:ether{:type type :src src :dst dst})]
       [packet context {:next-type type}]))))
