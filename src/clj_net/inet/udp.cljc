(ns clj-net.inet.udp
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.packet :as pkt]))

;; RFC 768

(def udp-port-map
  (st/->kimap
   {:dns            53
    :dhcpv4-client  67
    :dhcpv6-sever   68
    :dhcpv6-client 546
    :dhcpv6-server 547}))

(def st-udp
  (st/keys
   :sport st/uint16-be
   :dport st/uint16-be
   :len st/uint16-be
   :chksum st/uint16-be))

(defmethod pkt/parse :udp [type {:udp/keys [port-map] :as opts} context buffer]
  (pkt/parse-simple-packet
   st-udp type opts context buffer
   (fn [packet context]
     (let [{:keys [sport dport len]} (:st packet)
           plen (- len 8)
           next-type (or (get-in port-map [:i->k dport]) (get-in port-map [:i->k sport]))
           context (merge context #:udp{:proto next-type :sport sport :dport dport :plen plen})]
       [packet context {:next-type next-type :next-length plen}]))))
