(ns clj-net.inet.udp
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.packet :as pkt]))

;; RFC 768

(def udp-service-map
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

(defmethod pkt/parse :udp [type {:udp/keys [service-map] :as opts} context buffer]
  (pkt/parse-simple-packet
   st-udp type opts context buffer
   (fn [packet context]
     (let [{:keys [sport dport len]} (:st packet)
           plen (- len 8)
           service (or (get-in service-map [:i->k dport]) (get-in service-map [:i->k sport]))
           context (merge context #:udp{:service service :sport sport :dport dport :plen plen})]
       [packet context {:next-type service :next-length plen}]))))
