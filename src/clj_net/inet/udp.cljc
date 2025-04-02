(ns clj-net.inet.udp
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.packet :as pkt]))

;; RFC 768

(def ^:dynamic *udp-service-map*
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

(defmethod pkt/parse :udp [type _context buffer]
  (pkt/unpack-packet
   st-udp type buffer
   (fn [{:keys [sport dport len]}]
     (let [plen (- len 8)
           service (->> [dport sport] (some (:i->k *udp-service-map*)))]
       {:context-extra #:udp{:service service :sport sport :dport dport :plen plen}
        :next-info {:type (when (some? service) service) :length plen}}))))
