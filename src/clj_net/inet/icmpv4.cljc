(ns clj-net.inet.icmpv4
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]))

;; RFC 792

(def icmpv4-type-map
  (st/->kimap
   {:icmpv4-echo-reply           0
    :icmpv4-echo-request         8
    :icmpv4-dest-unreach         3
    :icmpv4-source-quench        4
    :icmpv4-redirect             5
    :icmpv4-time-exceeded       11
    :icmpv4-param-problem       12
    :icmpv4-timestamp-request   13
    :icmpv4-timestamp-reply     14
    :icmpv4-information-request 15
    :icmpv4-information-reply   16}))

(def icmpv4-redirect-code-map
  (st/->kimap
   {:network-redirect     0
    :host-redirect        1
    :tos-network-redirect 2
    :tos-host-redirect    3}))

(def icmpv4-dest-unreach-code-map
  (st/->kimap
   {:network-unreachable  0
    :host-unreachable     1
    :protocol-unreachable 2
    :port-unreachable     3
    :fragmentation-needed 4
    :source-route-failed  5}))

(def icmpv4-time-exceeded-code-map
  (st/->kimap
   {:ttl-zero-during-transit    0
    :ttl-zero-during-reassembly 1}))

(def icmpv4-param-problem-code-map
  (st/->kimap {:ip-header-bad 0}))

(def st-icmpv4
  (st/keys
   :type st/uint8
   :code st/uint8
   :chksum st/uint16-be))

(def st-icmpv4-echo
  (st/keys
   :id st/uint16-be
   :seq st/uint16-be))

(def st-icmpv4-redirect
  (st/keys
   :gw ia/st-ipv4))

(defmethod pkt/parse :icmpv4 [type {:icmpv4/keys [type-map] :as opts} context buffer]
  (pkt/parse-simple-packet
   st-icmpv4 type opts context buffer
   (fn [packet context]
     (let [{:keys [type code]} (:st packet)
           next-type (get-in type-map [:i->k type])
           context (merge context #:icmpv4{:proto next-type :code code})]
       [packet context {:next-type next-type}]))))

(defn parse-icmpv4-echo
  [type opts context buffer]
  (pkt/parse-simple-packet
   st-icmpv4-echo type opts context buffer
   (fn [packet context]
     (let [{:keys [id seq]} (:st packet)
           context (merge context #:icmpv4{:id id :seq seq})]
       [packet context]))))

(defmethod pkt/parse :icmpv4-echo-request [type opts context buffer]
  (parse-icmpv4-echo type opts context buffer))

(defmethod pkt/parse :icmpv4-echo-reply [type opts context buffer]
  (parse-icmpv4-echo type opts context buffer))

(defmethod pkt/parse :icmpv4-redirect [type opts context buffer]
  (pkt/parse-simple-packet
   st-icmpv4-redirect type opts context buffer))
