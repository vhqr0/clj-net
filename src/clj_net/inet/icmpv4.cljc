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

(defmethod pkt/parse :icmpv4 [type _context buffer]
  (pkt/parse-packet
   st-icmpv4 type buffer
   (fn [{:keys [type code]}]
     {:context-extra #:icmpv4{:type type :code code}
      :next-info {:type [:icmpv4 type]}})))

(doseq [[k i] (:k->i icmpv4-type-map)]
  (defmethod pkt/parse [:icmpv4 i] [_type context buffer] (pkt/parse k context buffer)))

(defn parse-icmpv4-echo
  [type buffer]
  (pkt/parse-packet
   st-icmpv4-echo type buffer
   (fn [{:keys [id seq]}]
     {:context-extra #:icmpv4{:id id :seq seq}})))

(defmethod pkt/parse :icmpv4-echo-request [type _context buffer]
  (parse-icmpv4-echo type buffer))

(defmethod pkt/parse :icmpv4-echo-reply [type _context buffer]
  (parse-icmpv4-echo type buffer))

(defmethod pkt/parse :icmpv4-redirect [type _context buffer]
  (pkt/parse-packet st-icmpv4-redirect type buffer))
