(ns clj-net.inet.icmpv6
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]))

;; RFC 4443 ICMPv6
;; RFC 4861 NDP

(def icmpv6-type-map
  (st/->kimap
   {:icmpv6-dest-unreach     1
    :icmpv6-packet-too-big   2
    :icmpv6-time-exceeded    3
    :icmpv6-param-problem    4
    :icmpv6-echo-request   128
    :icmpv6-echo-reply     129
    :icmpv6-nd-rs          133
    :icmpv6-nd-ra          134
    :icmpv6-nd-ns          135
    :icmpv6-nd-na          136
    :icmpv6-nd-redirect    137}))

(def icmpv6-dest-unreach-code-map
  (st/->kimap
   {:no-route-to-destination        0
    :administratively-prohibited    1
    :beyond-scope-of-source-address 2
    :address-unreachable            3
    :port-unreachable               4
    :source-address-failed-policy   5
    :reject-route-to-destination    6}))

(def icmpv6-time-exceeded-code-map
  (st/->kimap
   {:hop-limit-exceeded-in-transit     0
    :fragment-reassembly-time-exceeded 1}))

(def icmpv6-param-problem-code-map
  (st/->kimap
   {:erroneous-header-field-encountered         0
    :unrecognized-next-header-type-encountered  1
    :unrecognized-ipv6-option-encountered       2
    :first-fragment-has-incomplete-header-chain 3}))

(def st-icmpv6
  (st/keys
   :type st/uint8
   :code st/uint8
   :chksum st/uint16-be))

(def st-icmpv6-echo
  (st/keys
   :id st/uint16-be
   :seq st/uint16-be))

(def st-icmpv6-packet-too-big
  (st/keys
   :mtu st/uint32-be))

(def st-icmpv6-nd-rs
  (st/keys
   :res st/uint32-be
   :options st/bytes))

(def st-icmpv6-nd-ra
  (-> (st/keys
       :chlim st/uint8
       :m-o-res (st/bits [1 1 6])
       :routerlifetime st/uint16-be
       :reachabletime st/uint32-be
       :retranstimer st/uint32-be
       :options st/bytes)
      (st/wrap-vec-destructs
       {:m-o-res [:m :o :res]})))

(def st-icmpv6-nd-ns
  (st/keys
   :res st/uint32-be
   :tgt ia/st-ipv6
   :options st/bytes))

(def st-icmpv6-nd-na
  (-> (st/keys
       :r-s-o-res (st/bits [1 1 1 13])
       :tgt ia/st-ipv6
       :options st/bytes)
      (st/wrap-vec-destructs
       {:r-s-o-res [:r :s :o :res]})))

(def st-icmpv6-nd-redirect
  (st/keys
   :res st/uint32-be
   :tgt ia/st-ipv6
   :dst ia/st-ipv6
   :options st/bytes))

(def icmpv6-nd-option-map
  (st/->kimap
   {:src-lladdr   1
    :dst-lladdr   2
    :prefix-info  3
    :redirect-hdr 4
    :mtu          5}))

(def st-icmpv6-nd-option
  (st/keys
   :type st/uint8
   :data (-> st/uint8
             (st/wrap #(+ % 2) #(- % 2))
             st/bytes-var)))

(def st-icmpv6-nd-option-lladdr
  ia/st-mac)

(def st-icmpv6-nd-option-prefix-info
  (-> (st/keys
       :prefixlen st/uint8
       :l-a-res1 (st/bits [1 1 6])
       :validlifetime st/uint32-be
       :preferredlifetime st/uint32-be
       :res2 st/uint32-be
       :prefix ia/st-ipv6)
      (st/wrap-vec-destructs
       {:l-a-res1 [:l :a :res1]})))

(def st-icmpv6-nd-option-redirect-hdr
  (st/keys
   :res1 st/uint16-be
   :res2 st/uint32-be
   :pkt st/bytes))

(def st-icmpv6-nd-option-mtu
  (st/keys
   :res st/uint16-be
   :mtu st/uint32-be))

(defmethod pkt/parse :icmpv6 [_type {:icmpv6/keys [type-map] :as opts} context buffer]
  (pkt/parse-simple-packet
   st-icmpv6 type opts context buffer
   (fn [packet context]
     (let [{:keys [type code]} (:st packet)
           next-type (get-in type-map [:i->k type])
           context (merge context #:icmpv6{:proto next-type :code code})]
       [packet context {:next-type next-type}]))))

(defn parse-icmpv6-echo
  [type opts context buffer]
  (pkt/parse-simple-packet
   st-icmpv6-echo type opts context buffer
   (fn [packet context]
     (let [{:keys [id seq]} (:st packet)
           context (merge context #:icmpv6{:id id :seq seq})]
       [packet context]))))

(defmethod pkt/parse :icmpv6-echo-request [type opts context buffer]
  (parse-icmpv6-echo type opts context buffer))

(defmethod pkt/parse :icmpv6-echo-reply [type opts context buffer]
  (parse-icmpv6-echo type opts context buffer))

(defmethod pkt/parse :icmpv6-packet-too-big [type opts context buffer]
  (pkt/parse-simple-packet
   st-icmpv6-packet-too-big type opts context buffer))

(defmethod pkt/parse :icmpv6-nd-rs [type opts context buffer]
  (pkt/parse-simple-packet
   st-icmpv6-nd-rs type opts context buffer))

(defmethod pkt/parse :icmpv6-nd-ra [type opts context buffer]
  (pkt/parse-simple-packet
   st-icmpv6-nd-ra type opts context buffer))

(defmethod pkt/parse :icmpv6-nd-ns [type opts context buffer]
  (pkt/parse-simple-packet
   st-icmpv6-nd-ns type opts context buffer))

(defmethod pkt/parse :icmpv6-nd-na [type opts context buffer]
  (pkt/parse-simple-packet
   st-icmpv6-nd-na type opts context buffer))

(defmethod pkt/parse :icmpv6-nd-redirect [type opts context buffer]
  (pkt/parse-simple-packet
   st-icmpv6-nd-redirect type opts context buffer))
