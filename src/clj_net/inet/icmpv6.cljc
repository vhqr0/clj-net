(ns clj-net.inet.icmpv6
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
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

(def st-icmpv6
  (-> (st/keys
       :type st/uint8
       :code st/uint8
       :checksum st/uint16-be)
      (st/wrap-merge
       {:type 128 :code 0 :checksum 0})))

(def st-icmpv6-echo
  (-> (st/keys
       :id st/uint16-be
       :seq st/uint16-be)
      (st/wrap-merge
       {:id 0 :seq 0})))

(def st-icmpv6-packet-too-big
  (-> (st/keys
       :mtu st/uint32-be)
      (st/wrap-merge
       {:mtu 1280})))

(defmethod pkt/parse :icmpv6 [type _context buffer]
  (pkt/unpack-packet
   st-icmpv6 type buffer
   (fn [{:keys [type code]}]
     {:context-extra #:icmpv6{:type type :code code}
      :next-info {:type [:icmpv6 type]}})))

(doseq [[k i] (:k->i icmpv6-type-map)]
  (defmethod pkt/parse [:icmpv6 i] [_type context buffer] (pkt/parse k context buffer)))

(defn parse-icmpv6-echo
  [type buffer]
  (pkt/unpack-packet
   st-icmpv6-echo type buffer
   (fn [{:keys [id seq]}]
     {:context-extra #:icmpv6{:id id :seq seq}})))

(defmethod pkt/parse :icmpv6-echo-request [type _context buffer]
  (parse-icmpv6-echo type buffer))

(defmethod pkt/parse :icmpv6-echo-reply [type _context buffer]
  (parse-icmpv6-echo type buffer))

(defmethod pkt/parse :icmpv6-packet-too-big [type _context buffer]
  (pkt/unpack-packet st-icmpv6-packet-too-big type buffer))

;;; ndp

(def st-icmpv6-nd-rs
  (-> (st/keys
       :res st/uint32-be
       :options st/bytes)
      (st/wrap-merge
       {:res 0 :options (b/empty)})))

(def st-icmpv6-nd-ra
  (-> (st/keys
       :chlim st/uint8
       :m-o-res (st/bits [1 1 6])
       :routerlifetime st/uint16-be
       :reachabletime st/uint32-be
       :retranstimer st/uint32-be
       :options st/bytes)
      (st/wrap-vec-destructs
       {:m-o-res [:m :o :res]})
      (st/wrap-merge
       {:chlim 0 :m 0 :o 0 :res 0 :routerlifetime 1800
        :reachabletime 0 :retranstimer 0 :options (b/empty)})))

(def st-icmpv6-nd-ns
  (-> (st/keys
       :res st/uint32-be
       :tgt ia/st-ipv6
       :options st/bytes)
      (st/wrap-merge
       {:res 0 :tgt ia/ipv6-zero :options (b/empty)})))

(def st-icmpv6-nd-na
  (-> (st/keys
       :r-s-o-res (st/bits [1 1 1 13])
       :tgt ia/st-ipv6
       :options st/bytes)
      (st/wrap-vec-destructs
       {:r-s-o-res [:r :s :o :res]})
      (st/wrap-merge
       {:r 1 :s 0 :o 1 :res 0 :tgt ia/ipv6-zero :options (b/empty)})))

(def st-icmpv6-nd-redirect
  (-> (st/keys
       :res st/uint32-be
       :tgt ia/st-ipv6
       :dst ia/st-ipv6
       :options st/bytes)
      (st/wrap-merge
       {:res 0 :tgt ia/ipv6-zero :dst ia/ipv6-zero :options (b/empty)})))

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
             (st/wrap
              #(quot (+ % 2) 8)
              #(- (* 8 %) 2))
             (st/wrap-validator
              #(and (nat-int? %) (zero? (mod (+ % 2) 8))))
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

(def icmpv6-nd-option-st-map
  {:src-lladdr st-icmpv6-nd-option-lladdr
   :dst-lladdr st-icmpv6-nd-option-lladdr
   :prefix-info st-icmpv6-nd-option-prefix-info
   :redirect-hdr st-icmpv6-nd-option-redirect-hdr
   :mtu st-icmpv6-nd-option-mtu})

(defmulti parse-icmpv6-nd-option
  (fn [option] (:type option)))

(defmethod parse-icmpv6-nd-option :default [option] option)

(doseq [[k i] (:k->i icmpv6-nd-option-map)]
  (let [st (get icmpv6-nd-option-st-map k)]
    (defmethod parse-icmpv6-nd-option i [option] (pkt/unpack-option st k option))))

(defn parse-icmpv6-nd
  [st type buffer]
  (pkt/unpack-packet
   st type buffer
   (fn [{:keys [options]}]
     (let [options (->> (st/unpack-many options st-icmpv6-nd-option) (mapv parse-icmpv6-nd-option))]
       {:data-extra {:options options}}))))

(defmethod pkt/parse :icmpv6-nd-rs [type _context buffer] (parse-icmpv6-nd st-icmpv6-nd-rs type buffer))
(defmethod pkt/parse :icmpv6-nd-ra [type _context buffer] (parse-icmpv6-nd st-icmpv6-nd-ra type buffer))
(defmethod pkt/parse :icmpv6-nd-ns [type _context buffer] (parse-icmpv6-nd st-icmpv6-nd-ns type buffer))
(defmethod pkt/parse :icmpv6-nd-na [type _context buffer] (parse-icmpv6-nd st-icmpv6-nd-na type buffer))
(defmethod pkt/parse :icmpv6-nd-redirect [type _context buffer] (parse-icmpv6-nd st-icmpv6-nd-redirect type buffer))
